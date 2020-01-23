
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_channel.h>


static void ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n,
    ngx_int_t type);
static void ngx_start_cache_manager_processes(ngx_cycle_t *cycle,
    ngx_uint_t respawn);
static void ngx_pass_open_channel(ngx_cycle_t *cycle, ngx_channel_t *ch);
static void ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo);
static ngx_uint_t ngx_reap_children(ngx_cycle_t *cycle);
static void ngx_master_process_exit(ngx_cycle_t *cycle);
static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data);
static void ngx_worker_process_init(ngx_cycle_t *cycle, ngx_int_t worker);
static void ngx_worker_process_exit(ngx_cycle_t *cycle);
static void ngx_channel_handler(ngx_event_t *ev);
static void ngx_cache_manager_process_cycle(ngx_cycle_t *cycle, void *data);
static void ngx_cache_manager_process_handler(ngx_event_t *ev);
static void ngx_cache_loader_process_handler(ngx_event_t *ev);

/*
在Linux中，需要使用命令行来控制Nginx服务器的启动与停止、重载配置文件、回滚日志文件、平滑升级等行为。默认情况下，Nginx被安装在目录
/usr/local/nginx/中，其二进制文件路径为/usr/local/nginc/sbin/nginx，配置文件路径为/usr/local/nginx/conf/nginx.conf。当然，
在configure执行时是可以指定把它们安装在不同目录的
*/
ngx_uint_t    ngx_process;
ngx_uint_t    ngx_worker;
ngx_pid_t     ngx_pid;
ngx_pid_t     ngx_parent;

sig_atomic_t  ngx_reap;
sig_atomic_t  ngx_sigio;
sig_atomic_t  ngx_sigalrm;
sig_atomic_t  ngx_terminate;
sig_atomic_t  ngx_quit;
sig_atomic_t  ngx_debug_quit;
ngx_uint_t    ngx_exiting;
sig_atomic_t  ngx_reconfigure;
sig_atomic_t  ngx_reopen;

sig_atomic_t  ngx_change_binary;
ngx_pid_t     ngx_new_binary;
ngx_uint_t    ngx_inherited;
ngx_uint_t    ngx_daemonized;

sig_atomic_t  ngx_noaccept;
ngx_uint_t    ngx_noaccepting;
ngx_uint_t    ngx_restart;


static u_char  master_process[] = "master process";


static ngx_cache_manager_ctx_t  ngx_cache_manager_ctx = {
    ngx_cache_manager_process_handler, "cache manager process", 0
};

static ngx_cache_manager_ctx_t  ngx_cache_loader_ctx = {
    ngx_cache_loader_process_handler, "cache loader process", 60000
};


static ngx_cycle_t      ngx_exit_cycle;
static ngx_log_t        ngx_exit_log;
static ngx_open_file_t  ngx_exit_log_file;

/*
多进程master-worker模式启动，调用该方法，主要有以下工作：
1.主进程设置信号阻塞
2.设置进程标题
3.启动worker进程
4.启动缓存索引重建进程和管理进程
5.主进程循环处理信号
*/
void
ngx_master_process_cycle(ngx_cycle_t *cycle)
{
    char              *title;
    u_char            *p;
    size_t             size;
    ngx_int_t          i;
    ngx_uint_t         n, sigio;
    sigset_t           set;
    struct itimerval   itv;
    ngx_uint_t         live;
    ngx_msec_t         delay;
    ngx_listening_t   *ls;
    ngx_core_conf_t   *ccf;

    // 设置屏蔽信号
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGINT);
    sigaddset(&set, ngx_signal_value(NGX_RECONFIGURE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_REOPEN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_NOACCEPT_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_TERMINATE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_CHANGEBIN_SIGNAL));

    // 信号屏蔽, 并不是禁止递送信号, 而是暂时阻塞信号的递送
    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sigprocmask() failed");
    }

    sigemptyset(&set);


    size = sizeof(master_process);

    for (i = 0; i < ngx_argc; i++) {
        size += ngx_strlen(ngx_argv[i]) + 1;
    }

    title = ngx_pnalloc(cycle->pool, size);
    if (title == NULL) {
        /* fatal */
        exit(2);
    }

    p = ngx_cpymem(title, master_process, sizeof(master_process) - 1);
    for (i = 0; i < ngx_argc; i++) {
        *p++ = ' ';
        p = ngx_cpystrn(p, (u_char *) ngx_argv[i], size);
    }

    // 进程名称设置为title
    ngx_setproctitle(title);

    //master进程获取core模块配置，ccf中有要创建多少个worker的设定
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    
    // 启动worker进程,在每个worker进程中调用所有模块的init_process方法
    ngx_start_worker_processes(cycle, ccf->worker_processes,
                               NGX_PROCESS_RESPAWN);
    // 启动 cache manager 进程
    ngx_start_cache_manager_processes(cycle, 0);

    ngx_new_binary = 0;
    delay = 0;
    sigio = 0;
    live = 1;
    
    // 循环
    for ( ;; ) {
         /*
            delay用来等待子进程退出的时间，由于接受到SIGINT信号后，需要先发送信号给子进程，而子进程的退出需要一定的时间，
            超时时如果子进程已退出，我们父进程就直接退出，否则发送sigkill信号给子进程(强制退出),然后再退出。
        */
        if (delay) {
            if (ngx_sigalrm) {
                sigio = 0;
                delay *= 2;
                ngx_sigalrm = 0;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "termination cycle: %M", delay);

            // 初始化定时器
            itv.it_interval.tv_sec = 0;
            itv.it_interval.tv_usec = 0;
            itv.it_value.tv_sec = delay / 1000;
            itv.it_value.tv_usec = (delay % 1000 ) * 1000;

            // 设置定时器
            if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                              "setitimer() failed");
            }
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "sigsuspend");

        // 延时，等待信号, master进程挂起
        sigsuspend(&set);

        // 更新缓冲时间
        ngx_time_update();

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "wake up, sigio %i", sigio);

        // ngx_reap为1，说明有子进程已经退出
        if (ngx_reap) {
            ngx_reap = 0;
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "reap children");
            // 处理退出的子进程
            live = ngx_reap_children(cycle);
        }

        // 如果无存活子进程，且收到ngx_terminate或者ngx_quit信号，则master退出
        if (!live && (ngx_terminate || ngx_quit)) {
            ngx_master_process_exit(cycle);
        }

        // 如果ngx_terminate标志位为l，则向所有子进程发送信号TERM．通知子进程强制退出进程，接下来直接跳到第1步并挂起进程，等待信号激活进程
        if (ngx_terminate) {
            if (delay == 0) {
                delay = 50;
            }

            if (sigio) {
                sigio--;
                continue;
            }

            sigio = ccf->worker_processes + 2 /* cache processes */;

            // 超时大于 1000 直接 kill，否则发送 TERM
            if (delay > 1000) {
                ngx_signal_worker_processes(cycle, SIGKILL);
            } else {
                ngx_signal_worker_processes(cycle,
                                       ngx_signal_value(NGX_TERMINATE_SIGNAL));
            }

            continue;
        }

        // ngx_quit为1的分支流程。关闭所有的监听端口，接下来直接跳到第1步并挂起master进程，等待信号激活进程
        if (ngx_quit) {
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));

            ls = cycle->listening.elts;
            for (n = 0; n < cycle->listening.nelts; n++) {
                if (ngx_close_socket(ls[n].fd) == -1) {
                    ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                                  ngx_close_socket_n " %V failed",
                                  &ls[n].addr_text);
                }
            }
            cycle->listening.nelts = 0;

            continue;
        }

        // 如果ngx_reconfigure标志位为0，则跳到第13步检查ngx_restart标志位。如果ngx_reconfigure为l，则表示需要重新读取配置文件
        if (ngx_reconfigure) {
            ngx_reconfigure = 0;

            if (ngx_new_binary) {
                ngx_start_worker_processes(cycle, ccf->worker_processes,
                                           NGX_PROCESS_RESPAWN);
                ngx_start_cache_manager_processes(cycle, 0);
                ngx_noaccepting = 0;

                continue;
            }

            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            // 重新初始化config，并重新启动新的worker
            cycle = ngx_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (ngx_cycle_t *) ngx_cycle;
                continue;
            }

            ngx_cycle = cycle;
            ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                   ngx_core_module);
            ngx_start_worker_processes(cycle, ccf->worker_processes,
                                       NGX_PROCESS_JUST_RESPAWN);
            ngx_start_cache_manager_processes(cycle, 1);

            /* allow new processes to start */
            ngx_msleep(100);

            live = 1;
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
        }

        if (ngx_restart) {
            ngx_restart = 0;
            ngx_start_worker_processes(cycle, ccf->worker_processes,
                                       NGX_PROCESS_RESPAWN);
            ngx_start_cache_manager_processes(cycle, 0);
            live = 1;
        }

        /* 
         * 如果ngx_reopen为1，则调用ngx_reopen_files穷法重新打开所有文件，同时将ngx_reopen标志位置为0
         * 这个功能使得日志文件不至于过大。当然，这与使用kill命令发送USR1信号效果相同（日志切割）
        */
        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, ccf->user);
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_REOPEN_SIGNAL));
        }

        // 如果ngx_change_binary为1，则表示需要平滑升级Nginx，这时将调用ngx_exec_new_binary方法用新的子进程启动新版本的Nginx程序， 同时将ngx_change_binary标志位置为0
        if (ngx_change_binary) {
            ngx_change_binary = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "changing binary");
            ngx_new_binary = ngx_exec_new_binary(cycle, ngx_argv);
        }

        // 接受到停止accept连接,worker退出，master保持不退出
        if (ngx_noaccept) {
            ngx_noaccept = 0;
            ngx_noaccepting = 1;
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
        }
    }
}

/*
 *如果hginx.conf中配置为单进程工作模式
 *将会调用ngx_single_process_cycle方法进入单迸程工作模式
 */
void
ngx_single_process_cycle(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    // 获取环境变量
    if (ngx_set_environment(cycle, NULL) == NULL) {
        /* fatal */
        exit(2);
    }

    // 遍历所有模块，执行init_process
    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_process) {
            if (cycle->modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    // 循环处理以下逻辑
    for ( ;; ) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        /*
         *事件循环的核心函数
         *1 抢占 accept mutex
         *2 等待并分发事件
         *3 处理 accept事件
         *4 处理其他io事件
         */
        ngx_process_events_and_timers(cycle);

        if (ngx_terminate || ngx_quit) {

            for (i = 0; cycle->modules[i]; i++) {
                if (cycle->modules[i]->exit_process) {
                    cycle->modules[i]->exit_process(cycle);
                }
            }

            ngx_master_process_exit(cycle);
        }
        
        // 重新配置
        if (ngx_reconfigure) {
            ngx_reconfigure = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            cycle = ngx_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (ngx_cycle_t *) ngx_cycle;
                continue;
            }

            ngx_cycle = cycle;
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, (ngx_uid_t) -1);
        }
    }
}

// 启动worker子进程
static void
ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n, ngx_int_t type)
{
    ngx_int_t      i;
    ngx_channel_t  ch;

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "start worker processes");

    ngx_memzero(&ch, sizeof(ngx_channel_t));
    // 传递给其他worker子进程的命令，打开通信管道
    ch.command = NGX_CMD_OPEN_CHANNEL;

    // 由master进程按照配置文件中worker进程的数目，启动这些子进程
    for (i = 0; i < n; i++) {

        // 调用该方法，fork子进程
        ngx_spawn_process(cycle, ngx_worker_process_cycle,
                          (void *) (intptr_t) i, "worker process", type);

        // 向已创建的worker进程，广播当前创建worker进程信息
        ch.pid = ngx_processes[ngx_process_slot].pid;
        ch.slot = ngx_process_slot;
        ch.fd = ngx_processes[ngx_process_slot].channel[0];

        // 把该子进程的相关channel信息传递给已经创建好的其他所有子进程
        ngx_pass_open_channel(cycle, &ch);
    }
}


static void
ngx_start_cache_manager_processes(ngx_cycle_t *cycle, ngx_uint_t respawn)
{
    ngx_uint_t       i, manager, loader;
    ngx_path_t     **path;
    ngx_channel_t    ch;

    manager = 0;
    loader = 0;

    path = ngx_cycle->paths.elts;
    for (i = 0; i < ngx_cycle->paths.nelts; i++) {

        if (path[i]->manager) {
            manager = 1;
        }

        if (path[i]->loader) {
            loader = 1;
        }
    }

    if (manager == 0) {
        return;
    }

    ngx_spawn_process(cycle, ngx_cache_manager_process_cycle,
                      &ngx_cache_manager_ctx, "cache manager process",
                      respawn ? NGX_PROCESS_JUST_RESPAWN : NGX_PROCESS_RESPAWN);

    ngx_memzero(&ch, sizeof(ngx_channel_t));

    ch.command = NGX_CMD_OPEN_CHANNEL;
    ch.pid = ngx_processes[ngx_process_slot].pid;
    ch.slot = ngx_process_slot;
    ch.fd = ngx_processes[ngx_process_slot].channel[0];

    ngx_pass_open_channel(cycle, &ch);

    if (loader == 0) {
        return;
    }

    ngx_spawn_process(cycle, ngx_cache_manager_process_cycle,
                      &ngx_cache_loader_ctx, "cache loader process",
                      respawn ? NGX_PROCESS_JUST_SPAWN : NGX_PROCESS_NORESPAWN);

    ch.command = NGX_CMD_OPEN_CHANNEL;
    ch.pid = ngx_processes[ngx_process_slot].pid;
    ch.slot = ngx_process_slot;
    ch.fd = ngx_processes[ngx_process_slot].channel[0];

    ngx_pass_open_channel(cycle, &ch);
}


static void
ngx_pass_open_channel(ngx_cycle_t *cycle, ngx_channel_t *ch)
{
    ngx_int_t  i;

    for (i = 0; i < ngx_last_process; i++) {

        if (i == ngx_process_slot
            || ngx_processes[i].pid == -1
            || ngx_processes[i].channel[0] == -1)
        {
            continue;
        }

        ngx_log_debug6(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                      "pass channel s:%i pid:%P fd:%d to s:%i pid:%P fd:%d",
                      ch->slot, ch->pid, ch->fd,
                      i, ngx_processes[i].pid,
                      ngx_processes[i].channel[0]);

        /* TODO: NGX_AGAIN */

        ngx_write_channel(ngx_processes[i].channel[0],
                          ch, sizeof(ngx_channel_t), cycle->log);
    }
}

static void
ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo)
{
    ngx_int_t      i;
    ngx_err_t      err;
    ngx_channel_t  ch;

    ngx_memzero(&ch, sizeof(ngx_channel_t));

#if (NGX_BROKEN_SCM_RIGHTS)

    ch.command = 0;

#else
    
    switch (signo) {

    case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
        ch.command = NGX_CMD_QUIT;
        break;

    case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        ch.command = NGX_CMD_TERMINATE;
        break;

    case ngx_signal_value(NGX_REOPEN_SIGNAL):
        ch.command = NGX_CMD_REOPEN;
        break;

    default:
        ch.command = 0;
    }

#endif

    ch.fd = -1;


    for (i = 0; i < ngx_last_process; i++) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %i %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       ngx_processes[i].pid,
                       ngx_processes[i].exiting,
                       ngx_processes[i].exited,
                       ngx_processes[i].detached,
                       ngx_processes[i].respawn,
                       ngx_processes[i].just_spawn);

        if (ngx_processes[i].detached || ngx_processes[i].pid == -1) {
            continue;
        }

        if (ngx_processes[i].just_spawn) {
            ngx_processes[i].just_spawn = 0;
            continue;
        }

        if (ngx_processes[i].exiting
            && signo == ngx_signal_value(NGX_SHUTDOWN_SIGNAL))
        {
            continue;
        }

        if (ch.command) {
            if (ngx_write_channel(ngx_processes[i].channel[0],
                                  &ch, sizeof(ngx_channel_t), cycle->log)
                == NGX_OK)
            {
                if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
                    ngx_processes[i].exiting = 1;
                }

                continue;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "kill (%P, %d)", ngx_processes[i].pid, signo);

        if (kill(ngx_processes[i].pid, signo) == -1) {
            err = ngx_errno;
            ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                          "kill(%P, %d) failed", ngx_processes[i].pid, signo);

            if (err == NGX_ESRCH) {
                ngx_processes[i].exited = 1;
                ngx_processes[i].exiting = 0;
                ngx_reap = 1;
            }

            continue;
        }

        if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
            ngx_processes[i].exiting = 1;
        }
    }
}


static ngx_uint_t
ngx_reap_children(ngx_cycle_t *cycle)
{
    ngx_int_t         i, n;
    ngx_uint_t        live;
    ngx_channel_t     ch;
    ngx_core_conf_t  *ccf;

    ngx_memzero(&ch, sizeof(ngx_channel_t));

    ch.command = NGX_CMD_CLOSE_CHANNEL;
    ch.fd = -1;

    live = 0;
    for (i = 0; i < ngx_last_process; i++) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %i %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       ngx_processes[i].pid,
                       ngx_processes[i].exiting,
                       ngx_processes[i].exited,
                       ngx_processes[i].detached,
                       ngx_processes[i].respawn,
                       ngx_processes[i].just_spawn);

        if (ngx_processes[i].pid == -1) {
            continue;
        }

        if (ngx_processes[i].exited) {

            if (!ngx_processes[i].detached) {
                ngx_close_channel(ngx_processes[i].channel, cycle->log);

                ngx_processes[i].channel[0] = -1;
                ngx_processes[i].channel[1] = -1;

                ch.pid = ngx_processes[i].pid;
                ch.slot = i;

                for (n = 0; n < ngx_last_process; n++) {
                    if (ngx_processes[n].exited
                        || ngx_processes[n].pid == -1
                        || ngx_processes[n].channel[0] == -1)
                    {
                        continue;
                    }

                    ngx_log_debug3(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                                   "pass close channel s:%i pid:%P to:%P",
                                   ch.slot, ch.pid, ngx_processes[n].pid);

                    /* TODO: NGX_AGAIN */

                    ngx_write_channel(ngx_processes[n].channel[0],
                                      &ch, sizeof(ngx_channel_t), cycle->log);
                }
            }

            if (ngx_processes[i].respawn
                && !ngx_processes[i].exiting
                && !ngx_terminate
                && !ngx_quit)
            {
                if (ngx_spawn_process(cycle, ngx_processes[i].proc,
                                      ngx_processes[i].data,
                                      ngx_processes[i].name, i)
                    == NGX_INVALID_PID)
                {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                                  "could not respawn %s",
                                  ngx_processes[i].name);
                    continue;
                }


                ch.command = NGX_CMD_OPEN_CHANNEL;
                ch.pid = ngx_processes[ngx_process_slot].pid;
                ch.slot = ngx_process_slot;
                ch.fd = ngx_processes[ngx_process_slot].channel[0];

                ngx_pass_open_channel(cycle, &ch);

                live = 1;

                continue;
            }

            if (ngx_processes[i].pid == ngx_new_binary) {

                ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                       ngx_core_module);

                if (ngx_rename_file((char *) ccf->oldpid.data,
                                    (char *) ccf->pid.data)
                    == NGX_FILE_ERROR)
                {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                                  ngx_rename_file_n " %s back to %s failed "
                                  "after the new binary process \"%s\" exited",
                                  ccf->oldpid.data, ccf->pid.data, ngx_argv[0]);
                }

                ngx_new_binary = 0;
                if (ngx_noaccepting) {
                    ngx_restart = 1;
                    ngx_noaccepting = 0;
                }
            }

            if (i == ngx_last_process - 1) {
                ngx_last_process--;

            } else {
                ngx_processes[i].pid = -1;
            }

        } else if (ngx_processes[i].exiting || !ngx_processes[i].detached) {
            live = 1;
        }
    }

    return live;
}


static void
ngx_master_process_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    ngx_delete_pidfile(cycle);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exit");

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_master) {
            cycle->modules[i]->exit_master(cycle);
        }
    }

    ngx_close_listening_sockets(cycle);

    /*
     * Copy ngx_cycle->log related data to the special static exit cycle,
     * log, and log file structures enough to allow a signal handler to log.
     * The handler may be called when standard ngx_cycle->log allocated from
     * ngx_cycle->pool is already destroyed.
     */


    ngx_exit_log = *ngx_log_get_file_log(ngx_cycle->log);

    ngx_exit_log_file.fd = ngx_exit_log.file->fd;
    ngx_exit_log.file = &ngx_exit_log_file;
    ngx_exit_log.next = NULL;
    ngx_exit_log.writer = NULL;

    ngx_exit_cycle.log = &ngx_exit_log;
    ngx_exit_cycle.files = ngx_cycle->files;
    ngx_exit_cycle.files_n = ngx_cycle->files_n;
    ngx_cycle = &ngx_exit_cycle;

    ngx_destroy_pool(cycle->pool);

    exit(0);
}

/*
 * 在Nginx主循环（主循环是ngx_worker_process_cycle方法）中，会定期地调用事件模块，以检查是否有网络事件发生。
*/
static void
ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data)
{
    ngx_int_t worker = (intptr_t) data;

    ngx_process = NGX_PROCESS_WORKER;
    ngx_worker = worker;

    // worker 进程初始化
    ngx_worker_process_init(cycle, worker);

    ngx_setproctitle("worker process");

    // work 主循环
    for ( ;; ) {

        if (ngx_exiting) {
            if (ngx_event_no_timers_left() == NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
                ngx_worker_process_exit(cycle);
            }
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        // 网络事件，定时器事件
        ngx_process_events_and_timers(cycle);

        if (ngx_terminate) {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
            ngx_worker_process_exit(cycle);
        }

        if (ngx_quit) {
            ngx_quit = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "gracefully shutting down");
            ngx_setproctitle("worker process is shutting down");

            if (!ngx_exiting) {
                ngx_exiting = 1;
                ngx_set_shutdown_timer(cycle);
                ngx_close_listening_sockets(cycle);
                ngx_close_idle_connections(cycle);
            }
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, -1);
        }
    }
}

/*
                                 |----------(ngx_worker_process_cycle->ngx_worker_process_init)
  ngx_start_worker_processes---| ngx_processes[]相关的操作赋值流程
                                 |----------ngx_pass_open_channel
*/
static void
ngx_worker_process_init(ngx_cycle_t *cycle, ngx_int_t worker)
{
    sigset_t          set;
    ngx_int_t         n;
    ngx_time_t       *tp;
    ngx_uint_t        i;
    ngx_cpuset_t     *cpu_affinity;
    struct rlimit     rlmt;
    ngx_core_conf_t  *ccf;
    ngx_listening_t  *ls;

    // 设置环境变量
    if (ngx_set_environment(cycle, NULL) == NULL) {
        /* fatal */
        exit(2);
    }

    // 加载配置
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (worker >= 0 && ccf->priority != 0) {
        if (setpriority(PRIO_PROCESS, 0, ccf->priority) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "setpriority(%d) failed", ccf->priority);
        }
    }

     // RLIMIT_NOFILE指定此进程可打开的最大文件描述词大一的值，超出此值，将会产生EMFILE错误
    if (ccf->rlimit_nofile != NGX_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t) ccf->rlimit_nofile;
        rlmt.rlim_max = (rlim_t) ccf->rlimit_nofile;

        if (setrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "setrlimit(RLIMIT_NOFILE, %i) failed",
                          ccf->rlimit_nofile);
        }
    }

    if (ccf->rlimit_core != NGX_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t) ccf->rlimit_core;
        rlmt.rlim_max = (rlim_t) ccf->rlimit_core;

        if (setrlimit(RLIMIT_CORE, &rlmt) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "setrlimit(RLIMIT_CORE, %O) failed",
                          ccf->rlimit_core);
        }
    }

    if (geteuid() == 0) {
        if (setgid(ccf->group) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "setgid(%d) failed", ccf->group);
            /* fatal */
            exit(2);
        }

        if (initgroups(ccf->username, ccf->group) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "initgroups(%s, %d) failed",
                          ccf->username, ccf->group);
        }

#if (NGX_HAVE_PR_SET_KEEPCAPS && NGX_HAVE_CAPABILITIES)
        if (ccf->transparent && ccf->user) {
            if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "prctl(PR_SET_KEEPCAPS, 1) failed");
                /* fatal */
                exit(2);
            }
        }
#endif

        if (setuid(ccf->user) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "setuid(%d) failed", ccf->user);
            /* fatal */
            exit(2);
        }

#if (NGX_HAVE_CAPABILITIES)
        if (ccf->transparent && ccf->user) {
            struct __user_cap_data_struct    data;
            struct __user_cap_header_struct  header;

            ngx_memzero(&header, sizeof(struct __user_cap_header_struct));
            ngx_memzero(&data, sizeof(struct __user_cap_data_struct));

            header.version = _LINUX_CAPABILITY_VERSION_1;
            data.effective = CAP_TO_MASK(CAP_NET_RAW);
            data.permitted = data.effective;

            if (syscall(SYS_capset, &header, &data) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "capset() failed");
                /* fatal */
                exit(2);
            }
        }
#endif
    }

    // 为每个进程设置 cpu 亲和性
    if (worker >= 0) {
        cpu_affinity = ngx_get_cpu_affinity(worker);

        if (cpu_affinity) {
            ngx_setaffinity(cpu_affinity, cycle->log);
        }
    }

#if (NGX_HAVE_PR_SET_DUMPABLE)

    /* allow coredump after setuid() in Linux 2.4.x */

    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "prctl(PR_SET_DUMPABLE) failed");
    }

#endif

    if (ccf->working_directory.len) {
        if (chdir((char *) ccf->working_directory.data) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "chdir(\"%s\") failed", ccf->working_directory.data);
            /* fatal */
            exit(2);
        }
    }

    /* 设置信号屏蔽 */
    sigemptyset(&set);

    if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sigprocmask() failed");
    }

    tp = ngx_timeofday();
    srandom(((unsigned) ngx_pid << 16) ^ tp->sec ^ tp->msec);

    /*
     * disable deleting previous events for the listening sockets because
     * in the worker processes there are no events at all at this point
     */
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        ls[i].previous = NULL;
    }

    //调用ngx_module_t结构的回调init_process
    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_process) {
            //ngx_event_process_init 
            if (cycle->modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    /* 依次关闭不用的管道 */
    for (n = 0; n < ngx_last_process; n++) {

        if (ngx_processes[n].pid == -1) {
            continue;
        }

        if (n == ngx_process_slot) {
            continue;
        }

        if (ngx_processes[n].channel[1] == -1) {
            continue;
        }

        if (close(ngx_processes[n].channel[1]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "close() channel failed");
        }
    }

    if (close(ngx_processes[ngx_process_slot].channel[0]) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "close() channel failed");
    }

#if 0
    ngx_last_process = 0;
#endif

    //调用epoll add 把ngx_channel管道事件加入epoll 中
    if (ngx_add_channel_event(cycle, ngx_channel, NGX_READ_EVENT,
                              ngx_channel_handler)
        == NGX_ERROR)
    {
        /* fatal */
        exit(2);
    }
}


static void
ngx_worker_process_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t         i;
    ngx_connection_t  *c;

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_process) {
            cycle->modules[i]->exit_process(cycle);
        }
    }

    if (ngx_exiting) {
        c = cycle->connections;
        for (i = 0; i < cycle->connection_n; i++) {
            if (c[i].fd != -1
                && c[i].read
                && !c[i].read->accept
                && !c[i].read->channel
                && !c[i].read->resolver)
            {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                              "*%uA open socket #%d left in connection %ui",
                              c[i].number, c[i].fd, i);
                ngx_debug_quit = 1;
            }
        }

        if (ngx_debug_quit) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "aborting");
            ngx_debug_point();
        }
    }

    /*
     * Copy ngx_cycle->log related data to the special static exit cycle,
     * log, and log file structures enough to allow a signal handler to log.
     * The handler may be called when standard ngx_cycle->log allocated from
     * ngx_cycle->pool is already destroyed.
     */

    ngx_exit_log = *ngx_log_get_file_log(ngx_cycle->log);

    ngx_exit_log_file.fd = ngx_exit_log.file->fd;
    ngx_exit_log.file = &ngx_exit_log_file;
    ngx_exit_log.next = NULL;
    ngx_exit_log.writer = NULL;

    ngx_exit_cycle.log = &ngx_exit_log;
    ngx_exit_cycle.files = ngx_cycle->files;
    ngx_exit_cycle.files_n = ngx_cycle->files_n;
    ngx_cycle = &ngx_exit_cycle;

    ngx_destroy_pool(cycle->pool);

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "exit");

    exit(0);
}


static void
ngx_channel_handler(ngx_event_t *ev)
{
    ngx_int_t          n;
    ngx_channel_t      ch;
    ngx_connection_t  *c;

    if (ev->timedout) {
        ev->timedout = 0;
        return;
    }

    c = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel handler");

    for ( ;; ) {

        n = ngx_read_channel(c->fd, &ch, sizeof(ngx_channel_t), ev->log);

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel: %i", n);

        if (n == NGX_ERROR) {

            if (ngx_event_flags & NGX_USE_EPOLL_EVENT) {
                ngx_del_conn(c, 0);
            }

            ngx_close_connection(c);
            return;
        }

        if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) {
            if (ngx_add_event(ev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return;
            }
        }

        if (n == NGX_AGAIN) {
            return;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,
                       "channel command: %ui", ch.command);

        switch (ch.command) {

        case NGX_CMD_QUIT:
            ngx_quit = 1;
            break;

        case NGX_CMD_TERMINATE:
            ngx_terminate = 1;
            break;

        case NGX_CMD_REOPEN:
            ngx_reopen = 1;
            break;

        case NGX_CMD_OPEN_CHANNEL:

            ngx_log_debug3(NGX_LOG_DEBUG_CORE, ev->log, 0,
                           "get channel s:%i pid:%P fd:%d",
                           ch.slot, ch.pid, ch.fd);

            ngx_processes[ch.slot].pid = ch.pid;
            ngx_processes[ch.slot].channel[0] = ch.fd;
            break;

        case NGX_CMD_CLOSE_CHANNEL:

            ngx_log_debug4(NGX_LOG_DEBUG_CORE, ev->log, 0,
                           "close channel s:%i pid:%P our:%P fd:%d",
                           ch.slot, ch.pid, ngx_processes[ch.slot].pid,
                           ngx_processes[ch.slot].channel[0]);

            if (close(ngx_processes[ch.slot].channel[0]) == -1) {
                ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                              "close() channel failed");
            }

            ngx_processes[ch.slot].channel[0] = -1;
            break;
        }
    }
}


static void
ngx_cache_manager_process_cycle(ngx_cycle_t *cycle, void *data)
{
    ngx_cache_manager_ctx_t *ctx = data;

    void         *ident[4];
    ngx_event_t   ev;

    /*
     * Set correct process type since closing listening Unix domain socket
     * in a master process also removes the Unix domain socket file.
     */
    ngx_process = NGX_PROCESS_HELPER;

    ngx_close_listening_sockets(cycle);

    /* Set a moderate number of connections for a helper process. */
    cycle->connection_n = 512;

    ngx_worker_process_init(cycle, -1);

    ngx_memzero(&ev, sizeof(ngx_event_t));
    ev.handler = ctx->handler;
    ev.data = ident;
    ev.log = cycle->log;
    ident[3] = (void *) -1;

    ngx_use_accept_mutex = 0;

    ngx_setproctitle(ctx->name);

    ngx_add_timer(&ev, ctx->delay);

    for ( ;; ) {

        if (ngx_terminate || ngx_quit) {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
            exit(0);
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, -1);
        }

        ngx_process_events_and_timers(cycle);
    }
}


static void
ngx_cache_manager_process_handler(ngx_event_t *ev)
{
    ngx_uint_t    i;
    ngx_msec_t    next, n;
    ngx_path_t  **path;

    next = 60 * 60 * 1000;

    path = ngx_cycle->paths.elts;
    for (i = 0; i < ngx_cycle->paths.nelts; i++) {

        if (path[i]->manager) {
            n = path[i]->manager(path[i]->data);

            next = (n <= next) ? n : next;

            ngx_time_update();
        }
    }

    if (next == 0) {
        next = 1;
    }

    ngx_add_timer(ev, next);
}


static void
ngx_cache_loader_process_handler(ngx_event_t *ev)
{
    ngx_uint_t     i;
    ngx_path_t   **path;
    ngx_cycle_t   *cycle;

    cycle = (ngx_cycle_t *) ngx_cycle;

    path = cycle->paths.elts;
    for (i = 0; i < cycle->paths.nelts; i++) {

        if (ngx_terminate || ngx_quit) {
            break;
        }

        if (path[i]->loader) {
            path[i]->loader(path[i]->data);
            ngx_time_update();
        }
    }

    exit(0);
}
