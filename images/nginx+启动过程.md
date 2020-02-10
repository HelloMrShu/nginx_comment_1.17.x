# nginx 启动过程

## main() 函数

core/nginx.c

### 1 ngx_strerror_init 初始化系统错误类型及文本信息

### 2 ngx_get_options 解析命令行参数，保存到全局变量中

### 3 ngx_show_version_info 显示nginx版本信息

### 4 ngx_time_init 初始化各种世间

### 5 ngx_log_init 日志文件初始化，包括文件和路径

### 6 ngx_process_options 参数解析到ngx_argv变量中

### 7 ngx_os_init 系统初始化

### 8 ngx_slab_sizes_init 初始化一些slab变量

### 9 ngx_add_inherited_sockets 继承socket，继承来的socket放在init_cycle.listening数组（目的平滑升级）

### 10 ngx_preinit_modules 初始化ngx_modules数组信息, index, name

### 11 ngx_init_cycle 初始化全局变量cycle（配置文件指定及解析，监听，共享内存等）

### 12 ngx_init_signals 初始化注册信号，并修改动作

### 13 ngx_process

#### ngx_single_process_cycle
（单进程工作模式）

文件：os/unix/ngx_process_cycle.c

##### 1 ngx_set_environment 设置环境变量

##### 2 for: module.init_process

##### 3 事件循环执行 ngx_process_events_and_timers
 处理网络事件，定时器，做了四件工作：

① 抢占 accept mutex
② 等待并分发事件
③ 处理 accept事件
④ 处理其他io事件

#### ngx_master_process_cycle
（master-worker模式）

文件：os/unix/ngx_process_cycle.c

##### 1 ngx_start_worker_processes 启动woker进程

①在每个worker进程中调用所有模块的init_process方法
② worker_processes配置项，生成子进程

###### ngx_spawn_process
pid=fork()，并返回pid

然后执行回调
ngx_worker_process_cycle

####### 1 ngx_worker_process_init
worker进程初始化

已经确定了epoll及其回调

######## 1 执行各模块ngx_event_core_module的init_process钩子
即ngx_event_process_init()函数

######## 2 module->actions.init，即执行ngx_epoll_init

######### ngx_event_actions = ngx_epoll_module_ctx.actions
指定处理函数为ngx_epoll_process_events()

####### 2 work 主循环

######## ngx_process_events_and_timers
(网络事件，定时事件)

######### 1 ngx_process_events 等待分发事件
调用ngx_module_t的process_events方法
即 ngx_event_actions.process_events

######### 2 ngx_epoll_process_events

epoll_wait收集事件到event_list
依次调用回调函数handler
即accept(ngx_event_accept)

文件：event/modules/ngx_epoll_module.c 

########## ngx_event_accept

ls->handler(c)
handler即ngx_http_init_connection

########### 1 第一次处理handler
ngx_http_wait_request_handler

后续处理handler
ngx_http_process_request_line

########### 2 ngx_http_process_request_headers

########### 3 ngx_http_process_request

########### 4 ngx_http_handler

########### 5 ngx_http_core_run_phases

checker 控制请求阶段走向
handler 具体处理逻辑

参数：ngx_http_request_t

############ 11 个阶段

1 NGX_HTTP_POST_READ_PHASE
2 NGX_HTTP_SERVER_REWRITE_PHASE
3 NGX_HTTP_FIND_CONFIG_PHASE
4 NGX_HTTP_REWRITE_PHASE
5 NGX_HTTP_POST_REWRITE_PHASE
6 NGX_HTTP_PREACCESS_PHASE
7 NGX_HTTP_ACCESS_PHASE
8 NGX_HTTP_POST_ACCESS_PHASE
9 NGX_HTTP_PRECONTENT_PHASE
10 NGX_HTTP_CONTENT_PHASE
11 NGX_HTTP_LOG_PHASE

############# ngx_http_output_filter
返回应答给客户端

##### 2 ngx_start_cache_manager_processes 启动cache manager进程

##### 3 进入主循环

###### sigsuspend
延时，等待信号, master进程挂起

###### ngx_time_update 更新缓冲时间

###### ngx_terminate ngx_quit ngx_reconfigure ngx_restart ngx_reopen ngx_noaccept信号处理
