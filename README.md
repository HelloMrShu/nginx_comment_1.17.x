# nginx_comment_1.17.x

基于1.17.x tag下的nginx源码注释

------------------------------

本项目是个人在需要理解epoll事件模型的前提下进行的，是个人理解的一个备注，希望感兴趣的同学一起学习，如有错误之处，烦请提pr帮助改正。

# 目前注释的主要内容
1. nginx启动过程
主要是main函数，路径/src/core/nginx.c

2. 两种工作模式
ngx_single_process_cycle 和 ngx_master_process_cycle

3 子进程工作流程
ngx_worker_process_cycle

4 核心事件处理函数
ngx_proccess_events_and_timers

5 事件处理
ngx_process_events 和 ngx_epoll_process_events，以及ngx_event_accept

6 http请求处理流程
从ngx_event_accept开始，处理请求头、请求行、处理请求的11个阶段，最后响应应答

# 流程图




