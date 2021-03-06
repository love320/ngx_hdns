#ifndef NGX_HTTP_iad_MODULE_H
#define NGX_HTTP_iad_MODULE_H

#include <ngx_core.h>
#include <ngx_http.h>

/* 配置指令的操作码 */
typedef enum {
    iad_opcode_iad
} ngx_http_iad_opcode_t;

/*各种配置指令
 *分为两类:“命令处理程序”,和“过滤器命令” */
typedef enum {
    iad_handler_cmd, //处理命令
    iad_filter_cmd //过滤命令
} ngx_http_iad_cmd_category_t;

/* 编译的形式配置指令参数的值 */
typedef struct {
    /* 持有的原始字符串参数值 */
    ngx_str_t       raw_value;
    ngx_array_t     *lengths;
    ngx_array_t     *values;
} ngx_http_iad_arg_template_t;

/* 代表一个配置指令(或命令) */
typedef struct {
    ngx_http_iad_opcode_t      opcode; 
    ngx_array_t                 *args;
} ngx_http_iad_cmd_t;

/* 本地配置类型 */
typedef struct {
    ngx_array_t     *handler_cmds;
    ngx_array_t     *before_body_cmds;
    ngx_array_t     *after_body_cmds;
} ngx_http_iad_loc_conf_t;

/* 上下文在请求处理周期结构
 * 命令的当前状态评估者 */
typedef struct {
    /* 接下来:处理命令 */
    ngx_uint_t       next_handler_cmd;

    /* 接下来:过滤器命令 */
    ngx_uint_t       next_before_filter_cmd;

    /* 接下来after-body过滤器命令的 */
    ngx_uint_t       next_after_filter_cmd;

    ngx_flag_t       headers_sent;
} ngx_http_iad_ctx_t;



#endif /* NGX_HTTP_iad_MODULE_H */

