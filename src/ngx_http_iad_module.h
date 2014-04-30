#ifndef NGX_HTTP_iad_MODULE_H
#define NGX_HTTP_iad_MODULE_H

#include <ngx_core.h>
#include <ngx_http.h>

/* ����ָ��Ĳ����� */
typedef enum {
    iad_opcode_iad
} ngx_http_iad_opcode_t;

/*��������ָ��
 *��Ϊ����:����������,�͡���������� */
typedef enum {
    iad_handler_cmd, //��������
    iad_filter_cmd //��������
} ngx_http_iad_cmd_category_t;

/* �������ʽ����ָ�������ֵ */
typedef struct {
    /* ���е�ԭʼ�ַ�������ֵ */
    ngx_str_t       raw_value;
    ngx_array_t     *lengths;
    ngx_array_t     *values;
} ngx_http_iad_arg_template_t;

/* ����һ������ָ��(������) */
typedef struct {
    ngx_http_iad_opcode_t      opcode; 
    ngx_array_t                 *args;
} ngx_http_iad_cmd_t;

/* ������������ */
typedef struct {
    ngx_array_t     *handler_cmds;
    ngx_array_t     *before_body_cmds;
    ngx_array_t     *after_body_cmds;
} ngx_http_iad_loc_conf_t;

/* �����������������ڽṹ
 * ����ĵ�ǰ״̬������ */
typedef struct {
    /* ������:�������� */
    ngx_uint_t       next_handler_cmd;

    /* ������:���������� */
    ngx_uint_t       next_before_filter_cmd;

    /* ������after-body����������� */
    ngx_uint_t       next_after_filter_cmd;

    ngx_flag_t       headers_sent;
} ngx_http_iad_ctx_t;



#endif /* NGX_HTTP_iad_MODULE_H */

