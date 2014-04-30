
#define NGX_CONF_BUFFER  4096

#include "ngx_shmap.h"
#include "ngx_http_iad_module.h"

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_log.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

static ngx_http_output_header_filter_pt ngx_http_next_header_filter = NULL;

static ngx_http_output_body_filter_pt ngx_http_next_body_filter = NULL;

static ngx_buf_t ngx_http_iad_space_buf;

static ngx_buf_t ngx_http_iad_newline_buf;

static ngx_shm_zone_t* zone ;
static int zone_in = 0;


/* ������ ��ʼ�� */
static ngx_int_t ngx_http_iad_filter_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_iad_header_filter(ngx_http_request_t *r);

static ngx_int_t ngx_http_iad_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

/* ��ʼ��ģ�鴦���� */
static ngx_int_t ngx_http_iad_init(ngx_conf_t *cf);

/* ��ʼ��ģ�鴦������������Ϣ */
static void* ngx_http_iad_create_conf(ngx_conf_t *cf);

/* ����ָ��������Ϣ */
static char* ngx_http_iad_iad(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char*
ngx_http_iad_helper(ngx_http_iad_opcode_t opcode,
        ngx_http_iad_cmd_category_t cat,
        ngx_conf_t *cf, ngx_command_t *cmd, void* conf);

/* �����ݴ����� */
static ngx_int_t ngx_http_iad_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_iad_exec_iad(ngx_http_request_t *r,
        ngx_http_iad_ctx_t *ctx, ngx_array_t *computed_args);

static ngx_int_t ngx_http_iad_eval_cmd_args(ngx_http_request_t *r,
        ngx_http_iad_cmd_t *cmd, ngx_array_t *computed_args);

static ngx_int_t ngx_http_iad_send_chain_link(ngx_http_request_t* r,
        ngx_http_iad_ctx_t *ctx, ngx_chain_t *cl);
		
static char* ngx_http_iad_init_main_conf(ngx_conf_t *cf,void* conf);

static char* ngx_http_iad_data_init_conf();

static ngx_command_t  ngx_http_iad_commands[] = {

    { ngx_string("iad"),
      NGX_HTTP_LOC_CONF|NGX_CONF_ANY,
      ngx_http_iad_iad,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_iad_loc_conf_t, handler_cmds),
      NULL },
      ngx_null_command
};

static ngx_http_module_t ngx_http_iad_module_ctx = {
    ngx_http_iad_init,              /* �ڴ����Ͷ�ȡ��ģ���������Ϣ֮ǰ������ */
    NULL,                          	/* �ڴ����Ͷ�ȡ��ģ���������Ϣ֮�󱻵��� */

    NULL,                         	/* ������������Ϣʱ������ */
    ngx_http_iad_init_main_conf,  	/* ��ʼ����������Ϣʱ������ */

    NULL,                          	/* ����������������Ϣʱ������*/
    NULL,                          	/* ���������úϲ���Ϣʱ������*/

    ngx_http_iad_create_conf, 		/* ��������������Ϣʱ������*/
    NULL                           	/* �������úϲ���Ϣʱ������*/
};

ngx_module_t ngx_http_iad_module = {
    NGX_MODULE_V1,
    &ngx_http_iad_module_ctx, 		/* ģ������*/
    ngx_http_iad_commands,   		/* ģ��ָ��*/
    NGX_HTTP_MODULE,                /* ģ������*/
    NULL,                           /* ��ʼ��������*/
    NULL,                           /* ��ʼ��ģ�鷽��*/
    NULL,                           /* ��ʼ����������*/
    NULL,                           /* ��ʼ���߳�*/
    NULL,                           /* �˳��߳�*/
    NULL,                           /* �˳�����*/
    NULL,                           /* �˳�������*/
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_iad_init(ngx_conf_t *cf) {
    static u_char space_str[]   = " ";
    static u_char newline_str[] = "\n";
		
    ngx_memzero(&ngx_http_iad_space_buf, sizeof(ngx_buf_t));
    ngx_http_iad_space_buf.memory = 1;
    ngx_http_iad_space_buf.start =
        ngx_http_iad_space_buf.pos =
            space_str;
    ngx_http_iad_space_buf.end =
        ngx_http_iad_space_buf.last =
            space_str + sizeof(space_str) - 1;

    ngx_memzero(&ngx_http_iad_newline_buf, sizeof(ngx_buf_t));
    ngx_http_iad_newline_buf.memory = 1;
    ngx_http_iad_newline_buf.start =
        ngx_http_iad_newline_buf.pos =
            newline_str;
    ngx_http_iad_newline_buf.end =
        ngx_http_iad_newline_buf.last =
            newline_str + sizeof(newline_str) - 1;

	return NGX_OK;
}

static ngx_int_t
ngx_http_iad_filter_init (ngx_conf_t *cf) {
    if (ngx_http_next_header_filter == NULL) {
        ngx_http_next_header_filter = ngx_http_top_header_filter;
        ngx_http_top_header_filter  = ngx_http_iad_header_filter;
    }
    if (ngx_http_next_body_filter == NULL) {
        ngx_http_next_body_filter = ngx_http_top_body_filter;
        ngx_http_top_body_filter  = ngx_http_iad_body_filter;
    }
    return NGX_OK;
}

static void*
ngx_http_iad_create_conf(ngx_conf_t *cf) {
    ngx_http_iad_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_iad_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
	
    return conf;
}

static char*
ngx_http_iad_helper(ngx_http_iad_opcode_t opcode,
        ngx_http_iad_cmd_category_t cat,
        ngx_conf_t *cf, ngx_command_t *cmd, void* conf) {
    ngx_http_core_loc_conf_t        *clcf;
    /* ngx_http_iad_loc_conf_t        *ulcf = conf; */
    ngx_array_t                     **args_ptr;
    ngx_http_script_compile_t       sc;
    ngx_str_t                       *raw_args;
    ngx_http_iad_arg_template_t    *arg;
    ngx_array_t                     **cmds_ptr;
    ngx_http_iad_cmd_t             *iad_cmd;
    ngx_uint_t                       i, n;

    /* ����ʵ��ƫ�������е��� */
    cmds_ptr = (ngx_array_t**)(((u_char*)conf) + cmd->offset);
    if (*cmds_ptr == NULL) {
        *cmds_ptr = ngx_array_create(cf->pool, 1,
                sizeof(ngx_http_iad_cmd_t));
        if (*cmds_ptr == NULL) {
            return NGX_CONF_ERROR;
        }
        if (cat == iad_handler_cmd) {
              /* ע�����ݵ��������� */
            clcf = ngx_http_conf_get_module_loc_conf(cf,
                    ngx_http_core_module);
            if (clcf == NULL) {
                return NGX_CONF_ERROR;
            }
 
            clcf->handler = ngx_http_iad_handler;
        } else {
            /* init ���� ȷ��ֻ��ʼ��һ��
             * ��ֹ��ʼ������ */
            ngx_http_iad_filter_init(cf);
        }
    }
    iad_cmd = ngx_array_push(*cmds_ptr);
    if (iad_cmd == NULL) {
        return NGX_CONF_ERROR;
    }
    iad_cmd->opcode = opcode;
    args_ptr = &iad_cmd->args;
    *args_ptr = ngx_array_create(cf->pool, 1,
            sizeof(ngx_http_iad_arg_template_t));
    if (*args_ptr == NULL) {
        return NGX_CONF_ERROR;
    }
    raw_args = cf->args->elts;
    /* ����������һ������,�ӵڶ�����ʼ */
    for (i = 1 ; i < cf->args->nelts; i++) {
        arg = ngx_array_push(*args_ptr);
        if (arg == NULL) {
            return NGX_CONF_ERROR;
        }
        arg->raw_value = raw_args[i];
 
        arg->lengths = NULL;
        arg->values  = NULL;
        n = ngx_http_script_variables_count(&arg->raw_value);
        if (n > 0) {
            ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
            sc.cf = cf;
            sc.source = &arg->raw_value;
            sc.lengths = &arg->lengths;
            sc.values = &arg->values;
            sc.variables = n;
            sc.complete_lengths = 1;
            sc.complete_values = 1;
            if (ngx_http_script_compile(&sc) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    } /* end for */
    return NGX_CONF_OK;
}

static char*
ngx_http_iad_iad(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    return ngx_http_iad_helper(iad_opcode_iad,
            iad_handler_cmd,
            cf, cmd, conf);
}



static ngx_int_t
ngx_http_iad_handler(ngx_http_request_t *r) {
    ngx_http_iad_loc_conf_t    *elcf;
    ngx_http_iad_ctx_t         *ctx;
    ngx_int_t                   rc;
    ngx_array_t                 *cmds;
    ngx_array_t                 *computed_args = NULL;
    ngx_http_iad_cmd_t         *cmd;
    ngx_http_iad_cmd_t         *cmd_elts;

	/* �ӱ��� loc request �� ��ȡ ngx_http_iad_module ������Ϣ */
    elcf = ngx_http_get_module_loc_conf(r, ngx_http_iad_module);
    cmds = elcf->handler_cmds;
    if (cmds == NULL) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_iad_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_iad_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_iad_module);
    }

    cmd_elts = cmds->elts;
    for (; ctx->next_handler_cmd < cmds->nelts; ctx->next_handler_cmd++) {
        cmd = &cmd_elts[ctx->next_handler_cmd];

        /* ������ǰcmd����(����еĻ�) */
        if (cmd->args) {
            computed_args = ngx_array_create(r->pool, cmd->args->nelts,
                    sizeof(ngx_str_t));
            if (computed_args == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            rc = ngx_http_iad_eval_cmd_args(r, cmd, computed_args);
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "Failed to evaluate arguments for "
                        "the \"iad\" directive.");
                return rc;
            }
        }

        /* ָ�ӵ��Ȼ��ڲ������� */
        switch (cmd->opcode) {
            case iad_opcode_iad:
		
                rc = ngx_http_iad_exec_iad(r, ctx, computed_args);				
                if (rc != NGX_OK) {
                    return rc;
                }
                break; 
            default:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "Unknown opcode: %d", cmd->opcode);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
                break;
        }
    }

    return ngx_http_iad_send_chain_link(r, ctx, NULL /* indicate LAST */);
}

static ngx_int_t
ngx_http_iad_exec_iad(ngx_http_request_t *r,
        ngx_http_iad_ctx_t *ctx, ngx_array_t *computed_args) {
    ngx_uint_t                  i;

    ngx_buf_t                   *space_buf;
    ngx_buf_t                   *newline_buf;
    ngx_buf_t                   *buf;

    ngx_buf_t                   *buf_state;
    ngx_buf_t                   *buf_time;
    ngx_buf_t                   *buf_end;

    ngx_str_t                   *computed_arg;
    ngx_str_t                   *computed_arg_elts;

    ngx_str_t                   *data_map_key;
    ngx_str_t                   *data_map_value;
    ngx_str_t                   data_map_value_null = ngx_null_string;
    
    ngx_str_t                   s_mid = ngx_null_string;
    ngx_str_t                   s_szn = ngx_null_string;
    ngx_str_t                   s_data = ngx_null_string;
    ngx_int_t                   i_action = 0; 

    ngx_str_t                   str_json_state = ngx_null_string;
    ngx_str_t                   str_json_time = ngx_null_string;

    ngx_chain_t *cl  = NULL; /* �������� */
    ngx_chain_t **ll = NULL;  /* ����ָ�����һ�����ӵĵ�ַ */

    uint8_t vt_str_cache = VT_STRING;
    
    
    ngx_http_iad_data_init_conf();
	
	if (computed_args == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* ��ȡ mid ������Ϣ */
    if(ngx_http_arg(r, (u_char*)"mid", 3, &s_mid)!=NGX_OK){
        //return NGX_HTTP_BAD_REQUEST;
    }

    /* ��ȡ action ������Ϣ */
    if(ngx_http_arg(r, (u_char*)"action", 6, &s_szn)==NGX_OK){
        i_action = ngx_atoi(s_szn.data, s_szn.len);
        //return NGX_HTTP_BAD_REQUEST;
    }

    /* ��ȡkey��Ϣ */
    data_map_key = &s_mid;
    data_map_value = &data_map_value_null;

    computed_arg_elts = computed_args->elts;
    for (i = 0; i < computed_args->nelts; i++) {
        computed_arg = &computed_arg_elts[i];
		
        buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));//����ngx_buf_t�����ڴ�ռ�
        if (buf == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    
        
        switch(i_action){
            case 0:{
                /*  ��zone �����в��Ҷ��� */
                ngx_shmap_get(zone,data_map_key, data_map_value,&vt_str_cache,0,0);
                                                  
                /*  �ӻ������ҵ�key ����value��Ϣ   */ 
                if(data_map_value->len > 0){
                    buf->start = buf->pos = data_map_value->data;
                    buf->last = buf->end = data_map_value->data + data_map_value->len;
                }else{
                    buf->start = buf->pos = computed_arg->data;
                    buf->last = buf->end = computed_arg->data + computed_arg->len;
                }
                break;
            }
                    
            case 1:{
                break;
            }

            case 101:{
                ngx_http_arg(r, (u_char*)"data", 4, &s_data);
                ngx_str_set(data_map_value,s_data.data);
                data_map_value->len = s_data.len;
                ngx_shmap_add(zone, data_map_key,data_map_value,VT_STRING,0,0);
                break;
            }

            case 102:{
                ngx_shmap_delete(zone,data_map_key);                
                break;
            }
                    
        }

        //ƴ��json���� 
        

        buf_state = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));//����ngx_buf_t�����ڴ�ռ�
        if (buf_state == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }        
        ngx_str_set(&str_json_state,"{state:0,data:");    
        buf_state->start = buf_state->pos = str_json_state.data;
        buf_state->last = buf_state->end = str_json_state.data + str_json_state.len;

        buf_time = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));//����ngx_buf_t�����ڴ�ռ�
        if (buf_time == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        } 
        str_json_time = ngx_cached_http_iad_yyyyMMdd;//��Ӧʱ��
        buf_time->start = buf_time->pos = str_json_time.data;
        buf_time->last = buf_time->end = str_json_time.data + str_json_time.len;
        
        buf_end = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));//����ngx_buf_t�����ڴ�ռ�
        if (buf_end == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        } 
        ngx_str_set(&str_json_state,"}");    
        buf_end->start = buf_end->pos = str_json_state.data;
        buf_end->last = buf_end->end = str_json_state.data + str_json_state.len;


        buf->memory = 1;
        buf_state->memory = 1;
        buf_time->memory = 1;
        buf_end->memory = 1;
			
        if (cl == NULL) {

            /* buf_state */
            cl = ngx_alloc_chain_link(r->pool);
            if (cl == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            cl->buf  = buf_state;
            cl->next = NULL;
            ll = &cl->next;


            /* Ȼ������ buf-data */
            *ll = ngx_alloc_chain_link(r->pool);
            if (*ll == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            (*ll)->buf  = buf;
            (*ll)->next = NULL;
            ll = &(*ll)->next;


            /* Ȼ������buf_time */
            *ll = ngx_alloc_chain_link(r->pool);
            if (*ll == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            (*ll)->buf  = buf_time;
            (*ll)->next = NULL;
            ll = &(*ll)->next;


        } else {
            /* ����һ���ռ� */
            *ll = ngx_alloc_chain_link(r->pool);
            if (*ll == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            space_buf = ngx_calloc_buf(r->pool);
            if (space_buf == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            /*  nginx���buf��ÿ��������,
				�������Ǳ������������һ����¡ */
            *space_buf = ngx_http_iad_space_buf;

            (*ll)->buf = space_buf;
            (*ll)->next = NULL;

            ll = &(*ll)->next;

            /* Ȼ������buf */
            *ll = ngx_alloc_chain_link(r->pool);
            if (*ll == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            (*ll)->buf  = buf;
            (*ll)->next = NULL;

            ll = &(*ll)->next;
        }
    } /* end for */

    newline_buf = ngx_calloc_buf(r->pool);
    if (newline_buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    *newline_buf = ngx_http_iad_newline_buf;

    if (cl == NULL) {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        cl->buf = newline_buf;
        cl->next = NULL;
        /* ll = &cl->next; */
    } else {
        *ll = ngx_alloc_chain_link(r->pool);
        if (*ll == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        (*ll)->buf  = newline_buf;
        (*ll)->next = NULL;
        /* ll = &(*ll)->next; */
    }

    return ngx_http_iad_send_chain_link(r, ctx, cl);
}

static ngx_int_t
ngx_http_iad_send_chain_link(ngx_http_request_t* r,
        ngx_http_iad_ctx_t *ctx, ngx_chain_t *cl) {
    ngx_int_t   rc;

    if ( ! ctx->headers_sent ) {
	
		/*	����ʹ��text/htmlģʽ������Ϣ */
        ctx->headers_sent = 1;
        r->headers_out.status = NGX_HTTP_OK;
		r->headers_out.content_type.len = sizeof("text/html") - 1;
		r->headers_out.content_type.data = (u_char *) "text/html";
		//r->headers_out.content_length_n = ngx_buf_size(cl->buf); //application/json
        if (ngx_http_set_content_type(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rc = ngx_http_send_header(r);	
		
        if (r->header_only || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
    }

    if (cl == NULL) {
        rc = ngx_http_send_special(r, NGX_HTTP_LAST);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
        return NGX_OK;
    }

    return ngx_http_output_filter(r, cl);
}

static ngx_int_t
ngx_http_iad_header_filter(ngx_http_request_t *r) {
       return NGX_OK;
}

static ngx_int_t
ngx_http_iad_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {
       return NGX_OK;
}

static ngx_int_t ngx_http_iad_eval_cmd_args(ngx_http_request_t *r,
        ngx_http_iad_cmd_t *cmd, ngx_array_t *computed_args) {
    ngx_uint_t                      i;
    ngx_array_t                     *args = cmd->args;
    ngx_str_t                       *computed_arg;
    ngx_http_iad_arg_template_t    *arg, *arg_elts;

    arg_elts = args->elts;
    for (i = 0; i < args->nelts; i++) {
        computed_arg = ngx_array_push(computed_args);
        if (computed_arg == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        arg = &arg_elts[i];
        if (arg->lengths == NULL) { /* ��������ֵ */
            *computed_arg = arg->raw_value;
        } else {
            if (ngx_http_script_run(r, computed_arg, arg->lengths->elts,
                        0, arg->values->elts) == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }
    return NGX_OK;
}

static char* ngx_http_iad_init_main_conf(ngx_conf_t *cf,void* conf)
{	
	size_t shm_size =1024*1024*10; //���û����С 1024*1024*10 = 10M
	ngx_str_t iad_shm_name = ngx_string("shm_iad_cache_zone"); //���û��������
	zone = ngx_shmap_init(cf,&iad_shm_name,shm_size,&ngx_http_iad_module);//��ʼ���������
	
	return NGX_CONF_OK;
}



static char* ngx_http_iad_data_init_conf(){

    if(zone_in == 1) return NGX_CONF_OK;

    uint64_t exptime = 0;
    ngx_str_t test_key = ngx_string("baidu");
    ngx_str_t test_value = ngx_string("http://www.baidu.com");
    ngx_shmap_add(zone, &test_key,&test_value,VT_STRING,exptime,0);
    
    ngx_str_t test_key1 = ngx_string("iad");
    ngx_str_t test_value1 = ngx_string("http://www.iad.com");
    ngx_shmap_add(zone, &test_key1,&test_value1,VT_STRING,exptime,0);
    
    ngx_str_t test_key2 = ngx_string("google");
    ngx_str_t test_value2 = ngx_string("http://www.google.com");
    ngx_shmap_add(zone, &test_key2,&test_value2,VT_STRING,exptime,0);
    
    zone_in = 1;

    return NGX_CONF_OK;
}

