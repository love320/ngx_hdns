
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

static ngx_shm_zone_t* zone ;//���漯

static ngx_str_t data_map_key_defalue = ngx_null_string;//Ĭ��key 999999

static ngx_str_t ngx_http_iad_domain = ngx_null_string;//������-�� ��Ϣ


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

static ngx_str_t* ngx_http_iad_timestamp(ngx_http_request_t *r); //����ʱ���ʽ��ר�� gateway

static ngx_int_t ngx_http_iad_arg(ngx_http_request_t *r, u_char *name, size_t len,ngx_str_t *value);//ͨ�û�ȡ������Ϣ ֧��get post

static ngx_str_t* ngx_http_iad_cache_key(ngx_http_request_t *r,ngx_str_t *gateway,ngx_str_t *type);//�ϳɻ���keyֵ��Ϣ

static ngx_str_t* ngx_http_iad_str_palloc(ngx_http_request_t *r);//ר�� ngx_str_t �����ڴ�������ʼ��

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
    NULL,                           /* ��ʼ��������*/
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
              /* ע�����ݵ�������� */
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

    ngx_str_t                   *computed_arg;
    ngx_str_t                   *computed_arg_elts;

    ngx_str_t                   *data_map_key;
    ngx_str_t                   *data_map_value;
    //ngx_str_t                   data_map_value_null = ngx_null_string;//����Ϣ������r->pool�У�����ǻ���ֵ���ͷ�
    
    ngx_str_t                   *s_domain;
    ngx_str_t                   *s_gateway;
    ngx_str_t                   *s_app_type;
    ngx_str_t                   *s_szn;
    ngx_str_t                   *s_data;
    ngx_str_t                   *s_iad;
    ngx_int_t                   i_action = 0; 

    size_t                      str_json_len;
    u_char                      *str_json_data_p;
    ngx_str_t                   *ngx_str_send_json;

    ngx_int_t                   i_state = 0;
    


    ngx_chain_t *cl  = NULL; /* �������� */
    ngx_chain_t **ll = NULL;  /* ����ָ�����һ�����ӵĵ�ַ */

    s_domain = ngx_http_iad_str_palloc(r);
    s_gateway = ngx_http_iad_str_palloc(r);
    s_app_type = ngx_http_iad_str_palloc(r);
    s_szn = ngx_http_iad_str_palloc(r);
    s_data = ngx_http_iad_str_palloc(r);
    s_iad = ngx_http_iad_str_palloc(r);

    uint8_t vt_str_cache = VT_STRING;    
    
	if (computed_args == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
    if(!(r->method & (NGX_HTTP_GET|NGX_HTTP_POST))){
        return NGX_HTTP_NOT_FOUND;
    } */ 

    /* ��ȡ mid ������Ϣ */
    if(ngx_http_iad_arg(r, (u_char*)"gateway", 7, s_gateway)!=NGX_OK){};

    /* appType */
    if(ngx_http_iad_arg(r, (u_char*)"appType", 7, s_app_type)!=NGX_OK){i_state = -201;}//Ӧ��APP��Ϣ û��

    /* ��ȡ action ������Ϣ */
    if(ngx_http_iad_arg(r, (u_char*)"action", 6, s_szn)==NGX_OK){
        i_action = ngx_atoi(s_szn->data, s_szn->len);    
    }

    //���û���ע�ᣬ��action = 1;
    if(i_action == 0 && s_gateway->len == 0) i_action = 1;

    /* ��ȡkey��Ϣ */
    data_map_key = ngx_http_iad_cache_key(r,s_gateway,s_app_type);

    //data_map_key = s_gateway;
   // data_map_value = &data_map_value_null;
    data_map_value = ngx_http_iad_str_palloc(r);

    
    ngx_shmap_get(zone,&ngx_http_iad_domain, s_domain,&vt_str_cache,0,0);//���key_domain�Ƿ����
    //������������������Ϣ����ͨ��.�����������ж�
    if(i_action == 501){
        i_state = 0;
    }else{
        if(s_domain->len <= 0){i_state = 501;i_action = -1;}//��������δ��ʼ��
    }

    if(i_state != 0){ i_action = -1;}//״̬���������󣬲�����i_action = -1 ��������
    

    computed_arg_elts = computed_args->elts;
    for (i = 0; i < computed_args->nelts; i++) {
        computed_arg = &computed_arg_elts[i];		        
        
        switch(i_action){
            case 0:{
                if(data_map_key->len <= 0){i_state = -1;break;}//��key��Ϣ
                /*  ��zone �����в��Ҷ��� */
                ngx_shmap_get(zone,data_map_key, data_map_value,&vt_str_cache,0,0);

                //û���ҵ�
                if(data_map_value->len <= 0) {i_state = 2;} 
                break;
            }
                    
            case 1:{
                s_gateway = ngx_http_iad_timestamp(r);//����ע����Ϣ
                //ʹ��Ĭ�� 999999
                ngx_shmap_get(zone,&data_map_key_defalue, data_map_value,&vt_str_cache,0,0);
                if(data_map_value->len <= 0) i_state = 4;//Ĭ����Ϣδ��ʼ��
                break;
            }

            case 101:{      
                if(!(r->method & NGX_HTTP_POST)){i_state = -120;break;}//������������Ϊpost��ʽ          
                if(ngx_http_iad_arg(r, (u_char*)"iad", 3, s_iad)!=NGX_OK){i_state = -101;break;}//�޲���iad - ��Կ                 
                if(s_iad->len != computed_arg->len){ i_state = -102;break;}//����iad - ��Կ ���Ȳ�һ�� 
                if(ngx_strncmp(s_iad->data,computed_arg->data,computed_arg->len) != 0){ i_state = -103;break;}//����iad ������ ��Կ
                if(ngx_http_iad_arg(r, (u_char*)"data", 4, s_data)!=NGX_OK){ i_state = -104;break;}//�޲���data��Ϣ

                ngx_shmap_get(zone,data_map_key, data_map_value,&vt_str_cache,0,0);//���key�Ƿ����
                if(data_map_value->len > 0){ i_state = -105;break;}//key ��Ӧ value �Ѵ���

                ngx_str_set(data_map_value,s_data->data);//װ��data��Ϣ                 
                data_map_value->len = s_data->len;//������Ϣ����
                ngx_shmap_add(zone, data_map_key,data_map_value,VT_STRING,0,0);//���뻺������

                break;
            }

            case 102:{             
                if(ngx_http_iad_arg(r, (u_char*)"iad", 3, s_iad)!=NGX_OK){i_state = -101;break;}//�޲���iad - ��Կ 
                if(s_iad->len != computed_arg->len){ i_state = -102;break;}//����iad - ��Կ ���Ȳ�һ�� 
                if(ngx_strncmp(s_iad->data,computed_arg->data,computed_arg->len) != 0){ i_state = -103;break;}//����iad ������ ��Կ

                ngx_shmap_get(zone,data_map_key, data_map_value,&vt_str_cache,0,0);//���key�Ƿ����
                if(data_map_value->len > 0){ i_state = -105;break;}//key ��Ӧ value �Ѵ���

                ngx_shmap_delete(zone,data_map_key);//�Ƴ���������      
                break;
            }

            case 110:{             
                if(ngx_http_iad_arg(r, (u_char*)"iad", 3, s_iad)!=NGX_OK){i_state = -101;break;}//�޲���iad - ��Կ 
                if(s_iad->len != computed_arg->len){ i_state = -102;break;}//����iad - ��Կ ���Ȳ�һ�� 
                if(ngx_strncmp(s_iad->data,computed_arg->data,computed_arg->len) != 0){ i_state = -103;break;}//����iad ������ ��Կ
                
                ngx_shmap_flush_all(zone);//��������ֵ�

                break;
            }

            case 501:{
                if(!(r->method & NGX_HTTP_POST)){i_state = -120;break;}//������������Ϊpost��ʽ          
                if(ngx_http_iad_arg(r, (u_char*)"iad", 3, s_iad)!=NGX_OK){i_state = -101;break;}//�޲���iad - ��Կ                 
                if(s_iad->len != computed_arg->len){ i_state = -102;break;}//����iad - ��Կ ���Ȳ�һ�� 
                if(ngx_strncmp(s_iad->data,computed_arg->data,computed_arg->len) != 0){ i_state = -103;break;}//����iad ������ ��Կ
                if(ngx_http_iad_arg(r, (u_char*)"data", 4, s_data)!=NGX_OK){ i_state = -504;break;}//�޲���data��Ϣ                

                ngx_shmap_get(zone,&ngx_http_iad_domain, s_domain,&vt_str_cache,0,0);//���key�Ƿ����
                
                if(s_domain->len > 0){
                    ngx_shmap_replace(zone, &ngx_http_iad_domain,s_data,VT_STRING,0,0);//key ��Ӧ value �Ѵ���
                }else{
                    ngx_shmap_add(zone, &ngx_http_iad_domain,s_data,VT_STRING,0,0);//���뻺������
                }

                ngx_str_set(s_domain,s_data->data);//װ��data��Ϣ                 
                s_domain->len = s_data->len;//������Ϣ����                

                break;
            }

            case 9999:{
                //��Ч������һЩ��ʱ���õĶ���
                ngx_http_iad_cache_key(r,s_gateway,s_app_type);
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,":get Go len %d ]]",s_app_type->len);//��ӡ����
                break;
            }
                    
        }        

        //ƴ��json����                
        if(i_state == 0){
            str_json_len =  data_map_value->len + s_domain->len + 72;
            str_json_data_p = ngx_palloc(r->pool,str_json_len);  

            (void) ngx_snprintf(str_json_data_p, str_json_len,
                                "{\"state\":%d,\"domain\":[%V],\"gateway\":\"%V\",\"data\":\"%V\",\"time\":\"%T\"}",
                                i_state,
                                s_domain,
                                s_gateway,
                                data_map_value,
                                ngx_time()
                                );
        }else{       
            str_json_len = 34 ;
            if(i_state > 0 && i_state < 10) str_json_len =  31;
            if(i_state >= 10 && i_state < 100) str_json_len =  32;
            if(i_state >= 100) str_json_len =  33;
            if(i_state < 0 && i_state > -10) str_json_len =  32;
            if(i_state <= -10 && i_state > -100) str_json_len =  33;
            if(i_state <= -100) str_json_len =  34;

            str_json_data_p = ngx_palloc(r->pool,str_json_len);  
            (void) ngx_snprintf(str_json_data_p, str_json_len,
                                "{\"state\":%d,\"time\":\"%T\"}",
                                i_state,                                
                                ngx_time()
                                );
        }        
        
        ngx_str_send_json = ngx_http_iad_str_palloc(r);
        ngx_str_send_json->data = str_json_data_p;
        ngx_str_send_json->len = str_json_len;
        
        buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));//����ngx_buf_t�����ڴ�ռ�
        if (buf == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        buf->memory = 1;

        buf->start = buf->pos = ngx_str_send_json->data;
        buf->last = buf->end = ngx_str_send_json->data + ngx_str_send_json->len;

        if (cl == NULL) {

            /* buf_state */
            cl = ngx_alloc_chain_link(r->pool);
            if (cl == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            cl->buf  = buf;
            cl->next = NULL;
            ll = &cl->next;

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

            /* Ȼ�����buf */
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
		r->headers_out.content_type.len = sizeof("application/json") - 1;
		r->headers_out.content_type.data = (u_char *) "application/json";
		r->headers_out.content_length_n = ngx_buf_size(cl->buf); //application/json
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

    ngx_str_set(&data_map_key_defalue,"999999");//Ĭ��keyֵ
    ngx_str_set(&ngx_http_iad_domain,"domain");//Ĭ��keyֵ
	
	return NGX_CONF_OK;
}


static ngx_str_t* ngx_http_iad_str_palloc(ngx_http_request_t *r)
{
    ngx_str_t *value;
    value = ngx_palloc(r->pool,sizeof(ngx_str_t));
    value->len = 0;
    return value;
}


static ngx_str_t* ngx_http_iad_timestamp(ngx_http_request_t *r)
{
    ngx_str_t       *ngx_timestamp;    
    ngx_tm_t        *gmt;
    u_char          *p_time;

    ngx_timestamp = ngx_http_iad_str_palloc(r);
    gmt = ngx_palloc(r->pool,sizeof(ngx_tm_t));
    p_time = ngx_palloc(r->pool,8);

    ngx_gmtime(ngx_time() + 28800 , gmt); // 28800 = 8 * 60 * 60 ���й�������Ҫ �� 8Сʱ
    
    (void) ngx_snprintf(p_time, 8, "%4d%02d%02d",gmt->ngx_tm_year,gmt->ngx_tm_mon,gmt->ngx_tm_mday);

    ngx_timestamp->data = p_time + 2;//ƫ�ƶ���ָ�룬"20140506" -> "140506" 
    ngx_timestamp->len = 6;

    return ngx_timestamp;
    
}


static ngx_int_t ngx_http_iad_arg(ngx_http_request_t *r, u_char *name, size_t len,ngx_str_t *value)
{   

    u_char  *p, *last, *start, *end;

    if (r->method & NGX_HTTP_POST) {
        p = r->header_in->pos;
        last = r->header_in->last;
        start = r->header_in->pos;
        end = r->header_in->last;   
    }else{
        p = r->args.data;
        last = p + r->args.len;
        start = r->args.data;
        end = p + r->args.len;  
    }
            

    for ( /* void */ ; p < last; p++) {

        p = ngx_strlcasestrn(p, last - 1, name, len - 1);

        if (p == NULL) {
            return NGX_DECLINED;
        }

        if ((p == start || *(p - 1) == '&') && *(p + len) == '=') {

            value->data = p + len + 1;

            p = ngx_strlchr(p, last, '&');

            if (p == NULL) {
                p = end;
            }

            value->len = p - value->data;

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
     
}

static ngx_str_t* ngx_http_iad_cache_key(ngx_http_request_t *r,ngx_str_t *gateway,ngx_str_t *type)
{
    ngx_str_t       *s_key;
    u_char          *s_gt_value;
    size_t          i_size;

    
    
    s_key = ngx_http_iad_str_palloc(r);
    s_key->len = 0;
    
    
    if(gateway->len <= 0 || type->len <=0){ return s_key;}
        
    i_size = gateway->len + type->len + 1;

    s_gt_value = ngx_palloc(r->pool,i_size);    

    (void) ngx_snprintf(s_gt_value, i_size, "%V_%V",gateway,type);

    s_key->data = s_gt_value; 
    s_key->len = i_size;

    return s_key;
    
}


