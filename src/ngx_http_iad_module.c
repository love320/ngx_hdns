
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

static ngx_shm_zone_t* zone ;//缓存集

static ngx_str_t data_map_key_defalue = ngx_null_string;//默认key 999999

static ngx_str_t ngx_http_iad_domain = ngx_null_string;//网关主-备 信息


/* 过滤器 初始化 */
static ngx_int_t ngx_http_iad_filter_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_iad_header_filter(ngx_http_request_t *r);

static ngx_int_t ngx_http_iad_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

/* 初始化模块处理器 */
static ngx_int_t ngx_http_iad_init(ngx_conf_t *cf);

/* 初始化模块处理器的配置信息 */
static void* ngx_http_iad_create_conf(ngx_conf_t *cf);

/* 处理指令配置信息 */
static char* ngx_http_iad_iad(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char*
ngx_http_iad_helper(ngx_http_iad_opcode_t opcode,
        ngx_http_iad_cmd_category_t cat,
        ngx_conf_t *cf, ngx_command_t *cmd, void* conf);

/* 主内容处理器 */
static ngx_int_t ngx_http_iad_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_iad_exec_iad(ngx_http_request_t *r,
        ngx_http_iad_ctx_t *ctx, ngx_array_t *computed_args);

static ngx_int_t ngx_http_iad_eval_cmd_args(ngx_http_request_t *r,
        ngx_http_iad_cmd_t *cmd, ngx_array_t *computed_args);

static ngx_int_t ngx_http_iad_send_chain_link(ngx_http_request_t* r,
        ngx_http_iad_ctx_t *ctx, ngx_chain_t *cl);
		
static char* ngx_http_iad_init_main_conf(ngx_conf_t *cf,void* conf);

static ngx_str_t* ngx_http_iad_timestamp(ngx_http_request_t *r); //处理时间格式，专用 gateway

static ngx_int_t ngx_http_iad_arg(ngx_http_request_t *r, u_char *name, size_t len,ngx_str_t *value);//通用获取参数信息 支持get post

static ngx_str_t* ngx_http_iad_cache_key(ngx_http_request_t *r,ngx_str_t *gateway,ngx_str_t *type);//合成缓存key值信息

static ngx_str_t* ngx_http_iad_str_palloc(ngx_http_request_t *r);//专用 ngx_str_t 申请内存器并初始化

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
    ngx_http_iad_init,              /* 在创建和读取该模块的配置信息之前被调用 */
    NULL,                          	/* 在创建和读取该模块的配置信息之后被调用 */

    NULL,                         	/* 创建主配置信息时被调用 */
    ngx_http_iad_init_main_conf,  	/* 初始化主配置信息时被调用 */

    NULL,                          	/* 创建服务器配置信息时被调用*/
    NULL,                          	/* 服务器配置合并信息时被调用*/

    ngx_http_iad_create_conf, 		/* 创建本地配置信息时被调用*/
    NULL                           	/* 本地配置合并信息时被调用*/
};

ngx_module_t ngx_http_iad_module = {
    NGX_MODULE_V1,
    &ngx_http_iad_module_ctx, 		/* 模块内容*/
    ngx_http_iad_commands,   		/* 模块指令*/
    NGX_HTTP_MODULE,                /* 模块类型*/
    NULL,                           /* 初始化主方法*/
    NULL,                           /* 初始化模块方法*/
    NULL,                           /* 初始化处理方法*/
    NULL,                           /* 初始化线程*/
    NULL,                           /* 退出线程*/
    NULL,                           /* 退出处理*/
    NULL,                           /* 退出主方法*/
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

    /* 根据实际偏移量进行调整 */
    cmds_ptr = (ngx_array_t**)(((u_char*)conf) + cmd->offset);
    if (*cmds_ptr == NULL) {
        *cmds_ptr = ngx_array_create(cf->pool, 1,
                sizeof(ngx_http_iad_cmd_t));
        if (*cmds_ptr == NULL) {
            return NGX_CONF_ERROR;
        }
        if (cat == iad_handler_cmd) {
              /* 注册内容到处理程序 */
            clcf = ngx_http_conf_get_module_loc_conf(cf,
                    ngx_http_core_module);
            if (clcf == NULL) {
                return NGX_CONF_ERROR;
            }
 
            clcf->handler = ngx_http_iad_handler;
        } else {
            /* init 方法 确定只初始化一次
             * 防止初始化二次 */
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
    /* 我们跳过第一个参数,从第二个开始 */
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

	/* 从本地 loc request 中 获取 ngx_http_iad_module 配置信息 */
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

        /* 评估当前cmd参数(如果有的话) */
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

        /* 指挥调度基于操作码吗 */
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
    //ngx_str_t                   data_map_value_null = ngx_null_string;//此信息不加入r->pool中，这个是缓存值不释放
    
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
    


    ngx_chain_t *cl  = NULL; /* 链的链接 */
    ngx_chain_t **ll = NULL;  /* 总是指向最后一个链接的地址 */

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

    /* 获取 mid 参数信息 */
    if(ngx_http_iad_arg(r, (u_char*)"gateway", 7, s_gateway)!=NGX_OK){};

    /* appType */
    if(ngx_http_iad_arg(r, (u_char*)"appType", 7, s_app_type)!=NGX_OK){i_state = -201;}//应用APP信息 没有

    /* 获取 action 参数信息 */
    if(ngx_http_iad_arg(r, (u_char*)"action", 6, s_szn)==NGX_OK){
        i_action = ngx_atoi(s_szn->data, s_szn->len);    
    }

    //若用户是注册，则action = 1;
    if(i_action == 0 && s_gateway->len == 0) i_action = 1;

    /* 获取key信息 */
    data_map_key = ngx_http_iad_cache_key(r,s_gateway,s_app_type);

    //data_map_key = s_gateway;
   // data_map_value = &data_map_value_null;
    data_map_value = ngx_http_iad_str_palloc(r);

    
    ngx_shmap_get(zone,&ngx_http_iad_domain, s_domain,&vt_str_cache,0,0);//检测key_domain是否存在
    //若是设置网关主备信息，则通过.可以跳过上判断
    if(i_action == 501){
        i_state = 0;
    }else{
        if(s_domain->len <= 0){i_state = 501;i_action = -1;}//网关域名未初始化
    }

    if(i_state != 0){ i_action = -1;}//状态不满足需求，不处理。i_action = -1 跳过处理
    

    computed_arg_elts = computed_args->elts;
    for (i = 0; i < computed_args->nelts; i++) {
        computed_arg = &computed_arg_elts[i];		        
        
        switch(i_action){
            case 0:{
                if(data_map_key->len <= 0){i_state = -1;break;}//无key信息
                /*  从zone 缓存中查找对象 */
                ngx_shmap_get(zone,data_map_key, data_map_value,&vt_str_cache,0,0);

                //没有找到
                if(data_map_value->len <= 0) {i_state = 2;} 
                break;
            }
                    
            case 1:{
                s_gateway = ngx_http_iad_timestamp(r);//分配注册信息
                //使用默认 999999
                ngx_shmap_get(zone,&data_map_key_defalue, data_map_value,&vt_str_cache,0,0);
                if(data_map_value->len <= 0) i_state = 4;//默认信息未初始化
                break;
            }

            case 101:{      
                if(!(r->method & NGX_HTTP_POST)){i_state = -120;break;}//新增操作必需为post方式          
                if(ngx_http_iad_arg(r, (u_char*)"iad", 3, s_iad)!=NGX_OK){i_state = -101;break;}//无参数iad - 密钥                 
                if(s_iad->len != computed_arg->len){ i_state = -102;break;}//参数iad - 密钥 长度不一致 
                if(ngx_strncmp(s_iad->data,computed_arg->data,computed_arg->len) != 0){ i_state = -103;break;}//参数iad 不等于 密钥
                if(ngx_http_iad_arg(r, (u_char*)"data", 4, s_data)!=NGX_OK){ i_state = -104;break;}//无参数data信息

                ngx_shmap_get(zone,data_map_key, data_map_value,&vt_str_cache,0,0);//检测key是否存在
                if(data_map_value->len > 0){ i_state = -105;break;}//key 对应 value 已存在

                ngx_str_set(data_map_value,s_data->data);//装载data信息                 
                data_map_value->len = s_data->len;//设置信息长度
                ngx_shmap_add(zone, data_map_key,data_map_value,VT_STRING,0,0);//加入缓存数据

                break;
            }

            case 102:{             
                if(ngx_http_iad_arg(r, (u_char*)"iad", 3, s_iad)!=NGX_OK){i_state = -101;break;}//无参数iad - 密钥 
                if(s_iad->len != computed_arg->len){ i_state = -102;break;}//参数iad - 密钥 长度不一致 
                if(ngx_strncmp(s_iad->data,computed_arg->data,computed_arg->len) != 0){ i_state = -103;break;}//参数iad 不等于 密钥

                ngx_shmap_get(zone,data_map_key, data_map_value,&vt_str_cache,0,0);//检测key是否存在
                if(data_map_value->len > 0){ i_state = -105;break;}//key 对应 value 已存在

                ngx_shmap_delete(zone,data_map_key);//移除缓存数据      
                break;
            }

            case 110:{             
                if(ngx_http_iad_arg(r, (u_char*)"iad", 3, s_iad)!=NGX_OK){i_state = -101;break;}//无参数iad - 密钥 
                if(s_iad->len != computed_arg->len){ i_state = -102;break;}//参数iad - 密钥 长度不一致 
                if(ngx_strncmp(s_iad->data,computed_arg->data,computed_arg->len) != 0){ i_state = -103;break;}//参数iad 不等于 密钥
                
                ngx_shmap_flush_all(zone);//清空整个字典

                break;
            }

            case 501:{
                if(!(r->method & NGX_HTTP_POST)){i_state = -120;break;}//新增操作必需为post方式          
                if(ngx_http_iad_arg(r, (u_char*)"iad", 3, s_iad)!=NGX_OK){i_state = -101;break;}//无参数iad - 密钥                 
                if(s_iad->len != computed_arg->len){ i_state = -102;break;}//参数iad - 密钥 长度不一致 
                if(ngx_strncmp(s_iad->data,computed_arg->data,computed_arg->len) != 0){ i_state = -103;break;}//参数iad 不等于 密钥
                if(ngx_http_iad_arg(r, (u_char*)"data", 4, s_data)!=NGX_OK){ i_state = -504;break;}//无参数data信息                

                ngx_shmap_get(zone,&ngx_http_iad_domain, s_domain,&vt_str_cache,0,0);//检测key是否存在
                
                if(s_domain->len > 0){
                    ngx_shmap_replace(zone, &ngx_http_iad_domain,s_data,VT_STRING,0,0);//key 对应 value 已存在
                }else{
                    ngx_shmap_add(zone, &ngx_http_iad_domain,s_data,VT_STRING,0,0);//加入缓存数据
                }

                ngx_str_set(s_domain,s_data->data);//装载data信息                 
                s_domain->len = s_data->len;//设置信息长度                

                break;
            }

            case 9999:{
                //无效区，放一些暂时不用的东东
                ngx_http_iad_cache_key(r,s_gateway,s_app_type);
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,":get Go len %d ]]",s_app_type->len);//打印内容
                break;
            }
                    
        }        

        //拼接json数据                
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
        
        buf = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));//开创ngx_buf_t类型内存空间
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
            /* 附加一个空间 */
            *ll = ngx_alloc_chain_link(r->pool);
            if (*ll == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            space_buf = ngx_calloc_buf(r->pool);
            if (space_buf == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            /*  nginx清除buf在每个请求处理,
				所以我们必须在这里进行一个克隆 */
            *space_buf = ngx_http_iad_space_buf;

            (*ll)->buf = space_buf;
            (*ll)->next = NULL;

            ll = &(*ll)->next;

            /* 然后添加buf */
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
	
		/*	声明使用text/html模式返回信息 */
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
        if (arg->lengths == NULL) { /* 不包含增值 */
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
	size_t shm_size =1024*1024*10; //设置缓存大小 1024*1024*10 = 10M
	ngx_str_t iad_shm_name = ngx_string("shm_iad_cache_zone"); //设置缓存的名字
	zone = ngx_shmap_init(cf,&iad_shm_name,shm_size,&ngx_http_iad_module);//初始化缓存对象

    ngx_str_set(&data_map_key_defalue,"999999");//默认key值
    ngx_str_set(&ngx_http_iad_domain,"domain");//默认key值
	
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

    ngx_gmtime(ngx_time() + 28800 , gmt); // 28800 = 8 * 60 * 60 在中国地区需要 加 8小时
    
    (void) ngx_snprintf(p_time, 8, "%4d%02d%02d",gmt->ngx_tm_year,gmt->ngx_tm_mon,gmt->ngx_tm_mday);

    ngx_timestamp->data = p_time + 2;//偏移二个指针，"20140506" -> "140506" 
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


