
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct ngx_http_cross_origin_val_s {
    ngx_uint_t                 hash;
    ngx_str_t                  value;
} ngx_http_cross_origin_val_t;


typedef struct {
    ngx_array_t  *origin_list;
    ngx_array_t  *method_list;
    ngx_array_t  *header_list;
    ngx_flag_t    origin_unbounded;
    ngx_flag_t    method_unbounded;
    ngx_flag_t    header_unbounded;
    ngx_flag_t    support_credential;
} ngx_http_cross_origin_loc_conf_t;


static void *ngx_http_cross_origin_create_conf(ngx_conf_t *cf);
static char *ngx_http_cross_origin_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_cross_origin_init(ngx_conf_t *cf);

static char *ngx_http_cors_origin_list(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cors_method_list(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cors_header_list(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_cross_origin_commands[] = {

    { ngx_string("cors_origin_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_cors_origin_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("cors_method_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_cors_method_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("cors_header_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_cors_header_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("cors_support_credential"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cross_origin_loc_conf_t, support_credential),
      NULL},

      ngx_null_command
};


static ngx_http_module_t  ngx_http_cross_origin_module_ctx = {
    NULL,                                       /* preconfiguration */
    ngx_http_cross_origin_init,                 /* postconfiguration */

    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */

    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */

    ngx_http_cross_origin_create_conf,          /* create location configuration */
    ngx_http_cross_origin_merge_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_cross_origin_module = {
    NGX_MODULE_V1,
    &ngx_http_cross_origin_module_ctx,     /* module context */
    ngx_http_cross_origin_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_int_t
ngx_http_cross_origin_rewrite_handler(ngx_http_request_t *r)
{
    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_cross_origin_filter(ngx_http_request_t *r)
{
    ngx_http_cross_origin_loc_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_cross_origin_module);

    return ngx_http_next_header_filter(r);
}


static void *
ngx_http_cross_origin_create_conf(ngx_conf_t *cf)
{
    ngx_http_cross_origin_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cross_origin_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->origin_list  = NULL;
     *     conf->method_list  = NULL;
     *     conf->header_list  = NULL;
     */

    conf->origin_unbounded  = NGX_CONF_UNSET;
    conf->method_unbounded  = NGX_CONF_UNSET;
    conf->header_unbounded  = NGX_CONF_UNSET;
    conf->support_credential = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_cross_origin_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_cross_origin_loc_conf_t *prev = parent;
    ngx_http_cross_origin_loc_conf_t *conf = child;

    if (conf->origin_list == NULL) {
        conf->origin_list = prev->origin_list;
    }

    ngx_conf_merge_value(conf->support_credential, prev->support_credential, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_cross_origin_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt             *h;
    ngx_http_core_main_conf_t       *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_cross_origin_rewrite_handler;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_cross_origin_filter;

    return NGX_OK;
}


static char *
ngx_http_cors_origin_list(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cross_origin_loc_conf_t  *crolcf = conf;

    ngx_str_t                         *value;
    ngx_uint_t                         i;
    ngx_http_cross_origin_val_t       *cov;

    value = cf->args->elts;

    if (crolcf->origin_list == NULL) {
        crolcf->origin_list = ngx_array_create(cf->pool, 4,
                                        sizeof(ngx_http_cross_origin_val_t));
        if (crolcf->origin_list == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "unbounded") == 0) {
            crolcf->origin_unbounded = 1;
            break;
        }

        cov = ngx_array_push(crolcf->origin_list);
        if (cov == NULL) {
            return NGX_CONF_ERROR;
        }

        cov->hash = ngx_hash_key(value[i].data, value[i].len);
        cov->value = value[i];
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_cors_method_list(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cross_origin_loc_conf_t  *crolcf = conf;

    ngx_str_t                         *value;
    ngx_uint_t                         i;
    ngx_http_cross_origin_val_t       *cov;

    value = cf->args->elts;

    if (crolcf->method_list == NULL) {
        crolcf->method_list = ngx_array_create(cf->pool, 4,
                                        sizeof(ngx_http_cross_origin_val_t));
        if (crolcf->method_list == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "unbounded") == 0) {
            crolcf->method_unbounded = 1;
            break;
        }

        cov = ngx_array_push(crolcf->method_list);
        if (cov == NULL) {
            return NGX_CONF_ERROR;
        }

        cov->hash = ngx_hash_key(value[i].data, value[i].len);
        cov->value = value[i];
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_cors_header_list(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cross_origin_loc_conf_t  *crolcf = conf;

    ngx_str_t                         *value;
    ngx_uint_t                         i;
    ngx_http_cross_origin_val_t       *cov;

    value = cf->args->elts;

    if (crolcf->header_list == NULL) {
        crolcf->header_list = ngx_array_create(cf->pool, 4,
                                        sizeof(ngx_http_cross_origin_val_t));
        if (crolcf->header_list == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "unbounded") == 0) {
            crolcf->header_unbounded = 1;
            break;
        }

        cov = ngx_array_push(crolcf->header_list);
        if (cov == NULL) {
            return NGX_CONF_ERROR;
        }

        cov->hash = ngx_hash_key(value[i].data, value[i].len);
        cov->value = value[i];
    }

    return NGX_CONF_OK;
}
