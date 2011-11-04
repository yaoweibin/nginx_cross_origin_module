

/* All the cross origin request process steps follow this RFC:  
 *
 * http://www.w3.org/TR/cors/
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define SP ' '

typedef struct {
    u_char    *name;
    uint32_t   method;
} ngx_http_corss_origin_method_name_t;


typedef struct ngx_http_cross_origin_val_s {
    ngx_uint_t                 hash;
    ngx_str_t                  value;
} ngx_http_cross_origin_val_t;


typedef struct {
    ngx_array_t  *origin_list;
    ngx_array_t  *method_list;
    ngx_array_t  *header_list;
    ngx_array_t  *expose_header_list;
    ngx_flag_t    enable;
    ngx_flag_t    origin_unbounded;
    ngx_flag_t    method_unbounded;
    ngx_flag_t    header_unbounded;
    ngx_flag_t    support_credential;
    time_t        max_age;

    ngx_str_t                  preflight_response_type;
    ngx_http_complex_value_t   preflight_response;
} ngx_http_cross_origin_loc_conf_t;


static ngx_int_t ngx_http_cross_origin_rewrite_handler(ngx_http_request_t *r);
static ngx_table_elt_t *ngx_http_cross_origin_search_header(
        ngx_http_request_t *r, ngx_str_t *name);
static ngx_array_t *ngx_http_cross_origin_search_multi_header(
        ngx_http_request_t *r, ngx_str_t *name);
static ngx_int_t ngx_http_cross_origin_search_list(ngx_array_t *arr, 
        ngx_str_t *name, ngx_flag_t case_insensitive);
static ngx_uint_t ngx_http_cross_origin_get_method(ngx_str_t *method);
static ngx_int_t ngx_http_cross_origin_add_header(ngx_http_request_t *r, 
        ngx_str_t *key, ngx_str_t *value);
static ngx_int_t ngx_http_cross_origin_search_string(ngx_str_t *string_array, 
        ngx_str_t *name, ngx_flag_t case_insensitive);
static ngx_str_t *ngx_http_cross_origin_concatenate_list_value(
        ngx_http_request_t *r, ngx_array_t *arr);
static ngx_array_t *ngx_http_cross_origin_split_string(ngx_http_request_t *r, 
        ngx_str_t *str, u_char separator);

static ngx_int_t ngx_http_cross_origin_filter(ngx_http_request_t *r);

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
static char *ngx_http_cors_expose_header_list(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_cors_preflight_response(ngx_conf_t *cf, 
        ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_cross_origin_commands[] = {

    { ngx_string("cors"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cross_origin_loc_conf_t, enable),
      NULL},

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

    { ngx_string("cors_expose_header_list"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_cors_expose_header_list,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("cors_max_age"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cross_origin_loc_conf_t, max_age),
      NULL},

    { ngx_string("cors_support_credential"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cross_origin_loc_conf_t, support_credential),
      NULL},

    { ngx_string("cors_preflight_response"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_cors_preflight_response,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    { ngx_string("cors_preflight_response_type"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cross_origin_loc_conf_t, preflight_response_type),
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

static ngx_str_t request_origin_header = ngx_string("Origin");
static ngx_str_t request_method_header = ngx_string("Access-Control-Request-Method");
static ngx_str_t request_headers_header = ngx_string("Access-Control-Request-Headers");

static ngx_str_t response_origin_header = ngx_string("Access-Control-Allow-Origin");
static ngx_str_t response_credential_header = ngx_string("Access-Control-Allow-Credentials");
static ngx_str_t response_max_age_header = ngx_string("Access-Control-Max-Age");
static ngx_str_t response_method_header = ngx_string("Access-Control-Allow-Methods");
static ngx_str_t response_headers_header = ngx_string("Access-Control-Allow-Headers");
static ngx_str_t response_expose_headers_header = ngx_string("Access-Control-Expose-Headers");

static ngx_str_t response_credential_true = ngx_string("true");

#define DEFAULT_RESPONSE_CONTENT_TYPE "text/plain"

/* case-sensitive */
static ngx_str_t simple_methods[] = {
    ngx_string("GET"),
    ngx_string("HEAD"),
    ngx_string("POST"),
    { 0, NULL }
};

/* case-insensitive */
static ngx_str_t simple_headers[] = {
    ngx_string("Accept"),
    ngx_string("Accept-Language"),
    ngx_string("Content-Language"),
    ngx_string("Last-Event-ID"),
    { 0, NULL }
};

#if 0
/* case-insensitive */
static ngx_str_t simple_types[] = {
    ngx_string("application/x-www-form-urlencoded"),
    ngx_string("multipart/form-data"),
    ngx_string("text/plain"),
    { 0, NULL }
};
#endif

/* case-insensitive */
static ngx_str_t simple_response_headers[] = {
    ngx_string("Cache-Control"),
    ngx_string("Content-Language"),
    ngx_string("Content-Type"),
    ngx_string("Expires"),
    ngx_string("Last-Modified"),
    ngx_string("Pragma"),
    { 0, NULL }
};


static ngx_http_corss_origin_method_name_t  ngx_methods_names[] = {
   { (u_char *) "GET",       (uint32_t) NGX_HTTP_GET },
   { (u_char *) "HEAD",      (uint32_t) NGX_HTTP_HEAD },
   { (u_char *) "POST",      (uint32_t) NGX_HTTP_POST },
   { (u_char *) "PUT",       (uint32_t) NGX_HTTP_PUT },
   { (u_char *) "DELETE",    (uint32_t) NGX_HTTP_DELETE },
   { (u_char *) "MKCOL",     (uint32_t) NGX_HTTP_MKCOL },
   { (u_char *) "COPY",      (uint32_t) NGX_HTTP_COPY },
   { (u_char *) "MOVE",      (uint32_t) NGX_HTTP_MOVE },
   { (u_char *) "OPTIONS",   (uint32_t) NGX_HTTP_OPTIONS },
   { (u_char *) "PROPFIND" , (uint32_t) NGX_HTTP_PROPFIND },
   { (u_char *) "PROPPATCH", (uint32_t) NGX_HTTP_PROPPATCH },
   { (u_char *) "LOCK",      (uint32_t) NGX_HTTP_LOCK },
   { (u_char *) "UNLOCK",    (uint32_t) NGX_HTTP_UNLOCK },
   { (u_char *) "PATCH",     (uint32_t) NGX_HTTP_PATCH },
   { (u_char *) "TRACE",     (uint32_t) NGX_HTTP_TRACE },
   { NULL, 0 }
};


/* For Preflight Request */
static ngx_int_t
ngx_http_cross_origin_rewrite_handler(ngx_http_request_t *r)
{
    u_char                           *last;
    ngx_str_t                        *origin_name, str_max_age;
    ngx_str_t                        *method_name;
    ngx_str_t                        *str_tmp;
    ngx_uint_t                        method, match, not_simple, i;
    /* array of ngx_table_elt_t */
    ngx_array_t                      *headers, *allow_headers;   
    ngx_table_elt_t                  *h;
    ngx_http_cross_origin_loc_conf_t *colcf;
    
    allow_headers = NULL;

    colcf = ngx_http_get_module_loc_conf(r, ngx_http_cross_origin_module);

    if (!colcf->enable) {
        goto leave;
    }

    if (!(r->method & (NGX_HTTP_OPTIONS))) {
        goto leave;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cross origin rewrite handler \"%V\"", &r->uri);

    /* Step 1 */
    h = ngx_http_cross_origin_search_header(r, &request_origin_header);
    if (h == NULL) {
        goto leave;
    }
    origin_name = &h->value;

    /* Step 2 */
    if (!colcf->origin_unbounded) {
        if (!ngx_http_cross_origin_search_list(colcf->origin_list, origin_name, 0)) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http cross origin header not include in the list of origin");
            goto leave;
        }
    }

    /* Step 3 */
    /* Is this necesssary? */
    h = ngx_http_cross_origin_search_header(r, &request_method_header);
    if (h == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "http cross origin not include the request method header");
        goto leave;
    }

    method = ngx_http_cross_origin_get_method(&h->value);
    if (method == NGX_HTTP_UNKNOWN) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "http cross origin get unknown method");
        goto leave;
    }
    method_name = &h->value;
    
    /* Step 4 */
    headers = ngx_http_cross_origin_search_multi_header(r, &request_headers_header);
    if (headers != NULL) {
        /*Parsing ?*/
    }

    /* Step 5 */
    if (!colcf->method_unbounded) {
        if (!ngx_http_cross_origin_search_list(colcf->method_list, method_name, 0)) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http cross origin method not include in the list of method");
            goto leave;
        }
    }

    /* Step 6 */
    if (!colcf->header_unbounded) {
        match = 0;
        if (headers) {
            h = headers->elts;
            for (i = 0; i < headers->nelts; i++) {
                if (ngx_http_cross_origin_search_list(colcf->header_list, 
                            &h[i].value, 1)) {
                    match++;

                    if (allow_headers == NULL) {

                        allow_headers = ngx_array_create(r->pool, 1, sizeof(ngx_str_t *));
                        if (allow_headers == NULL) {
                            return NGX_ERROR;
                        }
                    }

                    str_tmp = ngx_array_push(allow_headers);
                    if (str_tmp == NULL) {
                        return NGX_ERROR;
                    }

                    str_tmp = &h[i].value;
                }
            }
        }

        if (match == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http cross origin request header not include in the list of headers");
            goto leave;
        }
    }

    /* Step 7 */
    if (colcf->support_credential) {

        if (ngx_http_cross_origin_add_header(r, &response_origin_header, origin_name)
                == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (ngx_http_cross_origin_add_header(r, &response_credential_header, 
                    &response_credential_true) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }
    else {
        if (ngx_http_cross_origin_add_header(r, &response_origin_header, origin_name)
                == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    /* Step 8 */
    if (colcf->max_age) {
        str_max_age.data = ngx_pcalloc(r->pool, 64);
        if (str_max_age.data == NULL) {
            return NGX_ERROR;
        }

        last = ngx_snprintf(str_max_age.data, 64, "%T", colcf->max_age);

        str_max_age.len = last - str_max_age.data;

        if (ngx_http_cross_origin_add_header(r, &response_max_age_header, 
                    &str_max_age) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    /* Step 9 */
    if (!ngx_http_cross_origin_search_string(simple_methods, method_name, 0)) {
        /* XXX: Multi-filed-name in one or more headers? */
        str_tmp = ngx_http_cross_origin_concatenate_list_value(r, 
                colcf->method_list);

        if (str_tmp && ngx_http_cross_origin_add_header(r, 
                    &response_method_header, str_tmp) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    /* Step 10 */
    not_simple = 0;
    if (headers) {
        h = headers->elts;
        for (i = 0; i < headers->nelts; i++) {
            if (!ngx_http_cross_origin_search_string(simple_headers, &h[i].value, 1)) {
                not_simple = 1;
                break;
            }
        }
    }

    if (not_simple) {
        str_tmp = ngx_http_cross_origin_concatenate_list_value(r, 
                colcf->header_list);

        if (str_tmp && ngx_http_cross_origin_add_header(r, 
                    &response_headers_header, str_tmp) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }
    else if (colcf->header_unbounded && headers) {
        h = headers->elts;
        for (i = 0; i < headers->nelts; i++) {
            if (ngx_http_cross_origin_add_header(r, 
                        &response_headers_header, &h[i].value) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http cross origin prefight ok, send the response.");

    /* At last, send this preflight response */
    return ngx_http_send_response(r, 200, &colcf->preflight_response_type, 
            &colcf->preflight_response);

leave:

    return NGX_DECLINED;
}


/* For Simple Cross-Origin Request, Actual Request, and Redirects */
static ngx_int_t
ngx_http_cross_origin_filter(ngx_http_request_t *r)
{
    ngx_str_t                         *n, *origin_name, *str_tmp;
    ngx_uint_t                         match, i;
    ngx_array_t                       *names;
    ngx_table_elt_t                   *h;
    ngx_http_cross_origin_loc_conf_t  *colcf;

    colcf = ngx_http_get_module_loc_conf(r, ngx_http_cross_origin_module);

    if (!colcf->enable) {
        goto next_filter;
    }

    /* For testing, the preflight should be replied in the rewrite handler */
    if (r->method & (NGX_HTTP_OPTIONS)) {
        goto next_filter;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http cross origin filter");

    /* Step 1 */
    h = ngx_http_cross_origin_search_header(r, &request_origin_header);
    if (h == NULL) {
        goto next_filter;
    }
    origin_name = &h->value;
    
    /* Step 2 */
    if (!colcf->origin_unbounded) {
        match = 0;
        if (ngx_strlchr(origin_name->data, origin_name->data + origin_name->len, SP)) {
            /* Multiple origin names */
            names = ngx_http_cross_origin_split_string(r, origin_name, SP);
            if (names) {
                n = names->elts;
                for (i = 0; i < names->nelts; i++) {
                    if (ngx_http_cross_origin_search_list(colcf->origin_list, 
                                &n[i], 0)) {
                        match = 1;
                    }
                }
            }
        }
        else {
            /* Single origin name */
            if (ngx_http_cross_origin_search_list(colcf->origin_list, origin_name, 0)) {
                match = 1;
            }
        }

        if (match == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "http cross origin header not include in the list of origin");
            goto next_filter;
        }
    }

    /* Step 3 */
    if (colcf->support_credential) {

        if (ngx_http_cross_origin_add_header(r, &response_origin_header, origin_name)
                == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (ngx_http_cross_origin_add_header(r, &response_credential_header, 
                    &response_credential_true) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }
    else {
        if (ngx_http_cross_origin_add_header(r, &response_origin_header, origin_name)
                == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    /* Step 4 */
    if (colcf->expose_header_list && colcf->expose_header_list->nelts) {

        /* XXX: Multi-filed-name in one or more headers? */
        str_tmp = ngx_http_cross_origin_concatenate_list_value(r, 
                colcf->expose_header_list);

        if (str_tmp && ngx_http_cross_origin_add_header(r, 
                    &response_expose_headers_header, str_tmp) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http cross origin filter all ok");

next_filter:
    return ngx_http_next_header_filter(r);
}


static ngx_table_elt_t *
ngx_http_cross_origin_search_header(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_uint_t                   i;
    ngx_table_elt_t             *h;
    ngx_list_part_t             *part;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == name->len
                && ngx_strncasecmp(h[i].key.data, name->data, name->len) == 0)
        {
            return &h[i];
        }
    }

    return NULL;
}


static ngx_array_t *
ngx_http_cross_origin_search_multi_header(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_uint_t                   i;
    ngx_array_t                 *arr;
    ngx_table_elt_t             *h, *te;
    ngx_list_part_t             *part;

    arr = NULL;
    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == name->len
                && ngx_strncasecmp(h[i].key.data, name->data, name->len) == 0)
        {

            if (arr == NULL) {

                arr = ngx_array_create(r->pool, 1, sizeof(ngx_table_elt_t));
                if (arr == NULL) {
                    return NULL;
                }
            }

            te = ngx_array_push(arr);
            if (te == NULL) {
                return NULL;
            }

            *te = h[i];

        }
    }

    return arr;
}


static ngx_int_t 
ngx_http_cross_origin_search_list(ngx_array_t *arr, ngx_str_t *name, 
        ngx_flag_t case_insensitive)
{
    ngx_uint_t                   i, hash;
    ngx_http_cross_origin_val_t *elt;

    if (arr == NULL || name == NULL || name->len == 0) {
        return 0;
    }

    if (case_insensitive) {
        hash = ngx_hash_key_lc(name->data, name->len);
    }
    else {
        hash = ngx_hash_key(name->data, name->len);
    }

    elt = arr->elts;

    for (i = 0; i < arr->nelts; i++) {

        if (elt[i].hash != hash) {
            continue;
        }

        if (!case_insensitive && elt[i].value.len == name->len
                && ngx_strncmp(elt[i].value.data, name->data, name->len) == 0)
        {
            return 1;
        }

        if (case_insensitive && elt[i].value.len == name->len
                && ngx_strncasecmp(elt[i].value.data, name->data, name->len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


static ngx_uint_t
ngx_http_cross_origin_get_method(ngx_str_t *method)
{
    ngx_uint_t                           i;
    ngx_http_corss_origin_method_name_t *m;

    m = ngx_methods_names;
    
    for (i = 0; /* void */; i++) {

        if (m[i].name == NULL) {
            break;
        }

        if (ngx_strncmp(m[i].name, method->data, method->len) == 0)
        {
            return m[i].method;
        }
    }

    return NGX_HTTP_UNKNOWN;
}


static ngx_int_t
ngx_http_cross_origin_add_header(ngx_http_request_t *r, ngx_str_t *key,
    ngx_str_t *value)
{
    ngx_table_elt_t  *h;

    if (value->len) {
        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        h->hash = 1;
        h->key = *key;
        h->value = *value;
    }

    return NGX_OK;
}


static ngx_int_t 
ngx_http_cross_origin_search_string(ngx_str_t *string_array, ngx_str_t *name, 
        ngx_flag_t case_insensitive)
{
    ngx_str_t *s;

    if (string_array == NULL || name == NULL || name->len == 0) {
        return 0;
    }

    s = string_array;
    while (s->len) {

        if (!case_insensitive && s->len == name->len
                && ngx_strncmp(s->data, name->data, name->len) == 0)
        {
            return 1;
        }

        if (case_insensitive && s->len == name->len
                && ngx_strncasecmp(s->data, name->data, name->len) == 0)
        {
            return 1;
        }

        s++;
    }

    return 0;
}


static ngx_str_t *
ngx_http_cross_origin_concatenate_list_value(ngx_http_request_t *r, 
        ngx_array_t *arr)
{
    size_t                       len;
    u_char                      *last, *end;
    ngx_str_t                   *s;
    ngx_uint_t                   i;
    ngx_http_cross_origin_val_t *elt;

    if (arr == NULL) {
        return NULL;
    }

    elt = arr->elts;

    if (arr->nelts == 1) {
        return &elt->value;
    }

    len = 0;
    for (i = 0; i < arr->nelts; i++) {
        if (i == arr->nelts - 1) {
            len += elt[i].value.len;
            break;
        }

        len += elt[i].value.len + 1 + 1; /*GET, */
    }

    s = ngx_palloc(r->pool, sizeof(ngx_str_t));
    if (s == NULL) {
        return NULL;
    }

    s->data = ngx_palloc(r->pool, len);
    if (s->data == NULL) {
        return NULL;
    }

    last = s->data;
    end = s->data + len;

    for (i = 0; i < arr->nelts; i++) {

        if (i == arr->nelts - 1) {
            /* last element */
            last = ngx_snprintf(last, end - last, "%V", &elt[i].value);
            break;
        }

        last = ngx_snprintf(last, end - last, "%V, ", &elt[i].value);
    }

    s->len = last - s->data;

    return s;
}


static ngx_array_t *
ngx_http_cross_origin_split_string(ngx_http_request_t *r, ngx_str_t *str, 
        u_char separator)
{
    u_char                      *pre, *p, *last;
    ngx_str_t                   *ts;
    ngx_array_t                 *arr;

    arr = NULL;
    last = str->data + str->len;
    pre = p = str->data;

    while(p < last) {

        p = ngx_strlchr(p, last, separator);
        if (p == NULL) {
            break;
        }

        if (arr == NULL) {
            arr = ngx_array_create(r->pool, 4, sizeof(ngx_str_t));
            if (arr == NULL) {
                return NULL;
            }
        }

        ts = ngx_array_push(arr);
        if (ts == NULL) {
            return NULL;
        }

        ts->data = pre;
        ts->len = p - pre;

        p++;

        pre = p;
    }

    return arr;
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
     *     conf->expose_header_list  = NULL;
     *     conf->preflight_response_type  = {0, NULL};
     *     conf->preflight_response  = ALL NULL;
     *
     */

    conf->enable             = NGX_CONF_UNSET;
    conf->origin_unbounded   = NGX_CONF_UNSET;
    conf->method_unbounded   = NGX_CONF_UNSET;
    conf->header_unbounded   = NGX_CONF_UNSET;
    conf->support_credential = NGX_CONF_UNSET;
    conf->max_age            = NGX_CONF_UNSET;

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

    if (conf->method_list == NULL) {
        conf->method_list = prev->method_list;
    }

    if (conf->header_list == NULL) {
        conf->header_list = prev->header_list;
    }

    if (conf->expose_header_list == NULL) {
        conf->expose_header_list = prev->expose_header_list;
    }

    if (conf->preflight_response.value.len == 0) {
        conf->preflight_response = prev->preflight_response;
    }

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->origin_unbounded, prev->origin_unbounded, 0);
    ngx_conf_merge_value(conf->method_unbounded, prev->method_unbounded, 0);
    ngx_conf_merge_value(conf->header_unbounded, prev->header_unbounded, 0);
    ngx_conf_merge_value(conf->support_credential, prev->support_credential, 0);
    ngx_conf_merge_sec_value(conf->max_age, prev->max_age, 0);
    ngx_conf_merge_str_value(conf->preflight_response_type, 
            prev->preflight_response_type, DEFAULT_RESPONSE_CONTENT_TYPE);

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
    ngx_http_cross_origin_loc_conf_t  *colcf = conf;

    ngx_str_t                         *value;
    ngx_uint_t                         i;
    ngx_http_cross_origin_val_t       *cov;

    value = cf->args->elts;

    if (colcf->origin_list == NULL) {
        colcf->origin_list = ngx_array_create(cf->pool, 4,
                                        sizeof(ngx_http_cross_origin_val_t));
        if (colcf->origin_list == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "unbounded") == 0) {
            colcf->origin_unbounded = 1;
            break;
        }

        cov = ngx_array_push(colcf->origin_list);
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
    ngx_http_cross_origin_loc_conf_t  *colcf = conf;

    ngx_str_t                         *value;
    ngx_uint_t                         i;
    ngx_http_cross_origin_val_t       *cov;

    value = cf->args->elts;

    if (colcf->method_list == NULL) {
        colcf->method_list = ngx_array_create(cf->pool, 4,
                                        sizeof(ngx_http_cross_origin_val_t));
        if (colcf->method_list == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "unbounded") == 0) {
            colcf->method_unbounded = 1;
            break;
        }

        cov = ngx_array_push(colcf->method_list);
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
    ngx_http_cross_origin_loc_conf_t  *colcf = conf;

    ngx_str_t                         *value;
    ngx_uint_t                         i;
    ngx_http_cross_origin_val_t       *cov;

    value = cf->args->elts;

    if (colcf->header_list == NULL) {
        colcf->header_list = ngx_array_create(cf->pool, 4,
                                        sizeof(ngx_http_cross_origin_val_t));
        if (colcf->header_list == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "unbounded") == 0) {
            colcf->header_unbounded = 1;
            break;
        }

        cov = ngx_array_push(colcf->header_list);
        if (cov == NULL) {
            return NGX_CONF_ERROR;
        }

        cov->hash = ngx_hash_key_lc(value[i].data, value[i].len);
        cov->value = value[i];
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_cors_expose_header_list(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cross_origin_loc_conf_t  *colcf = conf;

    ngx_str_t                         *value;
    ngx_uint_t                         i;
    ngx_http_cross_origin_val_t       *cov;

    value = cf->args->elts;

    if (colcf->expose_header_list == NULL) {
        colcf->expose_header_list = ngx_array_create(cf->pool, 4,
                                        sizeof(ngx_http_cross_origin_val_t));
        if (colcf->expose_header_list == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_http_cross_origin_search_string(simple_response_headers, 
                    &value[i], 1)) {
            continue;
        }

        cov = ngx_array_push(colcf->expose_header_list);
        if (cov == NULL) {
            return NGX_CONF_ERROR;
        }

        cov->hash = ngx_hash_key_lc(value[i].data, value[i].len);
        cov->value = value[i];
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_cors_preflight_response(ngx_conf_t *cf, ngx_command_t *cmd, 
        void *conf)
{
    ngx_http_cross_origin_loc_conf_t  *colcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    if (colcf->preflight_response.value.len != 0) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &colcf->preflight_response;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
