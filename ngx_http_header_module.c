#include <ngx_http.h>

ngx_module_t ngx_http_header_module;

static ngx_int_t ngx_http_header_join_var(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_array_t *a = (ngx_array_t *)data;
    ngx_str_t *elts = a->elts;
    v->len = 0;
    ngx_flag_t f = 0;
    for (ngx_list_part_t *part = &r->headers_in.headers.part; part; part = part->next) {
        ngx_table_elt_t *header = part->elts;
        for (ngx_uint_t i = 0; i < part->nelts; i++) {
//            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "header[%i] = %V:%V", i, &header[i].key, &header[i].value);
            for (ngx_uint_t j = 0; j < a->nelts; j++) {
                if (elts[j].len == header[i].key.len && !ngx_strncasecmp(elts[j].data, header[i].key.data, header[i].key.len)) {
                    if (f) v->len += sizeof("\n") - 1;
                    v->len += header[i].key.len + sizeof(": ") - 1 + header[i].value.len;
                    f = 1;
                }
            }
        }
    }
    if (!(v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "header: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    u_char *p = v->data;
    f = 0;
    for (ngx_list_part_t *part = &r->headers_in.headers.part; part; part = part->next) {
        ngx_table_elt_t *header = part->elts;
        for (ngx_uint_t i = 0; i < part->nelts; i++) {
//            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "header[%i] = %V:%V", i, &header[i].key, &header[i].value);
            for (ngx_uint_t j = 0; j < a->nelts; j++) {
                if (elts[j].len == header[i].key.len && !ngx_strncasecmp(elts[j].data, header[i].key.data, header[i].key.len)) {
                    if (f) *p++ = '\n';
                    p = ngx_copy(p, header[i].key.data, header[i].key.len);
                    *p++ = ':';
                    *p++ = ' ';
                    p = ngx_copy(p, header[i].value.data, header[i].value.len);
                    f = 1;
                }
            }
        }
    }
    if (v->len != p - v->data) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "header: %s:%d", __FILE__, __LINE__); return NGX_ERROR; }
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static char *ngx_http_header_join_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *elts = cf->args->elts;
    if (elts[1].data[0] != '$') { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid variable name \"%V\"", &elts[1]); return NGX_CONF_ERROR; }
    elts[1].len--;
    elts[1].data++;
    ngx_http_variable_t *v = ngx_http_add_variable(cf, &elts[1], NGX_HTTP_VAR_CHANGEABLE);
    if (!v) return NGX_CONF_ERROR;
    v->get_handler = ngx_http_header_join_var;
    ngx_array_t *a = ngx_array_create(cf->pool, cf->args->nelts - 2, sizeof(ngx_str_t));
    if (!a) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "header: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
        ngx_str_t *s = ngx_array_push(a);
        if (!s) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "header: %s:%d", __FILE__, __LINE__); return NGX_CONF_ERROR; }
        *s = elts[i];
    }
    v->data = (uintptr_t)a;
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_header_commands[] = {
  { .name = ngx_string("header_join"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_2MORE,
    .set = ngx_http_header_join_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_header_module_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = NULL,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = NULL,
    .merge_srv_conf = NULL,
    .create_loc_conf = NULL,
    .merge_loc_conf = NULL
};

ngx_module_t ngx_http_header_module = {
    NGX_MODULE_V1,
    .ctx = &ngx_http_header_module_ctx,
    .commands = ngx_http_header_commands,
    .type = NGX_HTTP_MODULE,
    .init_master = NULL,
    .init_module = NULL,
    .init_process = NULL,
    .init_thread = NULL,
    .exit_thread = NULL,
    .exit_process = NULL,
    .exit_master = NULL,
    NGX_MODULE_V1_PADDING
};
