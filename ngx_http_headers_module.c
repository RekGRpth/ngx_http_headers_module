#include <ngx_http.h>

typedef struct {
    ngx_uint_t header;
} ngx_http_headers_location_conf_t;

ngx_module_t ngx_http_headers_module;

static ngx_int_t ngx_http_headers_save_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_array_t *a = (ngx_array_t *)data;
    ngx_str_t *elts = a->elts;
    v->len = 0;
    for (ngx_list_part_t *part = &r->headers_in.headers.part; part; part = part->next) {
        ngx_table_elt_t *header = part->elts;
        for (ngx_uint_t i = 0; i < part->nelts; i++) {
            for (ngx_uint_t j = 0; j < a->nelts; j++) {
                if (header[i].value.len && (elts[j].len == header[i].key.len || elts[j].data[elts[j].len - 1] == '*') && !ngx_strncasecmp(elts[j].data, header[i].key.data, elts[j].data[elts[j].len - 1] == '*' ? elts[j].len - 1: elts[j].len)) {
                    v->len += sizeof(size_t) + header[i].key.len + sizeof(size_t) + header[i].value.len;
                }
            }
        }
    }
    if (!(v->data = ngx_pnalloc(r->pool, v->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    u_char *p = v->data;
    for (ngx_list_part_t *part = &r->headers_in.headers.part; part; part = part->next) {
        ngx_table_elt_t *header = part->elts;
        for (ngx_uint_t i = 0; i < part->nelts; i++) {
            for (ngx_uint_t j = 0; j < a->nelts; j++) {
                if (header[i].value.len && (elts[j].len == header[i].key.len || elts[j].data[elts[j].len - 1] == '*') && !ngx_strncasecmp(elts[j].data, header[i].key.data, elts[j].data[elts[j].len - 1] == '*' ? elts[j].len - 1: elts[j].len)) {
                    *(size_t *)p = header[i].key.len;
                    p = ngx_copy(p + sizeof(size_t), header[i].key.data, header[i].key.len);
                    *(size_t *)p = header[i].value.len;
                    p = ngx_copy(p + sizeof(size_t), header[i].value.data, header[i].value.len);
                    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "header[%d] = %V:%V", i, &header[i].key, &header[i].value);
                }
            }
        }
    }
    if (v->len != p - v->data) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "v->len != p - v->data"); return NGX_ERROR; }
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    return NGX_OK;
}

static char *ngx_http_headers_save_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *elts = cf->args->elts;
    if (elts[1].data[0] != '$') { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "header: invalid variable name \"%V\"", &elts[1]); return NGX_CONF_ERROR; }
    elts[1].len--;
    elts[1].data++;
    ngx_http_variable_t *v = ngx_http_add_variable(cf, &elts[1], NGX_HTTP_VAR_CHANGEABLE);
    if (!v) return NGX_CONF_ERROR;
    v->get_handler = ngx_http_headers_save_get_handler;
    ngx_array_t *a = ngx_array_create(cf->pool, cf->args->nelts - 2, sizeof(ngx_str_t));
    if (!a) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_array_create"); return NGX_CONF_ERROR; }
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
        ngx_str_t *s = ngx_array_push(a);
        if (!s) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_array_push"); return NGX_CONF_ERROR; }
        *s = elts[i];
    }
    v->data = (uintptr_t)a;
    return NGX_CONF_OK;
}

static char *ngx_http_headers_load_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *elts = cf->args->elts;
    if (elts[1].data[0] != '$') { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "header: invalid variable name \"%V\"", &elts[1]); return NGX_CONF_ERROR; }
    elts[1].len--;
    elts[1].data++;
    ngx_int_t index = ngx_http_get_variable_index(cf, &elts[1]);
    if (index == NGX_ERROR) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "header: invalid variable \"%V\"", &elts[1]); return NGX_CONF_ERROR; }
    ngx_http_headers_location_conf_t *location_conf = conf;
    location_conf->header = (ngx_uint_t) index;
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_headers_commands[] = {
  { .name = ngx_string("headers_save"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_2MORE,
    .set = ngx_http_headers_save_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = ngx_string("headers_load"),
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
    .set = ngx_http_headers_load_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
    ngx_null_command
};

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_int_t ngx_http_headers_filter(ngx_http_request_t *r) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_headers_location_conf_t *location_conf = ngx_http_get_module_loc_conf(r, ngx_http_headers_module);
    if (!location_conf->header) return ngx_http_next_header_filter(r);
    ngx_http_variable_value_t *header = ngx_http_get_indexed_variable(r, location_conf->header);
    if (!header || !header->data || !header->len) return ngx_http_next_header_filter(r);
    for (u_char *p = header->data; p < header->data + header->len - sizeof(size_t); ) {
        size_t len = *(size_t *)p;
        p += sizeof(size_t);
        ngx_str_t key = {len, p};
        if ((p += len) >= header->data + header->len - sizeof(size_t)) break;
        len = *(size_t *)p;
        p += sizeof(size_t);
        ngx_str_t value = {len, p};
        p += len;
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "header = %V:%V", &key, &value);
        ngx_table_elt_t *table_elt = ngx_list_push(&r->headers_in.headers);
        if (!table_elt) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_list_push"); return NGX_ERROR; }
        table_elt->key = key;
        table_elt->value = value;
        if (key.len == sizeof("Authorization") - 1 && !ngx_strncasecmp(key.data, (u_char *)"Authorization", sizeof("Authorization") - 1)) r->headers_in.authorization = table_elt;
    }
    return ngx_http_next_header_filter(r);
}

static ngx_int_t ngx_http_headers_postconfiguration(ngx_conf_t *cf) {
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_headers_filter;
    return NGX_OK;
}

static void *ngx_http_headers_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_headers_location_conf_t *location_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_headers_location_conf_t));
    if (!location_conf) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pcalloc"); return NULL; }
    return location_conf;
}

static char *ngx_http_headers_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_headers_location_conf_t *prev = parent;
    ngx_http_headers_location_conf_t *conf = child;
    ngx_conf_merge_uint_value(conf->header, prev->header, 0);
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_headers_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = ngx_http_headers_postconfiguration,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = NULL,
    .merge_srv_conf = NULL,
    .create_loc_conf = ngx_http_headers_create_loc_conf,
    .merge_loc_conf = ngx_http_headers_merge_loc_conf
};

ngx_module_t ngx_http_headers_module = {
    NGX_MODULE_V1,
    .ctx = &ngx_http_headers_ctx,
    .commands = ngx_http_headers_commands,
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
