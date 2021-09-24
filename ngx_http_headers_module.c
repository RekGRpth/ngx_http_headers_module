#include <ngx_http.h>

typedef struct {
    ngx_uint_t header;
    ngx_str_t key;
    ngx_http_complex_value_t value;
} ngx_http_headers_location_t;

typedef struct {
    ngx_flag_t enable;
} ngx_http_headers_main_t;

ngx_module_t ngx_http_headers_module;

static ngx_int_t ngx_http_headers_save_func(ngx_http_request_t *r, ngx_str_t *val, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_array_t *a = (ngx_array_t *)data;
    ngx_str_t *elts = a->elts;
    val->len = 0;
    for (ngx_list_part_t *part = &r->headers_in.headers.part; part; part = part->next) {
        ngx_table_elt_t *header = part->elts;
        for (ngx_uint_t i = 0; i < part->nelts; i++) {
            for (ngx_uint_t j = 0; j < a->nelts; j++) {
                if (header[i].value.len && (elts[j].len == header[i].key.len || elts[j].data[elts[j].len - 1] == '*') && !ngx_strncasecmp(elts[j].data, header[i].key.data, elts[j].data[elts[j].len - 1] == '*' ? elts[j].len - 1: elts[j].len)) {
                    val->len += sizeof(size_t) + header[i].key.len + sizeof(size_t) + header[i].value.len;
                }
            }
        }
    }
    if (!(val->data = ngx_pnalloc(r->pool, val->len))) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_pnalloc"); return NGX_ERROR; }
    u_char *p = val->data;
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
    if (p != val->data + val->len) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "p != val->data + val->len"); return NGX_ERROR; }
    return NGX_OK;
}

static char *ngx_http_headers_save_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *elts = cf->args->elts;
    ngx_array_t *data = ngx_array_create(cf->pool, cf->args->nelts - 2, sizeof(*elts));
    if (!data) return "!ngx_array_create";
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
        ngx_str_t *str = ngx_array_push(data);
        if (!str) return "!ngx_array_push";
        *str = elts[i];
    }
    ndk_set_var_t filter = {NDK_SET_VAR_DATA, ngx_http_headers_save_func, 0, data};
    return ndk_set_var_core(cf, &elts[1], &filter);
}

static char *ngx_http_headers_load_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t *elts = cf->args->elts;
    if (elts[1].data[0] != '$') return "invalid variable name";
    elts[1].len--;
    elts[1].data++;
    ngx_int_t index = ngx_http_get_variable_index(cf, &elts[1]);
    if (index == NGX_ERROR) return "invalid variable";
    ngx_http_headers_location_t *location = conf;
    location->header = (ngx_uint_t) index;
    if (cf->args->nelts <= 2) return NGX_CONF_OK;
    location->key = elts[2];
    ngx_http_compile_complex_value_t ccv;
    ngx_memzero(&ccv, sizeof(ccv));
    ccv.cf = cf;
    ccv.value = &elts[3];
    ccv.complex_value = &location->value;
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) return "ngx_http_compile_complex_value != NGX_OK";
    ngx_http_headers_main_t *main = ngx_http_conf_get_module_main_conf(cf, ngx_http_headers_module);
    main->enable = 1;
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
    .type = NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1|NGX_CONF_TAKE3,
    .set = ngx_http_headers_load_conf,
    .conf = NGX_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
    ngx_null_command
};

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_int_t ngx_http_headers_filter(ngx_http_request_t *r) {
    ngx_http_headers_location_t *location = ngx_http_get_module_loc_conf(r, ngx_http_headers_module);
    if (!location->header) return ngx_http_next_header_filter(r);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_variable_value_t *header = ngx_http_get_indexed_variable(r, location->header);
    if (!header || !header->data || !header->len) return ngx_http_next_header_filter(r);
    ngx_int_t rc = location->key.len ? NGX_HTTP_FORBIDDEN : NGX_OK;
    for (u_char *p = header->data; p < header->data + header->len - sizeof(size_t); ) {
        size_t len = ((*(size_t *)p) << 48) >> 48;
        p += sizeof(size_t);
        ngx_str_t key = {len, p};
        if ((p += len) >= header->data + header->len - sizeof(size_t)) break;
        len = ((*(size_t *)p) << 48) >> 48;
        p += sizeof(size_t);
        ngx_str_t value = {len, p};
        p += len;
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "header = %V:%V", &key, &value);
        ngx_table_elt_t *table_elt = ngx_list_push(&r->headers_in.headers);
        if (!table_elt) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "!ngx_list_push"); return NGX_ERROR; }
        table_elt->key = key;
        table_elt->value = value;
        table_elt->hash = 1;
        if (key.len == sizeof("Authorization") - 1 && !ngx_strncasecmp(key.data, (u_char *)"Authorization", sizeof("Authorization") - 1)) r->headers_in.authorization = table_elt;
        if (location->key.len && location->key.len == key.len && !ngx_strncasecmp(location->key.data, key.data, key.len)) {
            ngx_str_t v;
            if (ngx_http_complex_value(r, &location->value, &v) != NGX_OK) { ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_complex_value != NGX_OK"); return NGX_ERROR; }
            if (v.len == value.len && !ngx_strncasecmp(value.data, v.data, v.len)) rc = NGX_OK;
        }
    }
    if (rc != NGX_OK) r->headers_out.status = NGX_HTTP_FORBIDDEN;
    return ngx_http_next_header_filter(r);
}

static ngx_int_t ngx_http_headers_postconfiguration(ngx_conf_t *cf) {
    ngx_http_headers_main_t *main = ngx_http_conf_get_module_main_conf(cf, ngx_http_headers_module);
    if (!main->enable) return NGX_OK;
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_headers_filter;
    return NGX_OK;
}

static void *ngx_http_headers_create_main_conf(ngx_conf_t *cf) {
    ngx_http_headers_main_t *main = ngx_pcalloc(cf->pool, sizeof(*main));
    if (!main) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pcalloc"); return NULL; }
    return main;
}

static void *ngx_http_headers_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_headers_location_t *location = ngx_pcalloc(cf->pool, sizeof(*location));
    if (!location) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "!ngx_pcalloc"); return NULL; }
    return location;
}

static char *ngx_http_headers_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_headers_location_t *prev = parent;
    ngx_http_headers_location_t *conf = child;
    ngx_conf_merge_uint_value(conf->header, prev->header, 0);
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_headers_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = ngx_http_headers_postconfiguration,
    .create_main_conf = ngx_http_headers_create_main_conf,
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
