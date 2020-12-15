#include "dbl_config.h"
#include "dbl_log.h"

#include <cyaml/cyaml.h>

static const cyaml_schema_field_t config_http_ssl_fields_schema[] = {
    CYAML_FIELD_STRING_PTR("certificate", CYAML_FLAG_POINTER,
            struct dbl_config_http_ssl, certificate, 0, 1024), 
    CYAML_FIELD_STRING_PTR("privatekey", CYAML_FLAG_POINTER,
            struct dbl_config_http_ssl, privatekey, 0, 1024), 
    CYAML_FIELD_END
};

static const cyaml_schema_field_t config_http_tcp_fields_schema[] = {
    CYAML_FIELD_UINT_PTR("keepalive_time", CYAML_FLAG_DEFAULT|CYAML_FLAG_OPTIONAL,
            struct dbl_config_http_tcp, keepalive_time),
    CYAML_FIELD_UINT_PTR("keepalive_intvl", CYAML_FLAG_DEFAULT|CYAML_FLAG_OPTIONAL,
            struct dbl_config_http_tcp, keepalive_intvl),
    CYAML_FIELD_UINT_PTR("keepalive_probes", CYAML_FLAG_DEFAULT|CYAML_FLAG_OPTIONAL,
            struct dbl_config_http_tcp, keepalive_probes),
    CYAML_FIELD_BOOL_PTR("nodelay", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL,
            struct dbl_config_http_tcp, nodelay),
    CYAML_FIELD_END
};

static const cyaml_schema_value_t string_ptr_schema = {
    CYAML_VALUE_STRING(CYAML_FLAG_POINTER, char, 1, CYAML_UNLIMITED)
};

static const cyaml_schema_field_t config_http_cors_fields_schema[] = {
    CYAML_FIELD_SEQUENCE_COUNT("origins", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL,
            struct dbl_config_http_cors, origins, origins_count, &string_ptr_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t config_http_partner_fields_schema[] = {
    CYAML_FIELD_STRING_PTR("id", CYAML_FLAG_POINTER,
            struct dbl_config_http_partner, id, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("secret", CYAML_FLAG_POINTER,
            struct dbl_config_http_partner, secret, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END
};

static const cyaml_schema_value_t config_http_partner_array_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT,
            struct dbl_config_http_partner, config_http_partner_fields_schema),
};

static const cyaml_schema_field_t config_http_fields_schema[] = {
    CYAML_FIELD_UINT("port", CYAML_FLAG_DEFAULT,
            struct dbl_config_http, port),
    CYAML_FIELD_INT("timeout", CYAML_FLAG_DEFAULT,
            struct dbl_config_http, timeout),
    CYAML_FIELD_STRING_PTR("access_log", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL,
            struct dbl_config_http, access_log_path, 0, CYAML_UNLIMITED),
    CYAML_FIELD_INT("maxheadersize", CYAML_FLAG_DEFAULT,
            struct dbl_config_http, maxheadersize),
    CYAML_FIELD_INT("maxbodysize", CYAML_FLAG_DEFAULT,
            struct dbl_config_http, maxbodysize),
    CYAML_FIELD_MAPPING_PTR("ssl", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL,
            struct dbl_config_http, ssl, config_http_ssl_fields_schema),
    CYAML_FIELD_MAPPING_PTR("tcp", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL,
            struct dbl_config_http, tcp, config_http_tcp_fields_schema),
    CYAML_FIELD_MAPPING_PTR("cors", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL,
            struct dbl_config_http, cors, config_http_cors_fields_schema),
    CYAML_FIELD_SEQUENCE("partners", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL,
            struct dbl_config_http, partners, &config_http_partner_array_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t config_fields_schema[] = {
    CYAML_FIELD_STRING_PTR("error_log", CYAML_FLAG_POINTER,
            struct dbl_config, error_log_path, 0, CYAML_UNLIMITED),
    CYAML_FIELD_MAPPING_PTR("http", CYAML_FLAG_POINTER,
            struct dbl_config, http, config_http_fields_schema),
    CYAML_FIELD_END
};

static const cyaml_schema_value_t config_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER,
            struct dbl_config, config_fields_schema),
};

static void dbl_config_parse_yaml_error_log_(cyaml_log_t level, void *ctx, const char *fmt, va_list args) {
    dbl_log_vwritestd(level == CYAML_LOG_ERROR? DBL_LOG_ERROR: DBL_LOG_DEBUG, 0, fmt, args);
}

const cyaml_config_t config = {
    .mem_fn = cyaml_mem,
    .log_level = CYAML_LOG_ERROR,
    .log_fn = dbl_config_parse_yaml_error_log_,
};

struct dbl_config *dbl_config_parse_file(const char *filepath) {
    struct dbl_config *result;

    int err = cyaml_load_file(filepath, &config, &config_schema, (void **)&result, NULL);
    if (err != CYAML_OK) {
        dbl_log_writestd(DBL_LOG_ERROR, 0, "parse configuration file failed '%s' (%s)", filepath, cyaml_strerror(err));
        return NULL;
    }
    return result;
}

void dbl_config_free(struct dbl_config *conf) {
    cyaml_free(&config, &config_schema, conf, 0);
}
