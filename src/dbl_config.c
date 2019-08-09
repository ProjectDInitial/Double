#include "dbl_config.h"
#include "dbl_log.h"

#include <cyaml/cyaml.h>
#include <errno.h>

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

static const cyaml_schema_field_t config_http_fields_schema[] = {
    CYAML_FIELD_UINT("port", CYAML_FLAG_DEFAULT,
            struct dbl_config_http, port),
    CYAML_FIELD_INT("timeout", CYAML_FLAG_DEFAULT,
            struct dbl_config_http, timeout),
    CYAML_FIELD_STRING_PTR("access_log", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL,
            struct dbl_config_http, access_log_path, 1, 1024),
    CYAML_FIELD_INT("maxheadersize", CYAML_FLAG_DEFAULT,
            struct dbl_config_http, maxheadersize),
    CYAML_FIELD_INT("maxbodysize", CYAML_FLAG_DEFAULT,
            struct dbl_config_http, maxbodysize),
    CYAML_FIELD_MAPPING_PTR("tcp", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL,
            struct dbl_config_http, tcp, config_http_tcp_fields_schema),
    CYAML_FIELD_MAPPING_PTR("ssl", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL,
            struct dbl_config_http, ssl, config_http_ssl_fields_schema),
    CYAML_FIELD_SEQUENCE("partners", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL,
            struct dbl_config_http, partners, &config_http_partner_array_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END
};

static const cyaml_schema_field_t config_fields_schema[] = {
    CYAML_FIELD_STRING_PTR("error_log", CYAML_FLAG_POINTER,
            struct dbl_config, error_log_path, 1, 1024),
    CYAML_FIELD_MAPPING_PTR("http", CYAML_FLAG_POINTER,
            struct dbl_config, http, config_http_fields_schema),
    CYAML_FIELD_END
};

static const cyaml_schema_value_t config_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER,
            struct dbl_config, config_fields_schema),
};

static void dbl_config_parse_yaml_error_log_(cyaml_log_t level, void *ctx, const char *fmt, va_list args) {
    char **rang = ctx;

    int n = vsnprintf(rang[0], rang[1] - rang[0], fmt, args);

    rang[0] += n;
}

struct dbl_config *dbl_config_parse_file(const char *filepath) {
    struct dbl_config *conf;

    char errstrbuf[1024];
    char *rang[] = {errstrbuf, errstrbuf + 1024};

    const cyaml_config_t cyaml_parse_config = {
        .mem_fn = cyaml_mem,         
        .log_level = CYAML_LOG_ERROR, 
        .log_fn = dbl_config_parse_yaml_error_log_,
        .log_ctx = rang,
    };

    int err = cyaml_load_file(filepath, &cyaml_parse_config, &config_schema, (void **)&conf, NULL);
    if (err != CYAML_OK) {
        dbl_log_writestd(DBL_LOG_ERROR, 0, "parse config file '%s' failed ('%s').\n%s", filepath, cyaml_strerror(err), errstrbuf);
        return NULL;
    }
    return conf;
}

void dbl_config_free(struct dbl_config *conf) {
    const cyaml_config_t cyaml_parse_config = {
        .mem_fn = cyaml_mem,         
    };

    cyaml_free(&cyaml_parse_config, &config_schema, conf, 0);
}
