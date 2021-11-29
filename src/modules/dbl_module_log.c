#include "dbl_module.h"

struct dbl_module_log_config {
    char                           *error;
    FILE                           *ferror;

    char                           *access;
    FILE                           *faccess;
};

struct dbl_module_log_ctx {
    struct dbl_module_log_config    config;
    struct dbl_log                  log_error;
    struct dbl_log                  log_access;
};

const struct dbl_yamlmapper_command dbl_module_log_map_config_field_commands[] = {
    {
        "error",
        offsetof(struct dbl_module_log_config, error),
        0,
        1,
        NULL,
        dbl_yamlmapper_set_string_ptr
    },        
    {
        "access",
        offsetof(struct dbl_module_log_config, access),
        0,
        0,
        NULL,
        dbl_yamlmapper_set_string_ptr
    },        
    DBL_YAML_MAPPER_NULL_CMD
};

const struct dbl_yamlmapper_command dbl_module_log_map_config_command = {
    "log",
    0,
    0,
    1,
    dbl_module_log_map_config_field_commands,
    dbl_yamlmapper_set_struct
};

static int dbl_module_log_init_(struct dbl_eventloop *evloop, struct dbl_yamlmapper *yamldoc);
static void dbl_module_log_delete_(struct dbl_eventloop *evloop);
static int dbl_module_log_init_config_(struct dbl_module_log_ctx *mctx, struct dbl_eventloop *evloop, struct dbl_yamlmapper *yamldoc); 
static void dbl_module_log_delete_config_(struct dbl_module_log_ctx *mctx);

struct dbl_module dbl_module_log = {
    "log",
    DBL_MODULE_UNSET_INDEX,
    dbl_module_log_init_,
    dbl_module_log_delete_,
    NULL 
};

static int dbl_module_log_init_(struct dbl_eventloop *evloop, struct dbl_yamlmapper *yamldoc) {
    struct dbl_module_log_ctx *mctx;
    struct dbl_module_log_config *config;

    mctx = dbl_pool_alloc(evloop->pool, sizeof(struct dbl_module_log_ctx));
    if (mctx == NULL)
        return -1;

    if (dbl_module_log_init_config_(mctx, evloop, yamldoc) == -1)
        return -1;
    
    config = &mctx->config;
    mctx->log_error.file = config->ferror;
    mctx->log_error.log_level = DBL_LOG_ERROR;
    evloop->newlog = &mctx->log_error;
    if (config->faccess) {
        mctx->log_access.file = config->faccess;
        mctx->log_access.log_level = DBL_LOG_INFO;
        evloop->accesslog = &mctx->log_access;
    }
    dbl_eventloop_set_module_ctx(evloop, dbl_module_log, mctx);
    return 0;
}

static void dbl_module_log_delete_(struct dbl_eventloop *evloop) {
    struct dbl_module_log_ctx *mctx;

    mctx = dbl_eventloop_get_module_ctx(evloop, dbl_module_log);
    dbl_module_log_delete_config_(mctx);
}

static int dbl_module_log_init_config_(struct dbl_module_log_ctx *mctx, struct dbl_eventloop *evloop, struct dbl_yamlmapper *yamldoc) {
    struct dbl_module_log_config *config;
    
    config = &mctx->config;
    memset(config, 0, sizeof(struct dbl_module_log_config));
    if (dbl_yamlmapper_map(yamldoc, evloop->pool, &dbl_module_log_map_config_command, NULL, config) == -1)
        goto error;

    /* error log is required */
    assert(config->error != NULL);
    config->ferror = fopen(config->error, "a");
    if (config->ferror == NULL) {
        dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "open error log file '%s' failed", config->error);
        goto error;
    }
    
    /* access log is optional */
    if (config->access) {
        config->faccess = fopen(config->access, "a");
        if (config->faccess == NULL) {
            dbl_log_error(DBL_LOG_ERROR, evloop->log, errno, "open access log file '%s' failed", config->access);
            goto error;
        }
    }

    return 0;

error:
    if (config->ferror)
        fclose(config->ferror);
    if (config->faccess)
        fclose(config->faccess);
    return -1;

}

static void dbl_module_log_delete_config_(struct dbl_module_log_ctx *mctx) {
    struct dbl_module_log_config *config;

    config = &mctx->config;
    fclose(config->ferror);
    if (config->faccess)
        fclose(config->faccess);
}
