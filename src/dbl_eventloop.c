#include "dbl_eventloop.h"
#include "dbl_module.h"

static int dbl_eventloop_add_all_modules_(struct dbl_eventloop *evloop, struct dbl_yamlmapper *yamldoc); 
static void dbl_eventloop_remove_all_modules_(struct dbl_eventloop *evloop);

static int dbl_eventloop_add_all_modules_(struct dbl_eventloop *evloop, struct dbl_yamlmapper *yamldoc) {
    const struct dbl_module *module;
    int nloaded = 0;

    evloop->module_ctx = dbl_pool_alloc(evloop->pool, dbl_max_modules * sizeof(void *));
    if (evloop->module_ctx == NULL)
        goto error;
    memset(evloop->module_ctx, 0,  dbl_max_modules * sizeof(void *));

    while (nloaded < dbl_max_modules) {
        module = dbl_modules[nloaded];
        if (module->init(evloop, yamldoc) == -1) {
            dbl_log_error(DBL_LOG_ERROR, evloop->log, 0, "module '%s' initialize failed", module->name);
            goto error;
        }
        nloaded++;
    }

    return 0;

error:
    while (nloaded > 0) {
        module = dbl_modules[--nloaded];
        if (module->delete)
            module->delete(evloop);
    }    
    return -1; 
}

static void dbl_eventloop_remove_all_modules_(struct dbl_eventloop *evloop) {
    const struct dbl_module *module;

    for (int i = 0; i < dbl_max_modules; i++) {
        module = dbl_modules[i];
        if (module->delete) 
            module->delete(evloop); 
    }
}

int dbl_init_eventloop(struct dbl_eventloop *evloop, const char *confpath, struct dbl_log *log) {
    const struct dbl_module *module;
    struct dbl_yamlmapper mapper;
    struct event_base *evbase;
    struct dbl_pool *pool;
    int res;

    evbase = NULL;
    pool = NULL;
    res = 0;
    
    memset(evloop, 0, sizeof(struct dbl_eventloop));

    /* Initialize a yaml mapper for load configuration from file */
    dbl_yamlmapper_init(&mapper, log);
    if (dbl_yamlmapper_load(&mapper, confpath) == -1)
        goto error;

    pool = dbl_pool_new(log);
    if (pool == NULL)
        goto error;

    evbase = event_base_new();
    if (evbase == NULL)
        goto error;

    evloop->evbase = evbase;
    evloop->pool = pool;
    evloop->log = log;

    if (dbl_eventloop_add_all_modules_(evloop, &mapper) == -1)
        goto error;
    
    evloop->log = evloop->newlog;
    for (int i = 0; i < dbl_max_modules; i++) {
        module = dbl_modules[i];
        if (module->before_running)
            module->before_running(evloop);
    }

    goto done;

error:
    if (pool)
        dbl_pool_free(pool);
    if (evbase)
        event_base_free(evbase);
    res = -1;

done:
    dbl_yamlmapper_delete(&mapper);
    return res;
}

void dbl_release_eventloop(struct dbl_eventloop *evloop) {
    dbl_eventloop_remove_all_modules_(evloop);
    event_base_free(evloop->evbase);
    dbl_pool_free(evloop->pool);
}
