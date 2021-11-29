#ifndef __DBL_MODULE_H
#define __DBL_MODULE_H

#include "dbl_eventloop.h"
#include "dbl_yamlmapper.h"

#define DBL_MODULE_UNSET_INDEX  -1

struct dbl_module {
    const char     *name;
    int             index;

    /* Initialize a module for eventloop */
    int           (*init)(struct dbl_eventloop *evloop, struct dbl_yamlmapper *yamldoc);

    /* Delete a module from eventloop */
    void          (*delete)(struct dbl_eventloop *evloop);

    /* A callback invoked before the the eventloop running */
    void          (*before_running)(struct dbl_eventloop *evloop);
};

extern struct dbl_module *dbl_modules[];
extern int dbl_max_modules;
extern struct dbl_module dbl_module_http;
extern struct dbl_module dbl_module_log;
extern struct dbl_module dbl_module_signal;

void dbl_register_all_modules();

#endif
