#include "dbl_module.h"

struct dbl_module *dbl_modules[] = {
    &dbl_module_log,
    &dbl_module_http,
    &dbl_module_signal,
    NULL,
};

int dbl_max_modules;

void dbl_register_all_modules() {
    struct dbl_module *module;

    dbl_max_modules = 0;
    while ((module = dbl_modules[dbl_max_modules])) 
        module->index = dbl_max_modules++;
}
