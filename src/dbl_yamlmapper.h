#ifndef __DBL_YAML_MAPPER_H
#define __DBL_YAML_MAPPER_H

#include "dbl_config.h"
#include <yaml.h>

struct dbl_yamlmapper {
    struct dbl_log             *log;
    struct yaml_document_s      document;
    int                         loaded;
};

struct dbl_yamlmapper_command {
    const char                             *key;
    size_t                                  offset;
    size_t                                  size; 
    int                                     required;
    const struct dbl_yamlmapper_command    *commands;
    int                                   (*set)(struct dbl_yamlmapper *mapper, struct dbl_pool *pool, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *node, void *object);
};

#define DBL_YAML_MAPPER_NULL_CMD            {NULL, 0, 0, 0, NULL, NULL}

/**
 * @brief Initialize a yaml mapper
 */
void dbl_yamlmapper_init(struct dbl_yamlmapper *mapper, struct dbl_log *log); 

/**
 * @brief Load a yaml document from the given path
 */
int dbl_yamlmapper_load(struct dbl_yamlmapper *mapper, const char *filepath); 

/**
 * @brief Delete the loaded document of the mapper 
 */
void dbl_yamlmapper_delete(struct dbl_yamlmapper *mapper);

int dbl_yamlmapper_map(struct dbl_yamlmapper *mapper, struct dbl_pool *pool, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *position, void *object); 
int dbl_yamlmapper_set_string_ptr(struct dbl_yamlmapper *mapper, struct dbl_pool *pool, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *position, void *object); 
int dbl_yamlmapper_set_struct(struct dbl_yamlmapper *mapper, struct dbl_pool *pool, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *position, void *object);
int dbl_yamlmapper_set_struct_ptr(struct dbl_yamlmapper *mapper, struct dbl_pool *pool, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *position, void *object); 
int dbl_yamlmapper_set_parray(struct dbl_yamlmapper *mapper, struct dbl_pool *pool, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *position, void *object); 
int dbl_yamlmapper_set_int(struct dbl_yamlmapper *mapper, struct dbl_pool *pool, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *position, void *object); 
int dbl_yamlmapper_set_int_ptr(struct dbl_yamlmapper *mapper, struct dbl_pool *pool, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *position, void *object); 
int dbl_yamlmapper_set_timeval(struct dbl_yamlmapper *mapper, struct dbl_pool *pool, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *position, void *object); 
#endif
