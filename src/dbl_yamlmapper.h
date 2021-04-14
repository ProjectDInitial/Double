#ifndef __DBL_YAML_MAPPER_H
#define __DBL_YAML_MAPPER_H

#include "dbl_config.h"
#include <yaml.h>

struct dbl_yamlmapper {
    struct dbl_log             *log;
    struct dbl_pool            *pool;
    struct yaml_document_s      document;
    int                         loaded;
};

struct dbl_yamlmapper_command {
    const char                             *key;
    size_t                                  offset;
    int                                     required;
    size_t                                  size;   
    const struct dbl_yamlmapper_command   *inner_commands;
    int                                   (*set)(struct dbl_yamlmapper *mapper, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *node, void *object);
};

#define DBL_YAML_MAPPER_SCALAR_CMD_PADDING  0, NULL, dbl_yamlmapper_set_scalar
#define DBL_YAML_MAPPER_OBJECT_CMD_PADDING           dbl_yamlmapper_set_object
#define DBL_YAML_MAPPER_ARRAY_CMD_PADDING            dbl_yamlmapper_set_array
#define DBL_YAML_MAPPER_NULL_CMD            {NULL, 0, 0, 0, NULL, NULL}


/**
 * @brief Initialize a yaml mapper
 */
int dbl_yamlmapper_init(struct dbl_yamlmapper *mapper, struct dbl_log *log); 

/**
 * @brief Release all resources on yaml mapper
 */
void dbl_yamlmapper_release(struct dbl_yamlmapper *mapper);

/**
 * @brief Load a yaml document from the given path
 */
int dbl_yamlmapper_load(struct dbl_yamlmapper *mapper, const char *filepath); 


int dbl_yamlmapper_set_scalar(struct dbl_yamlmapper *mapper, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *node, void *object); 
int dbl_yamlmapper_set_object(struct dbl_yamlmapper *mapper, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *node, void *object); 
int dbl_yamlmapper_set_array(struct dbl_yamlmapper *mapper, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *node, void *object); 
int dbl_yamlmapper_map_object(struct dbl_yamlmapper *mapper, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *start, const void **out_object); 
#endif
