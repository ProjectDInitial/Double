#include "dbl_yamlmapper.h"
#include "dbl_log.h"
#include "dbl_pool.h"
#include "dbl_array.h"
#include "dbl_util.h"

static int dbl_yamlmapper_get_node_sequence_length_(const struct yaml_node_s *node) {
    assert(node->type == YAML_SEQUENCE_NODE);
    return (node->data.sequence.items.top - node->data.sequence.items.start); 
}

static struct yaml_node_s *dbl_yamlmapper_get_node_sequence_element_(struct dbl_yamlmapper *mapper, const struct yaml_node_s *node, int index) {
    assert(node->type == YAML_SEQUENCE_NODE);
    assert(index < dbl_yamlmapper_get_node_sequence_length_(node));
    
    return yaml_document_get_node(&mapper->document, *(node->data.sequence.items.start + index));
}

struct yaml_node_s *dbl_yamlmapper_get_node_mapping_element_(struct dbl_yamlmapper *mapper, const struct yaml_node_s *node, const char *key, size_t len) {
    const struct yaml_node_pair_s *pair;
    const struct yaml_node_s *keynode;
    
    assert(node->type == YAML_MAPPING_NODE);
    
    for(pair = node->data.mapping.pairs.start;
        pair != node->data.mapping.pairs.top;
        pair++)
    {
        keynode = yaml_document_get_node(&mapper->document, pair->key);
        if (keynode->data.scalar.length == len &&
            strncmp((char*)keynode->data.scalar.value, key, len) == 0)
        {
            return yaml_document_get_node(&mapper->document, pair->value);
        }
    }
    return NULL;
}

//int dbl_yamlmapper_set_scalar(struct dbl_yamlmapper *mapper, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *node, void *object) { 
//    char *str;
//    
//    if (node->type != YAML_SCALAR_NODE) {
//        dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "node type is not scalar");
//        return -1;
//    }
//
//    str = dbl_pool_alloc(mapper->pool, node->data.scalar.length + 1);
//    if (str == NULL)
//        return -1;
//
//    memcpy(str, node->data.scalar.value, node->data.scalar.length);
//    str[node->data.scalar.length] = '\0';
//
//    *(void **)(object + cmd->offset) = str;
//    return 0;
//}
//
//int dbl_yamlmapper_set_object(struct dbl_yamlmapper *mapper, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *node, void *object) {
//    const struct dbl_yamlmapper_command *c;
//    const struct yaml_node_s *child;
//    void *obj;
//    
//    if (node->type != YAML_MAPPING_NODE) {
//        dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "node type is not map");
//        return -1;
//    }
//
//    obj = dbl_pool_alloc(mapper->pool, cmd->size);
//    if (obj == NULL)
//        return -1;
//    memset(obj, 0, cmd->size);
//
//    c = cmd->inner_commands;
//    while (c->key) {
//        child = dbl_yamlmapper_get_node_mapping_element_(mapper, node, c->key, strlen(c->key));
//        if (child == NULL) {
//            if (cmd->required) {
//                dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "node '%s' is required", c->key);
//                return -1;
//            }
//            continue;
//        }
//        if (c->set(mapper, c, child, obj) == -1) {
//            dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "node '%s' inner error", c->key);
//            return -1;
//        }
//        c++;
//    }
//
//    *(void **)(object + cmd->offset) = obj;
//    return 0;
//}
//
//int dbl_yamlmapper_set_array(struct dbl_yamlmapper *mapper, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *node, void *object) {
//    const struct dbl_yamlmapper_command *c;
//    const struct yaml_node_s *child;
//    void **arr;
//    int len;
//    
//    if (node->type != YAML_SEQUENCE_NODE) {
//        dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "node type is not sequence");
//        return -1;
//    }
//
//    len = dbl_yamlmapper_get_node_sequence_length_(node);
//    arr = dbl_pool_alloc(mapper->pool, sizeof(void *) * len);
//    c = cmd->inner_commands;
//    for (int i = 0; i < len; i++) {
//        child = dbl_yamlmapper_get_node_sequence_element_(mapper, node, i);
//        if (c->set(mapper, c, child, &arr[i]) == -1)
//            return -1;
//    }
//
//    *(void **)(object + cmd->offset) = arr;
//    *(int *)(object + cmd->size) = len;
//    return 0;
//}

void dbl_yamlmapper_init(struct dbl_yamlmapper *mapper, struct dbl_log *log) {
    mapper->log = log;
    mapper->loaded = 0;
}

int dbl_yamlmapper_load(struct dbl_yamlmapper *mapper, const char *filepath) {
    struct yaml_parser_s initparser, *parser; 
    FILE *file;
    int res;

    file = NULL;
    parser = NULL;
    res = 0;

    file = fopen(filepath, "r");
    if (file == NULL) {
        dbl_log_error(DBL_LOG_ERROR, mapper->log, errno, "yaml mapper load document '%s' failed", filepath);
        res = -1;
        goto done;
    }

    if (yaml_parser_initialize(&initparser) == 0) {
        dbl_log_error(DBL_LOG_ERROR, mapper->log, errno, "yaml mapper initialize parser failed");
        res = -1;
        goto done;
    }
    parser = &initparser;
    
    yaml_parser_set_input_file(parser, file);
    yaml_parser_set_encoding(parser, YAML_UTF8_ENCODING);
    if (yaml_parser_load(parser, &mapper->document) == 0) {
        dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "yaml mapper load document '%s' failed (%s - line:%zu column:%zu)", filepath, parser->problem, parser->problem_mark.line, parser->problem_mark.column);
        res = -1;
        goto done;
    }

    mapper->loaded = 1;

done:
    if (file)
        fclose(file);
    if (parser)
        yaml_parser_delete(parser);
    return res;
}

void dbl_yamlmapper_delete(struct dbl_yamlmapper *mapper) {
    if (mapper->loaded)
        yaml_document_delete(&mapper->document);
}


int dbl_yamlmapper_map(struct dbl_yamlmapper *mapper, struct dbl_pool *pool, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *position, void *object) {
    if (position == NULL)
        position = yaml_document_get_root_node(&mapper->document);

    if (position->type != YAML_MAPPING_NODE) {
        dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "yaml node is not a map");
        return -1;
    }
    
    position = dbl_yamlmapper_get_node_mapping_element_(mapper, position, cmd->key, strlen(cmd->key));
    if (position == NULL) {
        if (!cmd->required)
            return 0;

        dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "yaml node '%s' not found", cmd->key);
        return -1;
    }
    
    if (cmd->set(mapper, pool, cmd, position, object + cmd->offset) == -1) {
        dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "yaml mapping error on '%s'", cmd->key);    
        return -1;
    }

    return 0;
}

int dbl_yamlmapper_set_string_ptr(struct dbl_yamlmapper *mapper, struct dbl_pool *pool, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *position, void *object) {
    char *str;
    
    if (position->type != YAML_SCALAR_NODE) {
        dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "yaml node is not a scalar");
        return -1;
    }

    str = dbl_pool_strndup(pool, (char*)position->data.scalar.value, position->data.scalar.length);
    if (str == NULL)
        return -1;

    *(void **)object = str;
    return 0;
}

int dbl_yamlmapper_set_struct(struct dbl_yamlmapper *mapper, struct dbl_pool *pool, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *position, void *object) {
    if (position->type != YAML_MAPPING_NODE) {
        dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "yaml node is not a map");
        return -1;
    }

    for (cmd = cmd->commands; cmd->key; cmd++) {
        if (dbl_yamlmapper_map(mapper, pool, cmd, position, object) == -1)
            return -1;
    }
    return 0; 
}

int dbl_yamlmapper_set_struct_ptr(struct dbl_yamlmapper *mapper, struct dbl_pool *pool, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *position, void *object) {
    void *newobj;

    newobj = dbl_pool_alloc(pool, cmd->size);
    if (newobj == NULL)
        return -1;

    if (dbl_yamlmapper_set_struct(mapper, pool, cmd, position, newobj) == -1)
        return -1;

    *(void **)object = newobj;
    return 0;
}

int dbl_yamlmapper_set_parray(struct dbl_yamlmapper *mapper, struct dbl_pool *pool, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *position, void *object) {
    struct dbl_array *arr;
    struct yaml_node_s *node;
    int nele;
    void *ele;

    if (position->type != YAML_SEQUENCE_NODE) {
        dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "yaml node is not a sequence");
        return -1;
    }

    arr = object; 
    nele = dbl_yamlmapper_get_node_sequence_length_(position);
    if (dbl_array_init(arr, pool, nele, cmd->size) == -1)
        return -1;

    cmd = cmd->commands;
    for (int i = 0; i < nele; i++) {
        ele = dbl_array_push(arr);
        node = dbl_yamlmapper_get_node_sequence_element_(mapper, position, i);
        assert(ele != NULL);
        if (cmd->set(mapper, pool, cmd, node, ele) == -1)
            return -1;
    }
    return 0;
}

int dbl_yamlmapper_set_int(struct dbl_yamlmapper *mapper, struct dbl_pool *pool, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *position, void *object) {
    int val;
    
    if (position->type != YAML_SCALAR_NODE) 
        goto error;

    val = dbl_atoi((char*)position->data.scalar.value, position->data.scalar.length);
    if (val == -1) 
        goto error;
    
    *(int *)object = val;
    return 0;

error:
    dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "yaml node is not a positive integer");
    return -1;
}

int dbl_yamlmapper_set_int_ptr(struct dbl_yamlmapper *mapper, struct dbl_pool *pool, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *position, void *object) {
    int *val;

    val = dbl_pool_alloc(pool, sizeof(int));
    if (val == NULL)
        return -1;

    if (dbl_yamlmapper_set_int(mapper, pool, cmd, position, val) == -1)
        return -1;

    *(int **)object = val;
    return 0;
}

int dbl_yamlmapper_set_timeval(struct dbl_yamlmapper *mapper, struct dbl_pool *pool, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *position, void *object) {
    struct timeval tv;
    int ms;

    if (dbl_yamlmapper_set_int(mapper, pool, cmd, position, &ms) == -1)
        return -1;
    
    dbl_mstotv(ms, &tv);
    *(struct timeval*)object = tv;
    return 0;
}
