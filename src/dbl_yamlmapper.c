#include "dbl_yamlmapper.h"
#include "dbl_log.h"
#include "dbl_pool.h"

//static char *dbl_yamlmapper_get_node_scalar_value_(const struct yaml_node_s *node) {
//    return (char*)node->data.scalar.value;
//}
//
//static size_t dbl_yamlmapper_get_node_scalar_length_(const struct yaml_node_s *node) {
//    return node->data.scalar.length;
//}

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

int dbl_yamlmapper_set_scalar(struct dbl_yamlmapper *mapper, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *node, void *object) { 
    char *str;
    
    if (node->type != YAML_SCALAR_NODE) {
        dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "node type is not scalar");
        return -1;
    }

    str = dbl_pool_alloc(mapper->pool, node->data.scalar.length + 1);
    if (str == NULL)
        return -1;

    memcpy(str, node->data.scalar.value, node->data.scalar.length);
    str[node->data.scalar.length] = '\0';

    *(void **)(object + cmd->offset) = str;
    return 0;
}

int dbl_yamlmapper_set_object(struct dbl_yamlmapper *mapper, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *node, void *object) {
    const struct dbl_yamlmapper_command *c;
    const struct yaml_node_s *child;
    void *obj;
    
    if (node->type != YAML_MAPPING_NODE) {
        dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "node type is not map");
        return -1;
    }

    obj = dbl_pool_alloc(mapper->pool, cmd->size);
    if (obj == NULL)
        return -1;
    memset(obj, 0, cmd->size);

    c = cmd->inner_commands;
    while (c->key) {
        child = dbl_yamlmapper_get_node_mapping_element_(mapper, node, c->key, strlen(c->key));
        if (child == NULL) {
            if (cmd->required) {
                dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "node '%s' is required", c->key);
                return -1;
            }
            continue;
        }
        if (c->set(mapper, c, child, obj) == -1) {
            dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "node '%s' inner error", c->key);
            return -1;
        }
        c++;
    }

    *(void **)(object + cmd->offset) = obj;
    return 0;
}

int dbl_yamlmapper_set_array(struct dbl_yamlmapper *mapper, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *node, void *object) {
    const struct dbl_yamlmapper_command *c;
    const struct yaml_node_s *child;
    void **arr;
    int len;
    
    if (node->type != YAML_SEQUENCE_NODE) {
        dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "node type is not sequence");
        return -1;
    }

    len = dbl_yamlmapper_get_node_sequence_length_(node);
    arr = dbl_pool_alloc(mapper->pool, sizeof(void *) * len);
    c = cmd->inner_commands;
    for (int i = 0; i < len; i++) {
        child = dbl_yamlmapper_get_node_sequence_element_(mapper, node, i);
        if (c->set(mapper, c, child, &arr[i]) == -1)
            return -1;
    }

    *(void **)(object + cmd->offset) = arr;
    *(int *)(object + cmd->size) = len;
    return 0;
}

int dbl_yamlmapper_init(struct dbl_yamlmapper *mapper, struct dbl_log *log) {
    struct dbl_pool *pool;

    pool = dbl_pool_new(log);
    if (pool == NULL)
        return -1;

    mapper->pool = pool;
    mapper->log = log;
    mapper->loaded = 0;
    return 0;
}

void dbl_yamlmapper_release(struct dbl_yamlmapper *mapper) {
    dbl_pool_free(mapper->pool);
    if (mapper->loaded) {
        yaml_document_delete(&mapper->document);
    }
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
        dbl_log_error(DBL_LOG_ERROR, mapper->log, errno, "yaml document load failed '%s'", filepath);
        res = -1;
        goto done;
    }

    if (yaml_parser_initialize(&initparser) == 0) {
        dbl_log_error(DBL_LOG_ERROR, mapper->log, errno, "yaml document load failed '%s'", filepath);
        res = -1;
        goto done;
    }
    parser = &initparser;
    
    yaml_parser_set_input_file(parser, file);
    yaml_parser_set_encoding(parser, YAML_UTF8_ENCODING);
    if (yaml_parser_load(parser, &mapper->document) == 0) {
        dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "yaml document load failed '%s' (%s - line:%zu column:%zu)", filepath, parser->problem, parser->problem_mark.line, parser->problem_mark.column);
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

int dbl_yamlmapper_map_object(struct dbl_yamlmapper *mapper, const struct dbl_yamlmapper_command *cmd, const struct yaml_node_s *start, const void **out_object) {
    const void *obj;

    assert(cmd->offset == 0);
    assert(cmd->key != NULL);

    if (start == NULL)
        start = yaml_document_get_root_node(&mapper->document);

    if (start->type != YAML_MAPPING_NODE)
        return -1;

    start = dbl_yamlmapper_get_node_mapping_element_(mapper, start, cmd->key, strlen(cmd->key));
    if (start == NULL) {
        if (cmd->required) {
            dbl_log_error(DBL_LOG_ERROR, mapper->log, 0, "node '%s' could not be found in yaml document", cmd->key);
            return -1;
        }
        return 0;
    }
    
    if (cmd->set(mapper, cmd, start, &obj) == -1)
        return -1;

    *out_object = obj;
    return 0;
}
