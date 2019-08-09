#ifndef __DBL_CONFIG_H
#define __DBL_CONFIG_H

#include <stdio.h>

struct dbl_config {
    const char                                     *error_log_path;
    const struct dbl_config_http                   *http;
};

struct dbl_config_http {
    unsigned short                                  port;
    int                                             timeout;
    const char                                     *access_log_path;
    int                                             maxheadersize;
    int                                             maxbodysize;

    const struct dbl_config_http_ssl               *ssl;
    const struct dbl_config_http_tcp               *tcp;
    const struct dbl_config_http_partner           *partners;
    int                                             partners_count;
};

struct dbl_config_http_tcp {
    const int                                      *keepalive_time;
    const int                                      *keepalive_intvl;
    const int                                      *keepalive_probes;
    const int                                      *nodelay;
};

struct dbl_config_http_ssl {
    const char                                     *certificate;
    const char                                     *privatekey;
};

struct dbl_config_http_partner {
    const char                                     *id;
    const char                                     *secret;
};


/**
 * @brief Parse config from a file at the given path
 *
 * @param filepath the config file path
 *
 * @return a pointer to config object or NULL on error 
 */
struct dbl_config *dbl_config_parse_file(const char *filepath);


/**
 * @brief Free a config 
 *
 * @param config the config to be freed
 */
void dbl_config_free(struct dbl_config *config);

#endif
