#include "dbl_http.h"
#include "dbl_pool.h"
#include "dbl_util.h"

void dbl_http_form_init(struct dbl_http_form *form, struct dbl_pool *pool) {
    form->header = NULL;
    form->tail = &form->header;
    form->pool = pool;
    form->count = 0;
}

int dbl_http_form_add(struct dbl_http_form *form, const char *key, const char *val) {
    char *k, *v;

    assert(key != NULL);
    assert(val != NULL);
    
    k = dbl_pool_strdup(form->pool, key);
    if (k == NULL)
        return -1;

    v = dbl_pool_strdup(form->pool, val);
    if (v == NULL)
        return -1;
    
    return dbl_http_form_add_reference(form, k, v);
}

int dbl_http_form_add_reference(struct dbl_http_form *form, const char *key, const char *val) {
    struct dbl_http_pair *pair;
    
    assert(key != NULL);
    assert(val != NULL);

    pair = dbl_pool_alloc(form->pool, sizeof(struct dbl_http_pair));
    if (pair == NULL)
        return -1;

    pair->key = key;
    pair->value = val;
    pair->next = NULL;

    *form->tail = pair;
    form->tail = &pair->next;
    form->count++;
    return 0;
}

static struct dbl_http_pair *dbl_http_form_find_pair_(const struct dbl_http_form *form, const char *key) {
    struct dbl_http_pair *pair;

    for (pair = form->header; pair; pair = pair->next) {
        if (dbl_strcasecmp(pair->key, key) == 0) 
            return pair;
    }
    return NULL;
}

int dbl_http_form_insert(struct dbl_http_form *form, const char *key, const char *val) {
    struct dbl_http_pair *pair;
    char *v;

    pair = dbl_http_form_find_pair_(form, key);
    if (pair == NULL)
        return dbl_http_form_add(form, key, val);

    v = dbl_pool_strdup(form->pool, val);
    if (v == NULL)
        return -1;

    pair->value = v;
    return 0;
}

const char *dbl_http_form_find(const struct dbl_http_form *form, const char *key) {
    struct dbl_http_pair *pair;

    pair = dbl_http_form_find_pair_(form, key);
    if (pair == NULL)
        return NULL;
    return pair->value;
}

void dbl_http_form_remove(struct dbl_http_form *form, const char *key) {
    struct dbl_http_pair *prev;
    struct dbl_http_pair *pair;

    for (pair = form->header, prev = NULL; pair; prev = pair, pair = pair->next) {
        if (dbl_strcasecmp(pair->key, key) == 0) {
            if (pair == form->header) {
                if ((form->header = pair->next) == NULL)
                    form->tail = &form->header;
            }
            else {
                if ((prev->next = pair->next) == NULL)
                    form->tail = &prev->next;
            }
            form->count--;
            return;
        }
    }
}

static void dbl_http_form_sort_one_(struct dbl_http_form *form, struct dbl_http_pair **startat, dbl_http_pair_comparator comparator) {
    struct dbl_http_pair **prev, *curr, *next, *top, **top_prev;
    
    top = *startat;
    top_prev = NULL;
    for (prev = &top->next, curr = top->next; 
         curr != NULL; 
         prev = &curr->next, curr = curr->next) 
    {
        if (comparator(top, curr)) {
            top = curr;
            top_prev = prev;
        }
    }

    if (top_prev == NULL)
        return;

    curr = *startat;
    if (curr->next == top) {
        curr->next = top->next;
        top->next = curr;
    } 
    else {
        next = curr->next;
        curr->next = top->next;
        top->next = next;
        *top_prev = curr;
    }
    
    if (curr->next == NULL)
        form->tail = &curr->next;
    
    *startat = top;
}

void dbl_http_form_sort(struct dbl_http_form *form, dbl_http_pair_comparator comparator) {
    struct dbl_http_pair **header;

    if (form->header == NULL)
        return;

    header = &form->header;
    while (*header) {
        dbl_http_form_sort_one_(form, header, comparator);
        header = &(*header)->next;
    }
}

int dbl_http_form_parse_formdata(struct dbl_http_form *form, const char *formdata, size_t len, int decode) { 
    char *s;
    char *chunk, *key, *val;

    if (len == 0)
        return 0;

    s = dbl_pool_strndup(form->pool, formdata, len);
    if (s == NULL)
        return -1;

    while ((chunk = dbl_strsep(&s, "&"))) {
        if (strlen(chunk) == 0)
            return -1;

        val = chunk;
        key = dbl_strsep(&val, "=");
        if (strlen(key) == 0 || val == NULL)
            return -1;

        if (decode) {
            len = strlen(val);
            dbl_http_decode_uri(val, len, val, &len);
            val[len] = '\0';
        }

        if (dbl_http_form_add(form, key, val) == -1)
            return -1;
    }
    return 0; 
}

/**
 * RFC3986 2.3. Unreserved Characters
 *
 * unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
 *
 */
static const char uri_unreserved_chars[] = {
	/* 0 */
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 1, 1, 0,
	1, 1, 1, 1, 1, 1, 1, 1,   1, 1, 0, 0, 0, 0, 0, 0,
	/* 64 */
	0, 1, 1, 1, 1, 1, 1, 1,   1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,   1, 1, 1, 0, 0, 0, 0, 1,
	0, 1, 1, 1, 1, 1, 1, 1,   1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,   1, 1, 1, 0, 0, 0, 1, 0,
	
    0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
    
    0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
};

size_t dbl_http_decode_uri(const char *data, size_t length, char *buf, size_t *n) {
    size_t n_decoded;
    size_t n_written;
    char c;
    char hexstr[3]; 

    n_written = 0;
    n_decoded = 0;
    while (n_decoded < length && n_written < *n) {
        c = data[n_decoded];
        /* Check is percent encode */
        if (c == '%' &&
            n_decoded + 2 < length &&
            isxdigit(data[n_decoded + 1]) && isxdigit(data[n_decoded + 2]))
        {
            hexstr[0] = data[n_decoded + 1];
            hexstr[1] = data[n_decoded + 2];
            hexstr[2] = '\0';
			c = (char)strtol(hexstr, NULL, 16);
			n_decoded += 2;
        }
        n_decoded++;
        buf[n_written++] = c;
    }

    *n = n_written;
    return n_decoded;
}

size_t dbl_http_encode_uri(const char *data, size_t length, char *buf, size_t *n) {
    size_t n_encoded;   /* Number of byte encoded from the uri */
    size_t n_written;   /* Number of byte wriiten to the buffer */
    char c;
    char hexstr[4];

    n_written = 0;
    n_encoded = 0;
    while (n_encoded < length && n_written < *n) {
        c = data[n_encoded];
        if (uri_unreserved_chars[(unsigned char)c]) {
            buf[n_written++] = c;   
        }
        else { /* Char is URI reserved character, encoding it. */
            if (*n - n_written < 3)
                break;

            snprintf(hexstr, 4, "%%%02X", c);
            memcpy(buf + n_written, hexstr, 3);
            n_written += 3;
        }
        n_encoded++;
    }

    *n = n_written;
    return n_encoded;
}

void dbl_http_uri_init(struct dbl_http_uri *uri, struct dbl_pool *pool) {
    memset(uri, 0, sizeof(struct dbl_http_uri));
    uri->pool = pool;
}

int dbl_http_uri_parse(struct dbl_http_uri *uri, const char *url, size_t len) {
    struct http_parser_url parser;
    char *u;
    char *s;

    if (len == 0)
        return -1;

    u = dbl_pool_strndup(uri->pool, url, len);
    if (u == NULL)
        return -1;
    
    http_parser_url_init(&parser);
    if (http_parser_parse_url(u, len, 0, &parser) != 0)
        return -1;

    if (parser.field_set & (1 << UF_HOST)) {
        s = u + parser.field_data[UF_HOST].off;
        s[parser.field_data[UF_HOST].len] = '\0';
        uri->host = s;
    }
    if (parser.field_set & (1 << UF_PATH)) {
        s = u + parser.field_data[UF_PATH].off;
        s[parser.field_data[UF_PATH].len] = '\0';
        uri->path = s;
    }
    if (parser.field_set & (1 << UF_QUERY)) {
        s = u + parser.field_data[UF_QUERY].off;
        s[parser.field_data[UF_QUERY].len] = '\0';
        uri->query = s;
    }
    return 0;
}

const char *dbl_http_method_str(enum dbl_http_method method) {
    switch (method) {
#define XX(num, name, string) case DHTTP_METHOD_##name: return #string;
  DHTTP_METHOD_MAP(XX)
#undef XX
        default: return "unkown";
    }
}

const char *dbl_http_status_str(enum dbl_http_status status) {
    switch (status) {
#define XX(num, name, string) case DHTTP_STATUS_##name: return #string;
    DHTTP_STATUS_MAP(XX)
#undef XX
    default: return "unknown";
    }
}

int dbl_http_status_is_error(enum dbl_http_status status) {
    return status >= 400;
}
