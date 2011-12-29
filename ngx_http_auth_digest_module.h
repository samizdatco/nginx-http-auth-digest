#ifndef _NGX_HTTP_AUTH_DIGEST_H_INCLUDED_
#define _NGX_HTTP_AUTH_DIGEST_H_INCLUDED_

// the module conf
typedef struct {
    ngx_str_t                 realm;
    time_t                    timeout;
    time_t                    expires;
    ngx_int_t                 replays;
    ngx_http_complex_value_t  user_file;
    ngx_str_t                 cache_dir;
} ngx_http_auth_digest_loc_conf_t;

// contents of the request's authorization header
typedef struct { 
  ngx_str_t username;
  ngx_str_t realm;
  ngx_str_t nonce;
  ngx_str_t nc;
  ngx_str_t uri;
  ngx_str_t qop;
  ngx_str_t cnonce;
  ngx_str_t response;
  ngx_str_t opaque;
  ngx_int_t stale;
} ngx_http_auth_digest_cred_t;

// the nonce as an issue-time/random-num pair
typedef struct { 
  ngx_uint_t rnd;
  time_t t;
} ngx_http_auth_digest_nonce_t;

// nonce entries in the rbtree
typedef struct { 
    ngx_rbtree_node_t node;    // the node's .key is derived from the nonce val
    time_t            expires; // time at which the node should be evicted
    char              nc[0];   // bitvector of used nc values to prevent replays
} ngx_http_auth_digest_node_t;

// the main event
static ngx_int_t ngx_http_auth_digest_handler(ngx_http_request_t *r);

// passwd file handling
static void ngx_http_auth_digest_close(ngx_file_t *file);
static char *ngx_http_auth_digest_user_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
#define NGX_HTTP_AUTH_DIGEST_BUF_SIZE 4096

// digest challenge generation
static ngx_int_t ngx_http_auth_digest_send_challenge(ngx_http_request_t *r,
                     ngx_str_t *realm, ngx_uint_t is_stale);

// digest response validators
static ngx_int_t ngx_http_auth_digest_check_credentials(ngx_http_request_t *r, 
                     ngx_http_auth_digest_cred_t *ctx);
static ngx_inline ngx_int_t ngx_http_auth_digest_decode_auth(ngx_http_request_t *r, 
                     ngx_str_t *auth_str, char *field_name, ngx_str_t *field_val);
static ngx_int_t ngx_http_auth_digest_verify_user(ngx_http_request_t *r, 
                     ngx_http_auth_digest_cred_t *fields, ngx_str_t *line);
static ngx_int_t ngx_http_auth_digest_verify_hash(ngx_http_request_t *r, 
                     ngx_http_auth_digest_cred_t *fields, u_char *hashed_pw);

// the shm segment that houses the used-nonces tree
static ngx_uint_t      ngx_http_auth_digest_shm_size;
static ngx_shm_zone_t *ngx_http_auth_digest_shm_zone;
static ngx_rbtree_t   *ngx_http_auth_digest_rbtree;
static char *ngx_http_auth_digest_set_shm_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_auth_digest_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data);

// nonce bookkeeping
static ngx_http_auth_digest_nonce_t ngx_http_auth_digest_next_nonce(ngx_http_request_t *r);
static ngx_rbtree_node_t *ngx_http_auth_digest_rbtree_find(ngx_rbtree_key_t key, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

// nonce cleanup
#define NGX_HTTP_AUTH_DIGEST_CLEANUP_INTERVAL 3000
#define NGX_HTTP_AUTH_DIGEST_CLEANUP_BATCH_SIZE 2048
ngx_event_t *ngx_http_auth_digest_cleanup_timer;
static ngx_array_t *ngx_http_auth_digest_cleanup_list;
static ngx_atomic_t *ngx_http_auth_digest_cleanup_lock;
void ngx_http_auth_digest_cleanup(ngx_event_t *e);
static void ngx_http_auth_digest_rbtree_prune(ngx_log_t *log);
static void ngx_http_auth_digest_rbtree_prune_walk(ngx_rbtree_node_t *node, 
                ngx_rbtree_node_t *sentinel, time_t now, ngx_log_t *log);

// rbtree primitives
static void ngx_http_auth_digest_rbtree_insert(ngx_rbtree_node_t *temp,
                ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static void ngx_rbtree_generic_insert(ngx_rbtree_node_t *temp,
                ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel,
                int (*compare)(const ngx_rbtree_node_t *left, const ngx_rbtree_node_t *right));
static int ngx_http_auth_digest_rbtree_cmp(const ngx_rbtree_node_t *v_left,
                const ngx_rbtree_node_t *v_right);

// quick & dirty bitvectors (for marking used nc values)
static ngx_inline ngx_uint_t ngx_bitvector_size(ngx_uint_t nbits){
    return ((nbits + CHAR_BIT - 1) / CHAR_BIT);
}
static ngx_inline ngx_uint_t ngx_bitvector_test(char *bv, ngx_uint_t bit){
    return ((bv)[((bit) / CHAR_BIT)] & (1 << ((bit) % CHAR_BIT)));
}
static ngx_inline void ngx_bitvector_set(char *bv, ngx_uint_t bit){
    ((bv)[((bit) / CHAR_BIT)] &= ~(1 << ((bit) % CHAR_BIT)));
}

// module plumbing
static void *ngx_http_auth_digest_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_digest_merge_loc_conf(ngx_conf_t *cf,void *parent, void *child);
static ngx_int_t ngx_http_auth_digest_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_digest_worker_init(ngx_cycle_t *cycle);
static char *ngx_http_auth_digest(ngx_conf_t *cf, void *post, void *data);

// module datastructures
static ngx_conf_post_handler_pt ngx_http_auth_digest_p = ngx_http_auth_digest;
static ngx_command_t  ngx_http_auth_digest_commands[] = {

    { ngx_string("auth_digest"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_digest_loc_conf_t, realm),
      &ngx_http_auth_digest_p },
    { ngx_string("auth_digest_user_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_auth_digest_user_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_digest_loc_conf_t, user_file),
      NULL },
    { ngx_string("auth_digest_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_digest_loc_conf_t, timeout),
      NULL },
    { ngx_string("auth_digest_expires"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_digest_loc_conf_t, expires),
      NULL },
    { ngx_string("auth_digest_replays"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_digest_loc_conf_t, replays),
      NULL },
    { ngx_string("auth_digest_shm_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_auth_digest_set_shm_size,
      0,
      0,
      NULL },
      ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_digest_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_auth_digest_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_auth_digest_create_loc_conf,  /* create location configuration */
    ngx_http_auth_digest_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_auth_digest_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_digest_module_ctx,      /* module context */
    ngx_http_auth_digest_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_auth_digest_worker_init,      /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

#endif
