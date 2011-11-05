
/*
 * copyright (c) samizdat drafting co.
 * derived from http_auth_basic (c) igor sysoev
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>

// the module conf
typedef struct { 
    ngx_str_t                 realm;
    time_t                    timeout;
    time_t                    expires;
    ngx_int_t                 replays;
    ngx_http_complex_value_t  user_file;
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
} ngx_http_auth_digest_cred_t;

// the nonce as an issue-time/random-num pair
typedef struct { 
  ngx_uint_t rnd;
  time_t t;
} ngx_http_auth_digest_nonce_t;

// nonce entries in the rbtree
typedef struct { 
    ngx_rbtree_node_t                   node;    // the node's .key is derived from the nonce val
    time_t                              expires; // time at which the node should be evicted
    char                                nc[0];   // bitvector of used nc values to prevent replays
} ngx_http_auth_digest_node_t;

// the main event
static ngx_int_t ngx_http_auth_digest_handler(ngx_http_request_t *r);

// passwd file handling
static void ngx_http_auth_digest_close(ngx_file_t *file);
static char *ngx_http_auth_digest_user_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
#define NGX_HTTP_AUTH_BUF_SIZE  2048

// digest challenge generation
static ngx_int_t ngx_http_auth_digest_send_challenge(ngx_http_request_t *r,
    ngx_str_t *realm, ngx_uint_t is_stale);

// digest response validators
static ngx_int_t ngx_http_auth_digest_user(ngx_http_request_t *r, 
                     ngx_http_auth_digest_cred_t *ctx);
static ngx_inline ngx_int_t ngx_http_auth_digest_decode_auth(ngx_http_request_t *r, 
                     ngx_str_t *auth_str, char *field_name, ngx_str_t *field_val);
static ngx_int_t ngx_http_auth_digest_passwd_handler(ngx_http_request_t *r, 
                     ngx_http_auth_digest_cred_t *fields, ngx_str_t *line);
static ngx_int_t ngx_http_auth_digest_verify(ngx_http_request_t *r, 
                     ngx_http_auth_digest_cred_t *fields, ngx_str_t *HA1);

// the shm segment that houses the used-nonces tree
static ngx_uint_t      ngx_http_auth_digest_shm_size;
static ngx_shm_zone_t *ngx_http_auth_digest_shm_zone;
static ngx_rbtree_t   *ngx_http_auth_digest_rbtree;
static char *ngx_http_auth_digest_set_shm_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_auth_digest_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data);

// nonce bookkeeping
static ngx_http_auth_digest_nonce_t ngx_http_auth_digest_next_nonce(ngx_http_request_t *r);
static void ngx_http_auth_digest_rbtree_prune(ngx_http_request_t *r);
static void ngx_http_auth_digest_rbtree_prune_walk(ngx_rbtree_node_t *node, 
          ngx_rbtree_node_t *sentinel, time_t now, ngx_log_t *log);
static void ngx_http_auth_digest_rbtree_insert(ngx_rbtree_node_t *temp,
                ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static void ngx_rbtree_generic_insert(ngx_rbtree_node_t *temp,
                ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel,
                int (*compare)(const ngx_rbtree_node_t *left, const ngx_rbtree_node_t *right));
static int ngx_http_auth_digest_rbtree_cmp(const ngx_rbtree_node_t *v_left,
                const ngx_rbtree_node_t *v_right);
static ngx_rbtree_node_t *ngx_http_auth_digest_rbtree_find(ngx_rbtree_key_t key, 
                ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

// nc-counting
static ngx_uint_t ngx_bitvector_size(ngx_uint_t nbits);
static ngx_uint_t ngx_bitvector_test(char *bv, ngx_uint_t bit);
static void ngx_bitvector_set(char *bv, ngx_uint_t bit);
#define NGX_STALE -2600

// module plumbing
static void *ngx_http_auth_digest_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_digest_merge_loc_conf(ngx_conf_t *cf,void *parent, void *child);
static ngx_int_t ngx_http_auth_digest_init(ngx_conf_t *cf);
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
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
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
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_auth_digest_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_digest_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_digest_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->timeout = NGX_CONF_UNSET_UINT;
    conf->expires = NGX_CONF_UNSET_UINT;
    conf->replays = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_auth_digest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_digest_loc_conf_t  *prev = parent;
    ngx_http_auth_digest_loc_conf_t  *conf = child;

    ngx_conf_merge_sec_value(conf->timeout, prev->timeout, 60);
    ngx_conf_merge_sec_value(conf->expires, prev->expires, 10);
    ngx_conf_merge_value(conf->replays, prev->replays, 20);
    ngx_conf_merge_str_value(conf->realm, prev->realm, "")

    if (conf->user_file.value.len == 0) {
        conf->user_file = prev->user_file;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_digest_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_str_t                  *shm_name;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_digest_handler;    
    
    shm_name = ngx_palloc(cf->pool, sizeof *shm_name);
    shm_name->len = sizeof("auth_digest");
    shm_name->data = (unsigned char *) "auth_digest";

    if (ngx_http_auth_digest_shm_size == 0) {
        ngx_http_auth_digest_shm_size = 128 * ngx_pagesize; // default to 512k
    }

    ngx_http_auth_digest_shm_zone = ngx_shared_memory_add(
        cf, shm_name, ngx_http_auth_digest_shm_size, &ngx_http_auth_digest_module);
    if (ngx_http_auth_digest_shm_zone == NULL) {
        return NGX_ERROR;
    }
    ngx_http_auth_digest_shm_zone->init = ngx_http_auth_digest_init_shm_zone;

    return NGX_OK;
}


static char *
ngx_http_auth_digest(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *realm = data; // i.e., first field of ngx_http_auth_digest_loc_conf_t
    if (ngx_strcmp(realm->data, "off") == 0) {
        ngx_str_set(realm, "");
        return NGX_CONF_OK;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_digest_handler(ngx_http_request_t *r)
{
    off_t                            offset;
    ssize_t                          n;
    ngx_fd_t                         fd;
    ngx_int_t                        rc;
    ngx_err_t                        err;
    ngx_str_t                        user_file, passwd_line;
    ngx_uint_t                       i, level, login, left, passwd, realm, hash;
    ngx_file_t                       file;
    ngx_http_auth_digest_loc_conf_t *alcf;
    ngx_http_auth_digest_cred_t     *auth_fields;
    u_char                           buf[NGX_HTTP_AUTH_BUF_SIZE];
    enum {
        sw_login,
        sw_passwd,
        sw_realm,
        sw_skip
    } state;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_digest_module);
    if (alcf->realm.len == 0 || alcf->user_file.value.len == 0) {
        return NGX_DECLINED;
    }

    // is it insane to run this (blocking) full-tree crawl on every request?
    // what's the alternative, a timer?
    ngx_http_auth_digest_rbtree_prune(r);

    auth_fields = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_digest_cred_t));
    rc = ngx_http_auth_digest_user(r, auth_fields);

    if (rc==NGX_DECLINED || rc==NGX_STALE) {
      // no authorization header or using a stale nonce, send a new challenge
      return ngx_http_auth_digest_send_challenge(r, &alcf->realm, rc==NGX_STALE);
    }

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }


    // check and read in the passwd file from disk
    if (ngx_http_complex_value(r, &alcf->user_file, &user_file) != NGX_OK) {
        return NGX_ERROR;
    }

    fd = ngx_open_file(user_file.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        err = ngx_errno;

        if (err == NGX_ENOENT) {
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;

        } else {
            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_error(level, r->connection->log, err,
                      ngx_open_file_n " \"%s\" failed", user_file.data);

        return rc;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));

    file.fd = fd;
    file.name = user_file;
    file.log = r->connection->log;

    state = sw_login;
    passwd = 0;
    hash = 0;
    realm = 0;
    login = 0;
    left = 0;
    offset = 0;


    // parse through the passwd file and find the individual lines, then pass them off 
    // to be compared against the values in the authentication header
    while (1){
      n = ngx_read_file(&file, buf+left, NGX_HTTP_AUTH_BUF_SIZE-left, offset);
    
      if (n==0){
        buf[left+n] = '\0';
        ngx_str_t remain;
        remain.len = left+n;
        remain.data = buf;

        rc = ngx_http_auth_digest_passwd_handler(r, auth_fields, &remain);
        if (rc){
          ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "user \"%V\" found in realm \"%V\" (%V)",
                        &auth_fields->username, &auth_fields->realm, &user_file);
          return NGX_OK;
        }
        break;
      }
    
      if (n == NGX_ERROR) {
        ngx_http_auth_digest_close(&file);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }
    
      left = 0;
      for (i=left; i<(ngx_uint_t)n; i++){
        if (i==left && (buf[i]==CR||buf[i]==LF||buf[i]=='\0')){
          left++;
          continue;
        }
        
        if (buf[i] == CR || buf[i] == LF){
          u_char *p;
          passwd_line.len = i - left + 1;
          passwd_line.data = ngx_pcalloc(r->pool, passwd_line.len);
          if (passwd_line.data==NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
          p = ngx_cpymem(passwd_line.data, &buf[left], i-left);
          
          rc = ngx_http_auth_digest_passwd_handler(r, auth_fields, &passwd_line);
          if (rc){
            // success! found a matching user with the same password, so let the
            // request handling pipeline proceed
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "user \"%V\" found in realm \"%V\" (%V)",
                          &auth_fields->username, &auth_fields->realm, &user_file);
            return NGX_OK;
          }
          left = i+1;
        }
      }
      
      if (left<=(ngx_uint_t)n){
        ngx_memmove(buf, &buf[left], n-left);
        left = n-left;
      }else{
        left = 0;
      }
      offset+=n;
    }
    ngx_http_auth_digest_close(&file);
    
    // no match was found based on the fields in the authentication header.
    // send a new challenge and let the client retry
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "user \"%V\" not found (%V)",
                  &auth_fields->username, &user_file);
    return ngx_http_auth_digest_send_challenge(r, &alcf->realm, 0);
}


ngx_int_t
ngx_http_auth_digest_user(ngx_http_request_t *r, ngx_http_auth_digest_cred_t *ctx){
    ngx_str_t encoded;
    ngx_int_t missing;
    if (r->headers_in.authorization == NULL) {
        // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no auth header");
        return NGX_DECLINED;
    }

    encoded = r->headers_in.authorization->value;
    missing = 0;
    missing += ngx_http_auth_digest_decode_auth(r, &encoded, "username", &ctx->username);
    missing += ngx_http_auth_digest_decode_auth(r, &encoded, "qop", &ctx->qop);
    missing += ngx_http_auth_digest_decode_auth(r, &encoded, "realm", &ctx->realm);
    missing += ngx_http_auth_digest_decode_auth(r, &encoded, "nonce", &ctx->nonce);
    missing += ngx_http_auth_digest_decode_auth(r, &encoded, "nc", &ctx->nc);
    missing += ngx_http_auth_digest_decode_auth(r, &encoded, "uri", &ctx->uri);
    missing += ngx_http_auth_digest_decode_auth(r, &encoded, "cnonce", &ctx->cnonce);
    missing += ngx_http_auth_digest_decode_auth(r, &encoded, "response", &ctx->response);
    ngx_http_auth_digest_decode_auth(r, &encoded, "opaque", &ctx->opaque); // (optional/ignored)

    // bail out if anything but the opaque field is missing from the request header
    if (missing>0 || ctx->nonce.len!=17) return NGX_DECLINED;

    ngx_http_auth_digest_nonce_t nonce;
    ngx_uint_t                   key;
    ngx_http_auth_digest_node_t *found;
    ngx_slab_pool_t             *shpool;
    ngx_http_auth_digest_loc_conf_t  *alcf;
    
    shpool = (ngx_slab_pool_t *)ngx_http_auth_digest_shm_zone->shm.addr;
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_digest_module);

    nonce.rnd = ngx_hextoi(ctx->nonce.data, 8);
    nonce.t = ngx_hextoi(&ctx->nonce.data[8], 8);
    key = ngx_crc32_short((u_char *) &nonce.rnd, sizeof nonce.rnd) ^
          ngx_crc32_short((u_char *) &nonce.t, sizeof(nonce.t));
    int nc = ngx_atoi(ctx->nc.data, ctx->nc.len-1);

    ngx_shmtx_lock(&shpool->mutex);
    found = (ngx_http_auth_digest_node_t *)ngx_http_auth_digest_rbtree_find(key, ngx_http_auth_digest_rbtree->root, ngx_http_auth_digest_rbtree->sentinel);
    ngx_shmtx_unlock(&shpool->mutex);
    
    if (nc<0 || nc>=alcf->replays){ 
      // nonce has gone stale
      return NGX_STALE;
    }
    if (found==NULL){ 
      // nonce has alread expired (or was never issued)
      return NGX_DECLINED;
    }
      
    if (ngx_bitvector_test(found->nc, nc)){
      // if this is the first use of this nonce, switch the expiration time from the timeout
      // param to now+expires. using the 0th element of the nc vector to flag this...
      if (ngx_bitvector_test(found->nc, 0)){
        ngx_bitvector_set(found->nc, 0);
        found->expires = ngx_time() + alcf->expires;
      }
      ngx_bitvector_set(found->nc, nc);
      // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "good nc %s",buf);
      return NGX_OK;
    }else{
      // client reused an nc value. suspicious...
      return NGX_DECLINED;
    }      
}

static ngx_inline ngx_int_t 
ngx_http_auth_digest_decode_auth(ngx_http_request_t *r, ngx_str_t *auth_str, char *field_name, ngx_str_t *field_val){
  ngx_str_t key;
  u_char *start, *last, *p;

  key.len = ngx_strlen(field_name) + 2;
  key.data = ngx_pcalloc(r->pool, key.len);
  p = ngx_sprintf(key.data,"%s=", field_name);
  
  start = (u_char *) ngx_strstr(auth_str->data, key.data);
  if (start==NULL){
    field_val->len = 1;
    field_val->data = ngx_pcalloc(r->pool, 1);
    return 1;
  }
  
  start += key.len-1;
  if (*start=='"'){
    start++;
    last = (u_char *) ngx_strstr(start+1, "\"");
  }else{
    last = (u_char *) ngx_strstr(start+1, ",");
  }
  if (last==NULL) last = auth_str->data + auth_str->len;
  if (last>start){        
    field_val->len = last-start + 1;
    field_val->data = ngx_pcalloc(r->pool, field_val->len);
    p = ngx_cpymem(field_val->data, start, last-start);
  }
  
  return 0;
}

static ngx_int_t
ngx_http_auth_digest_passwd_handler(ngx_http_request_t *r, ngx_http_auth_digest_cred_t *fields, ngx_str_t *line){
  ngx_str_t HA1;
  ngx_uint_t i, from;
  enum {
      sw_login,
      sw_ha1,
      sw_realm
  } state;
  u_char *p;

  state = sw_login;
  from = 0;
  
  ngx_str_t orig;
  orig.len = line->len;
  orig.data = ngx_pcalloc(r->pool, orig.len+1);
  if (orig.data==NULL){
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  p = ngx_cpymem(orig.data, line->data, line->len);
  
  
  // parse through a single line, matching the username and realm character-by-character
  // against the authentication header fields
  u_char *buf = line->data;
  for (i=0; i<=line->len; i++){
    switch(state){
      if (buf[i]=='#' && state!=sw_ha1) return 0;
      
      case sw_login:
        
        if (buf[i]==':'){
          if (fields->username.len-1 != i) return 0;
          state=sw_realm;
          from=i+1;
        }else if (i>fields->username.len-1 || buf[i] != fields->username.data[i]){
          return 0;
        }
        break;
      
      case sw_realm:
        if (buf[i]==':'){
          if (fields->realm.len-1 != i-from) return 0; 
          state=sw_ha1;
          from=i+1;
        }else if (buf[i] != fields->realm.data[i-from]){
          return 0;
        }
        break;

      case sw_ha1:
        if (buf[i]=='\0' || buf[i]==':' || buf[i]=='#' || buf[i]==CR || buf[i]==LF){
          if (i-from != 32) return 0;
          
          HA1.len = 33;
          HA1.data = ngx_pcalloc(r->pool, HA1.len);
          if (HA1.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
          }
          p = ngx_cpymem(HA1.data, &buf[from], 32);

          // now ‘just’ do the hashing and if it matches up return 1 else 0
          return ngx_http_auth_digest_verify(r, fields, &HA1);
        }
        break;      
    }
    
  }
  

  return 1;
}

static ngx_int_t
ngx_http_auth_digest_verify(ngx_http_request_t *r, ngx_http_auth_digest_cred_t *fields, ngx_str_t *HA1)
{
  //
  //  digest: MD5(MD5(username:realm:password):nonce:nc:cnonce:qop:MD5(method:uri))
  // 
  //     ha1: md5(username:realm:password) or password-hash
  //     ha2: md5(method:uri)
  //     qop: md5(ha1:nonce:nc:cnonce:qop:ha2)
  //       
  //  verify: fields->response == digest(hashed_pw)
  // 

  u_char      *p;
  ngx_str_t    http_method;
  ngx_str_t    HA2, ha2_key;
  ngx_str_t    digest, digest_key;
  ngx_md5_t    md5;
  u_char       hash[16];

  // ha1 was precalculated and saved to the passwd file: md5(username:realm:password)
  
  // calculate ha2: md5(method:uri)
  http_method.len = r->method_name.len+1;
  http_method.data = ngx_pcalloc(r->pool, http_method.len);
  if (http_method.data==NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;  
  p = ngx_cpymem(http_method.data, r->method_name.data, r->method_end - r->method_name.data+1);
  
  ha2_key.len = http_method.len + r->uri.len + 1;
  ha2_key.data = ngx_pcalloc(r->pool, ha2_key.len);
  if (ha2_key.data==NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
  p = ngx_cpymem(ha2_key.data, http_method.data, http_method.len-1); *p++ = ':';
  p = ngx_cpymem(p, r->uri.data, r->uri.len);

  HA2.len = 33;
  HA2.data = ngx_pcalloc(r->pool, 33);
  ngx_md5_init(&md5);
  ngx_md5_update(&md5, ha2_key.data, ha2_key.len-1);
  ngx_md5_final(hash, &md5);  
  ngx_hex_dump(HA2.data, hash, 16);
  // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "    ha1 md5: (%s)",HA1->data);
  // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "    ha2 md5: (%s)",HA2.data);
  
  // calculate digest: md5(ha1:nonce:nc:cnonce:qop:ha2)
  digest_key.len = HA1->len-1 + fields->nonce.len-1 + fields->nc.len-1 + fields->cnonce.len-1 + fields->qop.len-1 + HA2.len-1 + 5 + 1;
  digest_key.data = ngx_pcalloc(r->pool, digest_key.len);
  if (digest_key.data==NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
  
  p = ngx_cpymem(digest_key.data, HA1->data, HA1->len-1); *p++ = ':';  
  p = ngx_cpymem(p, fields->nonce.data, fields->nonce.len-1); *p++ = ':';
  p = ngx_cpymem(p, fields->nc.data, fields->nc.len-1); *p++ = ':';
  p = ngx_cpymem(p, fields->cnonce.data, fields->cnonce.len-1); *p++ = ':';
  p = ngx_cpymem(p, fields->qop.data, fields->qop.len-1); *p++ = ':';
  p = ngx_cpymem(p, HA2.data, HA2.len-1);  
  // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "  dgt key: (%s) %i",digest_key.data,digest_key.len);


  // compare the hash of the full digest string to the response field of the auth header
  digest.len = 33;
  digest.data = ngx_pcalloc(r->pool, 33);
  ngx_md5_init(&md5);
  ngx_md5_update(&md5, digest_key.data, digest_key.len-1);
  ngx_md5_final(hash, &md5);  
  ngx_hex_dump(digest.data, hash, 16);
  // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "    dst md5: (%s)",digest.data);
  // ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "    request: (%s)",fields->response.data);

  return (ngx_strcmp(digest.data, fields->response.data) == 0);
}


static ngx_int_t
ngx_http_auth_digest_send_challenge(ngx_http_request_t *r, ngx_str_t *realm, ngx_uint_t is_stale)
{
    ngx_str_t challenge;
    u_char *p;
    
    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    
    challenge.len = sizeof("Digest algorithm=\"MD5\", qop=\"auth\", realm=\"\", nonce=\"\"") - 1 + realm->len + 16;
    if (is_stale) challenge.len += sizeof(", stale=\"true\"") - 1;
    challenge.data = ngx_pnalloc(r->pool, challenge.len);
    if (challenge.data == NULL) {
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_auth_digest_nonce_t nonce;
    nonce = ngx_http_auth_digest_next_nonce(r);
    if (nonce.t==0 && nonce.rnd==0){
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    p = ngx_cpymem(challenge.data, "Digest algorithm=\"MD5\", qop=\"auth\", realm=\"", sizeof("Digest algorithm=\"MD5\", qop=\"auth\", realm=\"") - 1);
    p = ngx_cpymem(p, realm->data, realm->len);
    p = ngx_cpymem(p, "\", nonce=\"", sizeof("\", nonce=\"") - 1);
    p = ngx_sprintf(p, "%08xl%08xl", nonce.rnd,nonce.t);
                          
    if (is_stale){
      p = ngx_cpymem(p, "\", stale=\"true\"", sizeof("\", stale=\"true\""));
    }else{
      p = ngx_cpymem(p, "\"", sizeof("\""));
    }
    r->headers_out.www_authenticate->value = challenge;

    return NGX_HTTP_UNAUTHORIZED;
}

static void
ngx_http_auth_digest_close(ngx_file_t *file)
{
    if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, file->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", file->name.data);
    }
}


static char *
ngx_http_auth_digest_user_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_digest_loc_conf_t *alcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    if (alcf->user_file.value.len) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &alcf->user_file;
    ccv.zero = 1;
    ccv.conf_prefix = 1;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}



static char *
ngx_http_auth_digest_set_shm_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ssize_t                         new_shm_size;
    ngx_str_t                      *value;

    value = cf->args->elts;

    new_shm_size = ngx_parse_size(&value[1]);
    if (new_shm_size == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Invalid memory area size `%V'", &value[1]);
        return NGX_CONF_ERROR;
    }

    new_shm_size = ngx_align(new_shm_size, ngx_pagesize);

    if (new_shm_size < 8 * (ssize_t) ngx_pagesize) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "The auth_digest_shm_size value must be at least %udKiB", (8 * ngx_pagesize) >> 10);
        new_shm_size = 8 * ngx_pagesize;
    }

    if (ngx_http_auth_digest_shm_size &&
        ngx_http_auth_digest_shm_size != (ngx_uint_t) new_shm_size) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "Cannot change memory area size without restart, ignoring change");
    } else {
        ngx_http_auth_digest_shm_size = new_shm_size;
    }
    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "Using %udKiB of shared memory for auth_digest", new_shm_size >> 10);


    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_auth_digest_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t                *shpool;
    ngx_rbtree_t                   *tree;
    ngx_rbtree_node_t              *sentinel;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    tree = ngx_slab_alloc(shpool, sizeof *tree);
    if (tree == NULL) {
        return NGX_ERROR;
    }

    sentinel = ngx_slab_alloc(shpool, sizeof *sentinel);
    if (sentinel == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(tree, sentinel,
                    ngx_http_auth_digest_rbtree_insert);
    shm_zone->data = tree;
    ngx_http_auth_digest_rbtree = tree;

    return NGX_OK;
}



static int
ngx_http_auth_digest_rbtree_cmp(const ngx_rbtree_node_t *v_left,
    const ngx_rbtree_node_t *v_right)
{
    if (v_left->key == v_right->key) return 0;
    else return (v_left->key < v_right->key) ? -1 : 1;
}

static void
ngx_rbtree_generic_insert(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel,
    int (*compare)(const ngx_rbtree_node_t *left, const ngx_rbtree_node_t *right))
{
    for ( ;; ) {
        if (node->key < temp->key) {

            if (temp->left == sentinel) {
                temp->left = node;
                break;
            }

            temp = temp->left;

        } else if (node->key > temp->key) {

            if (temp->right == sentinel) {
                temp->right = node;
                break;
            }

            temp = temp->right;

        } else { /* node->key == temp->key */
            if (compare(node, temp) < 0) {

                if (temp->left == sentinel) {
                    temp->left = node;
                    break;
                }

                temp = temp->left;

            } else {

                if (temp->right == sentinel) {
                    temp->right = node;
                    break;
                }

                temp = temp->right;
            }
        }
    }

    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static void
ngx_http_auth_digest_rbtree_insert(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel) {

    ngx_rbtree_generic_insert(temp, node, sentinel,
        ngx_http_auth_digest_rbtree_cmp);
}


static ngx_rbtree_node_t *
ngx_http_auth_digest_rbtree_find(ngx_rbtree_key_t key, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel){
  
  if (node==sentinel) return NULL;  
  
  ngx_rbtree_node_t *found = (node->key==key) ? node : NULL;
  if (found==NULL && node->left != sentinel){
    found = ngx_http_auth_digest_rbtree_find(key, node->left, sentinel);
  }
  if (found==NULL && node->right != sentinel){
    found = ngx_http_auth_digest_rbtree_find(key, node->right, sentinel);
  }

  return found;
}

static void ngx_http_auth_digest_rbtree_prune(ngx_http_request_t *r){
  time_t now = ngx_time();
  ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)ngx_http_auth_digest_shm_zone->shm.addr;  
  ngx_shmtx_lock(&shpool->mutex);
  ngx_http_auth_digest_rbtree_prune_walk(ngx_http_auth_digest_rbtree->root, ngx_http_auth_digest_rbtree->sentinel, now, r->connection->log);
  ngx_shmtx_unlock(&shpool->mutex);
}

static void ngx_http_auth_digest_rbtree_prune_walk(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, time_t now, ngx_log_t *log){
  if (node==sentinel) return;  
  ngx_http_auth_digest_node_t *dnode = (ngx_http_auth_digest_node_t*) node;

  if (node->left != sentinel){
    ngx_http_auth_digest_rbtree_prune_walk(node->left, sentinel, now, log);
  }
  
  if (node->right != sentinel){
    ngx_http_auth_digest_rbtree_prune_walk(node->right, sentinel, now, log);
  }
  
  if (dnode->expires < now){
    ngx_log_error(NGX_LOG_ERR, log, 0,
                  "expire: %08xul t:%i", node->key, dnode->expires-now);
    
    ngx_slab_pool_t *shpool;
    shpool = (ngx_slab_pool_t *)ngx_http_auth_digest_shm_zone->shm.addr;
    ngx_rbtree_delete(ngx_http_auth_digest_rbtree, node);
    ngx_slab_free_locked(shpool, dnode);
  }  
}


static ngx_http_auth_digest_nonce_t ngx_http_auth_digest_next_nonce(ngx_http_request_t *r){
  ngx_http_auth_digest_loc_conf_t  *alcf;
  ngx_slab_pool_t             *shpool;
  ngx_http_auth_digest_nonce_t nonce;
  ngx_uint_t                   key;
  ngx_http_auth_digest_node_t *node;  
  
  shpool = (ngx_slab_pool_t *)ngx_http_auth_digest_shm_zone->shm.addr;
  alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_digest_module);

  // create a nonce value that's not in the active set
  while(1){
    nonce.t = ngx_time();
    nonce.rnd = ngx_random();
    key = ngx_crc32_short((u_char *) &nonce.rnd, sizeof nonce.rnd) ^
          ngx_crc32_short((u_char *) &nonce.t, sizeof(nonce.t));
          
    ngx_shmtx_lock(&shpool->mutex);
    ngx_rbtree_node_t *found = ngx_http_auth_digest_rbtree_find(key, ngx_http_auth_digest_rbtree->root, ngx_http_auth_digest_rbtree->sentinel);

    if (found!=NULL){
      ngx_shmtx_unlock(&shpool->mutex);
      continue;
    }

    node = ngx_slab_alloc_locked(shpool, sizeof(ngx_http_auth_digest_node_t) + ngx_bitvector_size(1+alcf->replays));
    if (node==NULL){
      // this is not at all sufficient error handling. So long as there's no free space in the
      // shm segment, requests like this will trigger a 401 response even if the client sent
      // the proper credentials. a.k.a. DoS city...
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "auth_digest ran out of shm space");
      nonce.t = 0;
      nonce.rnd = 0;
      return nonce;
    }
    node->expires = nonce.t + alcf->timeout;
    ngx_memset(node->nc, 0xff, ngx_bitvector_size(1+alcf->replays));
    ((ngx_rbtree_node_t *)node)->key = key;   
    ngx_rbtree_insert(ngx_http_auth_digest_rbtree, &node->node);

    ngx_shmtx_unlock(&shpool->mutex);
    return nonce;
  }
    
}

// quick & dirty bitvectors for holding the nc usage record
#define BITMASK(b) (1 << ((b) % CHAR_BIT))
#define BITSLOT(b) ((b) / CHAR_BIT)
#define BITSET(a, b) ((a)[BITSLOT(b)] |= BITMASK(b))
#define BITCLEAR(a, b) ((a)[BITSLOT(b)] &= ~BITMASK(b))
#define BITTEST(a, b) ((a)[BITSLOT(b)] & BITMASK(b))
#define BITNSLOTS(nb) ((nb + CHAR_BIT - 1) / CHAR_BIT)
static ngx_uint_t ngx_bitvector_size(ngx_uint_t nbits){ return BITNSLOTS(nbits); }
static ngx_uint_t ngx_bitvector_test(char *bv, ngx_uint_t bit){ return BITTEST(bv, bit); }
static void ngx_bitvector_set(char *bv, ngx_uint_t bit){ BITCLEAR(bv, bit); }

