
/*
 * copyright (c) samizdat drafting co.
 * derived from http_auth_basic (c) igor sysoev
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include "ngx_http_auth_digest_module.h"


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
  
    if (conf->realm.len>0 && conf->user_file.value.len == 0){
      ngx_log_error(NGX_LOG_ERR, cf->log, 0,"auth_digest enabled but auth_digest_user_file not specified");
      return NGX_CONF_ERROR;
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

    ngx_http_auth_digest_cleanup_timer = ngx_pcalloc(cf->pool, sizeof(ngx_event_t));
    if (ngx_http_auth_digest_cleanup_timer == NULL) {
        return NGX_ERROR;
    }
    
    shm_name = ngx_palloc(cf->pool, sizeof *shm_name);
    shm_name->len = sizeof("auth_digest");
    shm_name->data = (unsigned char *) "auth_digest";

    if (ngx_http_auth_digest_shm_size == 0) {
        ngx_http_auth_digest_shm_size = 4 * 256 * ngx_pagesize; // default to 4mb
    }

    ngx_http_auth_digest_shm_zone = ngx_shared_memory_add(
        cf, shm_name, ngx_http_auth_digest_shm_size, &ngx_http_auth_digest_module);
    if (ngx_http_auth_digest_shm_zone == NULL) {
        return NGX_ERROR;
    }
    ngx_http_auth_digest_shm_zone->init = ngx_http_auth_digest_init_shm_zone;

    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_digest_worker_init(ngx_cycle_t *cycle){      
  if (ngx_process != NGX_PROCESS_WORKER){
     return NGX_OK;
  }

  // create a cleanup queue big enough for the max number of tree nodes in the shm
  ngx_http_auth_digest_cleanup_list = ngx_array_create(cycle->pool, 
                                                      NGX_HTTP_AUTH_DIGEST_CLEANUP_BATCH_SIZE, 
                                                      sizeof(ngx_rbtree_node_t *));                                            
  if (ngx_http_auth_digest_cleanup_list==NULL){
    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Could not allocate shared memory for auth_digest");
    return NGX_ERROR;          
  }
  
  ngx_connection_t  *dummy;
  dummy = ngx_pcalloc(cycle->pool, sizeof(ngx_connection_t));
  if (dummy == NULL) return NGX_ERROR;
  dummy->fd = (ngx_socket_t) -1;
  dummy->data = cycle;
  
  ngx_http_auth_digest_cleanup_timer->log = ngx_cycle->log;
  ngx_http_auth_digest_cleanup_timer->data = dummy;
  ngx_http_auth_digest_cleanup_timer->handler = ngx_http_auth_digest_cleanup;
  ngx_add_timer(ngx_http_auth_digest_cleanup_timer, NGX_HTTP_AUTH_DIGEST_CLEANUP_INTERVAL);
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
    ngx_file_t                       file;
    ngx_uint_t                       i, begin, tail, idle;
    ngx_http_auth_digest_loc_conf_t *alcf;
    ngx_http_auth_digest_cred_t     *auth_fields;
    u_char                           buf[NGX_HTTP_AUTH_DIGEST_BUF_SIZE];
    u_char                           line[NGX_HTTP_AUTH_DIGEST_BUF_SIZE];
    u_char                          *p;


    // if digest auth is disabled for this location, bail out immediately
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_digest_module);
    if (alcf->realm.len == 0 || alcf->user_file.value.len == 0) {
        return NGX_DECLINED;
        
        //
        // BUG? wait wait wait. shouldn't this be ngx_ok by default in the case
        //      of the former and ngx_declined in the latter?
        //
        
    }

    // unpack the Authorization header (if any) and verify that it contains all
    // required fields. otherwise send a challenge
    auth_fields = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_digest_cred_t));
    rc = ngx_http_auth_digest_check_credentials(r, auth_fields);
    if (rc==NGX_DECLINED) {
      return ngx_http_auth_digest_send_challenge(r, &alcf->realm, 0);
    }else if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // check for the existence of a passwd file and attempt to open it
    if (ngx_http_complex_value(r, &alcf->user_file, &user_file) != NGX_OK) {
        return NGX_ERROR;
    }
    fd = ngx_open_file(user_file.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_uint_t level;
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

    // step through the passwd file and find the individual lines, then pass them off 
    // to be compared against the values in the authorization header
    passwd_line.data = line;
    offset = begin = tail = 0;
    idle = 1;
    ngx_memzero(buf, NGX_HTTP_AUTH_DIGEST_BUF_SIZE);
    ngx_memzero(passwd_line.data, NGX_HTTP_AUTH_DIGEST_BUF_SIZE);
    while (1){
      n = ngx_read_file(&file, buf+tail, NGX_HTTP_AUTH_DIGEST_BUF_SIZE-tail, offset);      
      if (n == NGX_ERROR) {
        ngx_http_auth_digest_close(&file);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
      }
      
      begin = 0;
      for (i=0; i<n+tail; i++){
        if (buf[i] == '\n' || buf[i] == '\r'){
          if (!idle && i-begin>36){ // 36 is the min length with a single-char name and realm
            p = ngx_cpymem(passwd_line.data, &buf[begin], i-begin);
            p[0] = '\0';
            passwd_line.len = i-begin;
            rc = ngx_http_auth_digest_verify_user(r, auth_fields, &passwd_line);
            if (rc != NGX_DECLINED){
              ngx_http_auth_digest_close(&file);
              return rc;
            }
          }
          idle = 1;
          begin = i;
        }else if(idle){
          idle = 0;
          begin = i;
        }
      }
    
      if (!idle){
        tail = n + tail - begin;
        if (n==0 && tail>36){
          p = ngx_cpymem(passwd_line.data, &buf[begin], tail);
          p[0] = '\0';
          passwd_line.len = i-begin;
          rc = ngx_http_auth_digest_verify_user(r, auth_fields, &passwd_line);
          if (rc != NGX_DECLINED){
            ngx_http_auth_digest_close(&file);
            return rc;
          }                        
        }else{
          ngx_memmove(buf, &buf[begin], tail);
        }
      }
    
      if (n==0){
          break;
      }      
      
      offset += n;
    }

    ngx_http_auth_digest_close(&file);
    
    // since no match was found based on the fields in the authorization header,
    // send a new challenge and let the client retry
    return ngx_http_auth_digest_send_challenge(r, &alcf->realm, auth_fields->stale);
}


ngx_int_t
ngx_http_auth_digest_check_credentials(ngx_http_request_t *r, ngx_http_auth_digest_cred_t *ctx){
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

    return NGX_OK;
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
ngx_http_auth_digest_verify_user(ngx_http_request_t *r, ngx_http_auth_digest_cred_t *fields, ngx_str_t *line){
  ngx_uint_t i, from, nomatch;
  enum {
      sw_login,
      sw_ha1,
      sw_realm
  } state;

  state = sw_login;
  from = 0;
  nomatch = 0;
  
  // step through a single line (of the passwd file), matching the username and realm 
  // character-by-character against the request's Authorization header fields
  u_char *buf = line->data;
  for (i=0; i<=line->len; i++){
    u_char ch = buf[i];

    switch(state){      
      case sw_login:
        if (ch=='#') nomatch = 1;
        if (ch==':'){
          if (fields->username.len-1 != i) nomatch = 1;
          state=sw_realm;
          from=i+1;
        }else if (i>fields->username.len-1 || ch != fields->username.data[i]){
          nomatch = 1;
        }
        break;
      
      case sw_realm:
        if (ch=='#') nomatch = 1;
        if (ch==':'){
          if (fields->realm.len-1 != i-from) nomatch = 1; 
          state=sw_ha1;
          from=i+1;
        }else if (ch != fields->realm.data[i-from]){
          nomatch = 1;
        }
        break;

      case sw_ha1:
        if (ch=='\0' || ch==':' || ch=='#' || ch==CR || ch==LF){
          if (i-from != 32) nomatch = 1;          
        }
        break;      
    }
  }
  
  return (nomatch) ? NGX_DECLINED : ngx_http_auth_digest_verify_hash(r, fields, &buf[from]);
}

static ngx_int_t
ngx_http_auth_digest_verify_hash(ngx_http_request_t *r, ngx_http_auth_digest_cred_t *fields, u_char *hashed_pw)
{
  u_char      *p;
  ngx_str_t    http_method;
  ngx_str_t    HA1, HA2, ha2_key;
  ngx_str_t    digest, digest_key;
  ngx_md5_t    md5;
  u_char       hash[16];

  //  the hashing scheme:
  //    digest: MD5(MD5(username:realm:password):nonce:nc:cnonce:qop:MD5(method:uri))
  //                ^- HA1                                           ^- HA2
  //    verify: fields->response == MD5($hashed_pw:nonce:nc:cnonce:qop:MD5(method:uri))

  // ha1 was precalculated and saved to the passwd file: md5(username:realm:password)
  HA1.len = 33;
  HA1.data = ngx_pcalloc(r->pool, HA1.len);
  p = ngx_cpymem(HA1.data, hashed_pw, 32);
  
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
  HA2.data = ngx_pcalloc(r->pool, HA2.len);
  ngx_md5_init(&md5);
  ngx_md5_update(&md5, ha2_key.data, ha2_key.len-1);
  ngx_md5_final(hash, &md5);  
  ngx_hex_dump(HA2.data, hash, 16);
  
  // calculate digest: md5(ha1:nonce:nc:cnonce:qop:ha2)
  digest_key.len = HA1.len-1 + fields->nonce.len-1 + fields->nc.len-1 + fields->cnonce.len-1 + fields->qop.len-1 + HA2.len-1 + 5 + 1;
  digest_key.data = ngx_pcalloc(r->pool, digest_key.len);
  if (digest_key.data==NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
  
  p = ngx_cpymem(digest_key.data, HA1.data, HA1.len-1); *p++ = ':';  
  p = ngx_cpymem(p, fields->nonce.data, fields->nonce.len-1); *p++ = ':';
  p = ngx_cpymem(p, fields->nc.data, fields->nc.len-1); *p++ = ':';
  p = ngx_cpymem(p, fields->cnonce.data, fields->cnonce.len-1); *p++ = ':';
  p = ngx_cpymem(p, fields->qop.data, fields->qop.len-1); *p++ = ':';
  p = ngx_cpymem(p, HA2.data, HA2.len-1);  

  digest.len = 33;
  digest.data = ngx_pcalloc(r->pool, 33);
  if (digest.data==NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
  ngx_md5_init(&md5);
  ngx_md5_update(&md5, digest_key.data, digest_key.len-1);
  ngx_md5_final(hash, &md5);  
  ngx_hex_dump(digest.data, hash, 16);

  // compare the hash of the full digest string to the response field of the auth header
  // and bail out if they don't match
  if (ngx_strcmp(digest.data, fields->response.data) != 0) return NGX_DECLINED;
  
  ngx_http_auth_digest_nonce_t     nonce;
  ngx_uint_t                       key;
  ngx_http_auth_digest_node_t     *found;
  ngx_slab_pool_t                 *shpool;
  ngx_http_auth_digest_loc_conf_t *alcf;
  ngx_table_elt_t                 *info_header;
  ngx_str_t                        hkey, hval;
  
  shpool = (ngx_slab_pool_t *)ngx_http_auth_digest_shm_zone->shm.addr;
  alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_digest_module);
  nonce.rnd = ngx_hextoi(fields->nonce.data, 8);
  nonce.t = ngx_hextoi(&fields->nonce.data[8], 8);
  key = ngx_crc32_short((u_char *) &nonce.rnd, sizeof nonce.rnd) ^
        ngx_crc32_short((u_char *) &nonce.t, sizeof(nonce.t));

  int nc = ngx_atoi(fields->nc.data, fields->nc.len-1);
  if (nc<0 || nc>=alcf->replays){ 
    fields->stale = 1;    
    return NGX_DECLINED; 
  }

  // make sure nonce and nc are both valid
  ngx_shmtx_lock(&shpool->mutex);    
  found = (ngx_http_auth_digest_node_t *)ngx_http_auth_digest_rbtree_find(key, ngx_http_auth_digest_rbtree->root, ngx_http_auth_digest_rbtree->sentinel);
  if (found!=NULL && ngx_bitvector_test(found->nc, nc)){    
    if (ngx_bitvector_test(found->nc, 0)){
      // if this is the first use of this nonce, switch the expiration time from the timeout
      // param to now+expires. using the 0th element of the nc vector to flag this...
      ngx_bitvector_set(found->nc, 0);
      found->expires = ngx_time() + alcf->expires;
    }
    
    // mark this nc as ‘used’ to prevent replays 
    ngx_bitvector_set(found->nc, nc);

    
    // todo: if the bitvector is now ‘full’, could preemptively expire the node from the rbtree
    // ngx_rbtree_delete(ngx_http_auth_digest_rbtree, found);
    // ngx_slab_free_locked(shpool, found);


    
    ngx_shmtx_unlock(&shpool->mutex);
    
    // recalculate the digest with a modified HA2 value (for rspauth) and emit the
    // Authentication-Info header    
    ngx_memset(ha2_key.data, 0, ha2_key.len);
    p = ngx_sprintf(ha2_key.data, ":%s", r->uri.data);

    ngx_memset(HA2.data, 0, HA2.len);
    ngx_md5_init(&md5);
    ngx_md5_update(&md5, ha2_key.data, r->uri.len);
    ngx_md5_final(hash, &md5);  
    ngx_hex_dump(HA2.data, hash, 16);

    ngx_memset(digest_key.data, 0, digest_key.len);
    p = ngx_cpymem(digest_key.data, HA1.data, HA1.len-1); *p++ = ':';  
    p = ngx_cpymem(p, fields->nonce.data, fields->nonce.len-1); *p++ = ':';
    p = ngx_cpymem(p, fields->nc.data, fields->nc.len-1); *p++ = ':';
    p = ngx_cpymem(p, fields->cnonce.data, fields->cnonce.len-1); *p++ = ':';
    p = ngx_cpymem(p, fields->qop.data, fields->qop.len-1); *p++ = ':';
    p = ngx_cpymem(p, HA2.data, HA2.len-1);  

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, digest_key.data, digest_key.len-1);
    ngx_md5_final(hash, &md5);  
    ngx_hex_dump(digest.data, hash, 16);
    
    ngx_str_set(&hkey, "Authentication-Info");
    hval.len = sizeof("qop=\"auth\", rspauth=\"\", cnonce=\"\", nc=") + fields->cnonce.len + fields->nc.len + digest.len;
    hval.data = ngx_pcalloc(r->pool, hval.len);
    if (hval.data==NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    p = ngx_sprintf(hval.data, "qop=\"auth\", rspauth=\"%s\", cnonce=\"%s\", nc=%s", digest.data, fields->cnonce.data, fields->nc.data);
    
    info_header = ngx_list_push(&r->headers_out.headers);
    if (info_header == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;    
    info_header->key = hkey;
    info_header->value = hval;
    info_header->hash = 1;
    return NGX_OK;
  }else{
    // nonce is invalid/expired or client reused an nc value. suspicious...
    ngx_shmtx_unlock(&shpool->mutex);
    return NGX_DECLINED;
  }      
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
      // oom error when allocating nonce session in rbtree
      return NGX_HTTP_SERVICE_UNAVAILABLE;
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
    ngx_atomic_t                   *lock;
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


    lock = ngx_slab_alloc(shpool, sizeof(ngx_atomic_t));
    if (lock == NULL) {
        return NGX_ERROR;
    }
    ngx_http_auth_digest_cleanup_lock = lock;

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

void ngx_http_auth_digest_cleanup(ngx_event_t *ev){
  if (ev->timer_set) ngx_del_timer(ev);
  ngx_add_timer(ev, NGX_HTTP_AUTH_DIGEST_CLEANUP_INTERVAL);  
 
  if (ngx_trylock(ngx_http_auth_digest_cleanup_lock)){
    ngx_http_auth_digest_rbtree_prune(ev->log);
    ngx_unlock(ngx_http_auth_digest_cleanup_lock);    
  }  
}

static void ngx_http_auth_digest_rbtree_prune(ngx_log_t *log){
  ngx_uint_t i;
  time_t now = ngx_time();
  ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)ngx_http_auth_digest_shm_zone->shm.addr;  

  ngx_shmtx_lock(&shpool->mutex);
  ngx_http_auth_digest_cleanup_list->nelts = 0;  
  ngx_http_auth_digest_rbtree_prune_walk(ngx_http_auth_digest_rbtree->root, ngx_http_auth_digest_rbtree->sentinel, now, log);

  ngx_rbtree_node_t **elts = (ngx_rbtree_node_t **)ngx_http_auth_digest_cleanup_list->elts;
  for (i=0; i<ngx_http_auth_digest_cleanup_list->nelts; i++){
    ngx_rbtree_delete(ngx_http_auth_digest_rbtree, elts[i]);
    ngx_slab_free_locked(shpool, elts[i]);
  }
  ngx_shmtx_unlock(&shpool->mutex);

  // if the cleanup array grew during the run, shrink it back down
  if (ngx_http_auth_digest_cleanup_list->nalloc > NGX_HTTP_AUTH_DIGEST_CLEANUP_BATCH_SIZE){
    ngx_array_t *old_list = ngx_http_auth_digest_cleanup_list;
    ngx_array_t *new_list = ngx_array_create(old_list->pool, NGX_HTTP_AUTH_DIGEST_CLEANUP_BATCH_SIZE, sizeof(ngx_rbtree_node_t *));
    if (new_list!=NULL){
      ngx_array_destroy(old_list);
      ngx_http_auth_digest_cleanup_list = new_list;
    }else{
      ngx_log_error(NGX_LOG_ERR, log, 0, "auth_digest ran out of cleanup space");
    }
  }
  
}

static void ngx_http_auth_digest_rbtree_prune_walk(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, time_t now, ngx_log_t *log){
  if (node==sentinel) return;  

  if (node->left != sentinel){
    ngx_http_auth_digest_rbtree_prune_walk(node->left, sentinel, now, log);
  }
  
  if (node->right != sentinel){
    ngx_http_auth_digest_rbtree_prune_walk(node->right, sentinel, now, log);
  }
  
  ngx_http_auth_digest_node_t *dnode = (ngx_http_auth_digest_node_t*) node;
  if (dnode->expires <= ngx_time()){
    ngx_rbtree_node_t **dropnode = ngx_array_push(ngx_http_auth_digest_cleanup_list);
    dropnode[0] = node;
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
      ngx_shmtx_unlock(&shpool->mutex);
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "auth_digest ran out of shm space. Increase the auth_digest_shm_size limit.");
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


