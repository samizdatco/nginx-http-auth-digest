
/*
 * copyright (c) Erik Dubbelboer
 * fork from nginx-http-auth-digest (c) samizdat drafting co.
 * derived from http_auth_basic (c) igor sysoev
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>

#include "ngx_http_auth_digest_module.h"

static void *ngx_http_auth_digest_create_loc_conf(ngx_conf_t *cf) {
  ngx_http_auth_digest_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_digest_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  conf->timeout = NGX_CONF_UNSET_UINT;
  conf->expires = NGX_CONF_UNSET_UINT;
  conf->drop_time = NGX_CONF_UNSET_UINT;
  conf->replays = NGX_CONF_UNSET_UINT;
  conf->evasion_time = NGX_CONF_UNSET_UINT;
  conf->maxtries = NGX_CONF_UNSET_UINT;
  return conf;
}

static char *ngx_http_auth_digest_merge_loc_conf(ngx_conf_t *cf, void *parent,
                                                 void *child) {
  ngx_http_auth_digest_loc_conf_t *prev = parent;
  ngx_http_auth_digest_loc_conf_t *conf = child;

  ngx_conf_merge_sec_value(conf->timeout, prev->timeout, 60);
  ngx_conf_merge_sec_value(conf->expires, prev->expires, 10);
  ngx_conf_merge_sec_value(conf->drop_time, prev->drop_time, 300);
  ngx_conf_merge_value(conf->replays, prev->replays, 20);
  ngx_conf_merge_sec_value(conf->evasion_time, prev->evasion_time, 300);
  ngx_conf_merge_value(conf->maxtries, prev->maxtries, 5);

  if (conf->user_file.value.len == 0) {
    conf->user_file = prev->user_file;
  }

  if (conf->realm.value.len == 0) {
    conf->realm = prev->realm;
  }

  return NGX_CONF_OK;
}

static ngx_int_t ngx_http_auth_digest_init(ngx_conf_t *cf) {
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cmcf;
  ngx_str_t *shm_name;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = ngx_http_auth_digest_handler;

  ngx_http_auth_digest_cleanup_timer =
      ngx_pcalloc(cf->pool, sizeof(ngx_event_t));
  if (ngx_http_auth_digest_cleanup_timer == NULL) {
    return NGX_ERROR;
  }

  shm_name = ngx_palloc(cf->pool, sizeof *shm_name);
  shm_name->len = sizeof("auth_digest");
  shm_name->data = (unsigned char *)"auth_digest";

  if (ngx_http_auth_digest_shm_size == 0) {
    ngx_http_auth_digest_shm_size = 4 * 256 * ngx_pagesize; // default to 4mb
  }

  ngx_http_auth_digest_shm_zone =
      ngx_shared_memory_add(cf, shm_name, ngx_http_auth_digest_shm_size,
                            &ngx_http_auth_digest_module);
  if (ngx_http_auth_digest_shm_zone == NULL) {
    return NGX_ERROR;
  }
  ngx_http_auth_digest_shm_zone->init = ngx_http_auth_digest_init_shm_zone;

  return NGX_OK;
}

static ngx_int_t ngx_http_auth_digest_worker_init(ngx_cycle_t *cycle) {
  if (ngx_process != NGX_PROCESS_WORKER) {
    return NGX_OK;
  }

  // create a cleanup queue big enough for the max number of tree nodes in the
  // shm
  ngx_http_auth_digest_cleanup_list =
      ngx_array_create(cycle->pool, NGX_HTTP_AUTH_DIGEST_CLEANUP_BATCH_SIZE,
                       sizeof(ngx_rbtree_node_t *));

  if (ngx_http_auth_digest_cleanup_list == NULL) {
    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                  "Could not allocate shared memory for auth_digest");
    return NGX_ERROR;
  }

  ngx_connection_t *dummy;
  dummy = ngx_pcalloc(cycle->pool, sizeof(ngx_connection_t));
  if (dummy == NULL)
    return NGX_ERROR;
  dummy->fd = (ngx_socket_t)-1;
  dummy->data = cycle;

  ngx_http_auth_digest_cleanup_timer->log = ngx_cycle->log;
  ngx_http_auth_digest_cleanup_timer->data = dummy;
  ngx_http_auth_digest_cleanup_timer->handler = ngx_http_auth_digest_cleanup;
  ngx_add_timer(ngx_http_auth_digest_cleanup_timer,
                NGX_HTTP_AUTH_DIGEST_CLEANUP_INTERVAL);
  return NGX_OK;
}

static ngx_int_t ngx_http_auth_digest_handler(ngx_http_request_t *r) {
  off_t offset;
  ssize_t n;
  ngx_fd_t fd;
  ngx_int_t rc;
  ngx_err_t err;
  ngx_str_t user_file, passwd_line, realm;
  ngx_file_t file;
  ngx_uint_t i, begin, tail, idle;
  ngx_http_auth_digest_loc_conf_t *alcf;
  ngx_http_auth_digest_cred_t *auth_fields;
  u_char buf[NGX_HTTP_AUTH_DIGEST_BUF_SIZE];
  u_char line[NGX_HTTP_AUTH_DIGEST_BUF_SIZE];
  u_char *p;

  if (r->internal) {
    return NGX_DECLINED;
  }

  // if digest auth is disabled for this location, bail out immediately
  alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_digest_module);

  if (alcf->realm.value.len == 0) {
    return NGX_DECLINED;
  }

  if (ngx_http_complex_value(r, &alcf->realm, &realm) != NGX_OK) {
    return NGX_ERROR;
  }

  if (realm.len == 0 || alcf->user_file.value.len == 0) {
    return NGX_DECLINED;
  }

  if (ngx_strcmp(realm.data, "off") == 0) {
    return NGX_DECLINED;
  }

  if (ngx_http_auth_digest_evading(r, alcf)) {
    return NGX_HTTP_UNAUTHORIZED;
  }
  // unpack the Authorization header (if any) and verify that it contains all
  // required fields. otherwise send a challenge
  auth_fields = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_digest_cred_t));
  rc = ngx_http_auth_digest_check_credentials(r, auth_fields);
  if (rc == NGX_DECLINED) {
    return ngx_http_auth_digest_send_challenge(r, &realm, 0);
  } else if (rc == NGX_ERROR) {
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

  // step through the passwd file and find the individual lines, then pass them
  // off
  // to be compared against the values in the authorization header
  passwd_line.data = line;
  offset = begin = tail = 0;
  idle = 1;
  ngx_memzero(buf, NGX_HTTP_AUTH_DIGEST_BUF_SIZE);
  ngx_memzero(passwd_line.data, NGX_HTTP_AUTH_DIGEST_BUF_SIZE);
  while (1) {
    n = ngx_read_file(&file, buf + tail, NGX_HTTP_AUTH_DIGEST_BUF_SIZE - tail,
                      offset);
    if (n == NGX_ERROR) {
      ngx_http_auth_digest_close(&file);
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    begin = 0;
    for (i = 0; i < n + tail; i++) {
      if (buf[i] == '\n' || buf[i] == '\r') {
        if (!idle &&
            i - begin >
                36) { // 36 is the min length with a single-char name and realm
          p = ngx_cpymem(passwd_line.data, &buf[begin], i - begin);
          p[0] = '\0';
          passwd_line.len = i - begin;
          rc = ngx_http_auth_digest_verify_user(r, auth_fields, &passwd_line);

          if (rc == NGX_HTTP_AUTH_DIGEST_USERNOTFOUND) {
            rc = NGX_DECLINED;
          }

          if (rc != NGX_DECLINED) {
            ngx_http_auth_digest_close(&file);
            ngx_http_auth_digest_evasion_tracking(
                r, alcf, NGX_HTTP_AUTH_DIGEST_STATUS_SUCCESS);
            return rc;
          }
        }
        idle = 1;
        begin = i;
      } else if (idle) {
        idle = 0;
        begin = i;
      }
    }

    if (!idle) {
      tail = n + tail - begin;
      if (n == 0 && tail > 36) {
        p = ngx_cpymem(passwd_line.data, &buf[begin], tail);
        p[0] = '\0';
        passwd_line.len = i - begin;
        rc = ngx_http_auth_digest_verify_user(r, auth_fields, &passwd_line);
        if (rc == NGX_HTTP_AUTH_DIGEST_USERNOTFOUND) {
          rc = NGX_DECLINED;
        }
        if (rc != NGX_DECLINED) {
          ngx_http_auth_digest_close(&file);
          ngx_http_auth_digest_evasion_tracking(
              r, alcf, NGX_HTTP_AUTH_DIGEST_STATUS_SUCCESS);
          return rc;
        }
      } else {
        ngx_memmove(buf, &buf[begin], tail);
      }
    }

    if (n == 0) {
      break;
    }

    offset += n;
  }

  ngx_http_auth_digest_close(&file);
  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "invalid username or password for %*s",
                auth_fields->username.len, auth_fields->username.data);
  ngx_http_auth_digest_evasion_tracking(r, alcf,
                                        NGX_HTTP_AUTH_DIGEST_STATUS_FAILURE);

  // since no match was found based on the fields in the authorization header,
  // send a new challenge and let the client retry
  return ngx_http_auth_digest_send_challenge(r, &realm, auth_fields->stale);
}

ngx_int_t
ngx_http_auth_digest_check_credentials(ngx_http_request_t *r,
                                       ngx_http_auth_digest_cred_t *ctx) {

  if (r->headers_in.authorization == NULL) {
    return NGX_DECLINED;
  }

  /*
     token          = 1*<any CHAR except CTLs or separators>
     separators     = "(" | ")" | "<" | ">" | "@"
                    | "," | ";" | ":" | "\" | <">
                    | "/" | "[" | "]" | "?" | "="
                    | "{" | "}" | SP | HT
  */

  static uint32_t token_char[] = {
      0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

      /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
      0x03ff6cf8, /* 0000 0011 1111 1111  0110 1100 1111 1000 */

      /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
      0xc7fffffe, /* 1100 0111 1111 1111  1111 1111 1111 1110 */

      /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
      0x57ffffff, /* 0101 0111 1111 1111  1111 1111 1111 1111 */

      0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
      0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
      0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
      0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
  };

  u_char ch, *p, *last, *start = 0, *end;
  ngx_str_t name, value;
  ngx_int_t comma_count = 0, quoted_pair_count = 0;

  name.data = 0;
  name.len = 0;
  value.data = 0;
  value.len = 0;

  enum {
    sw_start = 0,
    sw_scheme,
    sw_scheme_end,
    sw_lws_start,
    sw_lws,
    sw_param_name_start,
    sw_param_name,
    sw_param_value_start,
    sw_param_value,
    sw_param_quoted_value,
    sw_param_end,
    sw_error,
  } state;

  ngx_str_t encoded = r->headers_in.authorization->value;

  state = sw_start;
  p = encoded.data;
  last = encoded.data + encoded.len;

  ch = *p++;

  while (p <= last) {
    switch (state) {
    default:
    case sw_error:
      return NGX_DECLINED;

    /* first char */
    case sw_start:
      if (ch == CR || ch == LF || ch == ' ' || ch == '\t') {
        ch = *p++;
      } else if (token_char[ch >> 5] & (1 << (ch & 0x1f))) {
        start = p - 1;
        state = sw_scheme;
      } else {
        state = sw_error;
      }
      break;

    case sw_scheme:
      if (token_char[ch >> 5] & (1 << (ch & 0x1f))) {
        ch = *p++;
      } else if (ch == ' ') {
        end = p - 1;
        state = sw_scheme_end;

        ctx->auth_scheme.data = start;
        ctx->auth_scheme.len = end - start;

        if (ngx_strncasecmp(ctx->auth_scheme.data, (u_char *)"Digest",
                            ctx->auth_scheme.len) != 0) {
          state = sw_error;
        }
      } else {
        state = sw_error;
      }
      break;

    case sw_scheme_end:
      if (ch == ' ') {
        ch = *p++;
      } else {
        state = sw_param_name_start;
      }
      break;

    case sw_lws_start:
      comma_count = 0;
      state = sw_lws;

    /* fall through */
    case sw_lws:
      if (comma_count > 0 && (token_char[ch >> 5] & (1 << (ch & 0x1f)))) {
        state = sw_param_name_start;
      } else if (ch == ',') {
        comma_count++;
        ch = *p++;
      } else if (ch == CR || ch == LF || ch == ' ' || ch == '\t') {
        ch = *p++;
      } else {
        state = sw_error;
      }
      break;

    case sw_param_name_start:
      if (token_char[ch >> 5] & (1 << (ch & 0x1f))) {
        start = p - 1;
        state = sw_param_name;
        ch = *p++;
      } else {
        state = sw_error;
      }
      break;

    case sw_param_name:
      if (token_char[ch >> 5] & (1 << (ch & 0x1f))) {
        ch = *p++;
      } else if (ch == '=') {
        end = p - 1;
        state = sw_param_value_start;

        name.data = start;
        name.len = end - start;

        ch = *p++;
      } else {
        state = sw_error;
      }
      break;

    case sw_param_value_start:
      if (token_char[ch >> 5] & (1 << (ch & 0x1f))) {
        start = p - 1;
        state = sw_param_value;
        ch = *p++;
      } else if (ch == '\"') {
        start = p;
        quoted_pair_count = 0;
        state = sw_param_quoted_value;
        ch = *p++;
      } else {
        state = sw_error;
      }
      break;

    case sw_param_value:
      if (token_char[ch >> 5] & (1 << (ch & 0x1f))) {
        ch = *p++;
      } else {
        end = p - 1;
        value.data = start;
        value.len = end - start;
        state = sw_param_end;
      }
      break;

    case sw_param_quoted_value:
      if (ch < 0x20 || ch == 0x7f) {
        state = sw_error;
      } else if (ch == '\\' && *p <= 0x7f) {
        quoted_pair_count++;
        /* Skip the next char, even if it's a \ */
        ch = *(p += 2);
      } else if (ch == '\"') {
        end = p - 1;
        ch = *p++;
        value.data = start;
        value.len = end - start - quoted_pair_count;
        if (quoted_pair_count > 0) {
          value.data = ngx_palloc(r->pool, value.len);
          u_char *d = value.data;
          u_char *s = start;
          for (; s < end; s++) {
            ch = *s;
            if (ch == '\\') {
              /* Make sure to add the next character
               * even if it's a \
               */
              s++;
              if (s < end) {
                *d++ = ch;
              }
              continue;
            }
            *d++ = ch;
          }
        }
        state = sw_param_end;
        goto param_end;
      } else {
        ch = *p++;
      }
      break;

    param_end:
    case sw_param_end:
      if (ngx_strncasecmp(name.data, (u_char *)"username", name.len) == 0) {
        ctx->username = value;
      } else if (ngx_strncasecmp(name.data, (u_char *)"qop", name.len) == 0) {
        ctx->qop = value;
      } else if (ngx_strncasecmp(name.data, (u_char *)"realm", name.len) == 0) {
        ctx->realm = value;
      } else if (ngx_strncasecmp(name.data, (u_char *)"nonce", name.len) == 0) {
        ctx->nonce = value;
      } else if (ngx_strncasecmp(name.data, (u_char *)"nc", name.len) == 0) {
        ctx->nc = value;
      } else if (ngx_strncasecmp(name.data, (u_char *)"uri", name.len) == 0) {
        ctx->uri = value;
      } else if (ngx_strncasecmp(name.data, (u_char *)"cnonce", name.len) ==
                 0) {
        ctx->cnonce = value;
      } else if (ngx_strncasecmp(name.data, (u_char *)"response", name.len) ==
                 0) {
        ctx->response = value;
      } else if (ngx_strncasecmp(name.data, (u_char *)"opaque", name.len) ==
                 0) {
        ctx->opaque = value;
      }

      state = sw_lws_start;
      break;
    }
  }

  if (state != sw_lws_start && state != sw_lws) {
    return NGX_DECLINED;
  }

  // bail out if anything but the opaque field is missing from the request
  // header
  if (!(ctx->username.len > 0 && ctx->qop.len > 0 && ctx->realm.len > 0 &&
        ctx->nonce.len > 0 && ctx->nc.len > 0 && ctx->uri.len > 0 &&
        ctx->cnonce.len > 0 && ctx->response.len > 0) ||
      ctx->nonce.len != 16) {
    return NGX_DECLINED;
  }

  return NGX_OK;
}

static ngx_int_t
ngx_http_auth_digest_verify_user(ngx_http_request_t *r,
                                 ngx_http_auth_digest_cred_t *fields,
                                 ngx_str_t *line) {
  ngx_uint_t i, from, nomatch;
  enum { sw_login, sw_ha1, sw_realm } state;

  state = sw_login;
  from = 0;
  nomatch = 0;

  // step through a single line (of the passwd file), matching the username and
  // realm
  // character-by-character against the request's Authorization header fields
  u_char *buf = line->data;
  for (i = 0; i <= line->len; i++) {
    u_char ch = buf[i];

    switch (state) {
    case sw_login:
      if (ch == '#')
        nomatch = 1;
      if (ch == ':') {
        if (fields->username.len != i)
          nomatch = 1;
        state = sw_realm;
        from = i + 1;
      } else if (i > fields->username.len || ch != fields->username.data[i]) {
        nomatch = 1;
      }
      break;

    case sw_realm:
      if (ch == '#')
        nomatch = 1;
      if (ch == ':') {
        if (fields->realm.len != i - from)
          nomatch = 1;
        state = sw_ha1;
        from = i + 1;
      } else if (ch != fields->realm.data[i - from]) {
        nomatch = 1;
      }
      break;

    case sw_ha1:
      if (ch == '\0' || ch == ':' || ch == '#' || ch == CR || ch == LF) {
        if (i - from != 32)
          nomatch = 1;
      }
      break;
    }
  }

  if (nomatch) {
    return NGX_HTTP_AUTH_DIGEST_USERNOTFOUND;
  }

  return ngx_http_auth_digest_verify_hash(r, fields, &buf[from]);
}

static ngx_int_t
ngx_http_auth_digest_verify_hash(ngx_http_request_t *r,
                                 ngx_http_auth_digest_cred_t *fields,
                                 u_char *hashed_pw) {
  u_char *p;
  ngx_str_t http_method;
  ngx_str_t HA1, HA2, ha2_key;
  ngx_str_t digest, digest_key;
  ngx_md5_t md5;
  u_char hash[16];

  // The .net Http library sends the incorrect URI as part of the Authorization
  // response. Instead of the complete URI including the query parameters it
  // sends only the basic URI without the query parameters. It also uses this
  // value in the calculations.
  // To be compatible with the .net library the following change is made to this
  // module:
  // - Compare the URI in the Authorization (A-URI) with the request URI (R-URI).
  // - If A-URI and R-URI are identical verify is executed.
  // - If A-URI and R-URI are identical up to the '?' verify is executed
  // - Otherwise the check is not executed and authorization is declined
  if (!((r->unparsed_uri.len == fields->uri.len) &&
        (ngx_strncmp(r->unparsed_uri.data, fields->uri.data, fields->uri.len) == 0)))
  { 
    if (!((r->unparsed_uri.len > fields->uri.len) &&
          (ngx_strncmp(r->unparsed_uri.data, fields->uri.data, fields->uri.len) == 0) &&
          (r->unparsed_uri.data[fields->uri.len] == '?')))
    {
      return NGX_DECLINED; 
    }
  }
  
  //  the hashing scheme:
  //    digest:
  //    MD5(MD5(username:realm:password):nonce:nc:cnonce:qop:MD5(method:uri))
  //                ^- HA1                                           ^- HA2
  //    verify: fields->response ==
  //    MD5($hashed_pw:nonce:nc:cnonce:qop:MD5(method:uri))

  // ha1 was precalculated and saved to the passwd file:
  // md5(username:realm:password)
  HA1.len = 33;
  HA1.data = ngx_pcalloc(r->pool, HA1.len);
  p = ngx_cpymem(HA1.data, hashed_pw, 32);

  // calculate ha2: md5(method:uri)
  http_method.len = r->method_name.len + 1;
  http_method.data = ngx_pcalloc(r->pool, http_method.len);
  if (http_method.data == NULL)
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  p = ngx_cpymem(http_method.data, r->method_name.data, r->method_name.len);

  ha2_key.len = http_method.len + fields->uri.len + 1;
  ha2_key.data = ngx_pcalloc(r->pool, ha2_key.len);
  if (ha2_key.data == NULL)
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  p = ngx_cpymem(ha2_key.data, http_method.data, http_method.len - 1);
  *p++ = ':';
  p = ngx_cpymem(p, fields->uri.data, fields->uri.len);

  HA2.len = 33;
  HA2.data = ngx_pcalloc(r->pool, HA2.len);
  ngx_md5_init(&md5);
  ngx_md5_update(&md5, ha2_key.data, ha2_key.len - 1);
  ngx_md5_final(hash, &md5);
  ngx_hex_dump(HA2.data, hash, 16);

  // calculate digest: md5(ha1:nonce:nc:cnonce:qop:ha2)
  digest_key.len = HA1.len - 1 + fields->nonce.len + fields->nc.len +
                   fields->cnonce.len + fields->qop.len + HA2.len - 1 + 5 + 1;
  digest_key.data = ngx_pcalloc(r->pool, digest_key.len);
  if (digest_key.data == NULL)
    return NGX_HTTP_INTERNAL_SERVER_ERROR;

  p = ngx_cpymem(digest_key.data, HA1.data, HA1.len - 1);
  *p++ = ':';
  p = ngx_cpymem(p, fields->nonce.data, fields->nonce.len);
  *p++ = ':';
  p = ngx_cpymem(p, fields->nc.data, fields->nc.len);
  *p++ = ':';
  p = ngx_cpymem(p, fields->cnonce.data, fields->cnonce.len);
  *p++ = ':';
  p = ngx_cpymem(p, fields->qop.data, fields->qop.len);
  *p++ = ':';
  p = ngx_cpymem(p, HA2.data, HA2.len - 1);

  digest.len = 33;
  digest.data = ngx_pcalloc(r->pool, 33);
  if (digest.data == NULL)
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  ngx_md5_init(&md5);
  ngx_md5_update(&md5, digest_key.data, digest_key.len - 1);
  ngx_md5_final(hash, &md5);
  ngx_hex_dump(digest.data, hash, 16);

  // compare the hash of the full digest string to the response field of the
  // auth header
  // and bail out if they don't match
  if (fields->response.len != digest.len - 1 ||
      ngx_memcmp(digest.data, fields->response.data, fields->response.len) != 0)
    return NGX_DECLINED;

  ngx_http_auth_digest_nonce_t nonce;
  ngx_uint_t key;
  ngx_http_auth_digest_node_t *found;
  ngx_slab_pool_t *shpool;
  ngx_http_auth_digest_loc_conf_t *alcf;
  ngx_table_elt_t *info_header;
  ngx_str_t hkey, hval;

  shpool = (ngx_slab_pool_t *)ngx_http_auth_digest_shm_zone->shm.addr;
  alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_digest_module);
  nonce.rnd = ngx_hextoi(fields->nonce.data, 8);
  nonce.t = ngx_hextoi(&fields->nonce.data[8], 8);
  key = ngx_crc32_short((u_char *)&nonce.rnd, sizeof nonce.rnd) ^
        ngx_crc32_short((u_char *)&nonce.t, sizeof(nonce.t));

  int nc = ngx_hextoi(fields->nc.data, fields->nc.len);
  if (nc < 0 || nc >= alcf->replays) {
    fields->stale = 1;
    return NGX_DECLINED;
  }

  // make sure nonce and nc are both valid
  ngx_shmtx_lock(&shpool->mutex);
  found = (ngx_http_auth_digest_node_t *)ngx_http_auth_digest_rbtree_find(
      key, ngx_http_auth_digest_rbtree->root,
      ngx_http_auth_digest_rbtree->sentinel);
  if (found != NULL) {
    if (found->expires <= ngx_time()) {
      fields->stale = 1;
      goto invalid;
    }
    if (!ngx_bitvector_test(found->nc, nc)) {
      goto invalid;
    }
    if (ngx_bitvector_test(found->nc, 0)) {
      // if this is the first use of this nonce, switch the expiration time from
      // the timeout
      // param to now+expires. using the 0th element of the nc vector to flag
      // this...
      ngx_bitvector_set(found->nc, 0);
      found->expires = ngx_time() + alcf->expires;
      found->drop_time = ngx_time() + alcf->drop_time;
    }

    // mark this nc as ‘used’ to prevent replays
    ngx_bitvector_set(found->nc, nc);

    // todo: if the bitvector is now ‘full’, could preemptively expire the node
    // from the rbtree
    // ngx_rbtree_delete(ngx_http_auth_digest_rbtree, found);
    // ngx_slab_free_locked(shpool, found);

    ngx_shmtx_unlock(&shpool->mutex);

    // recalculate the digest with a modified HA2 value (for rspauth) and emit
    // the
    // Authentication-Info header
    ngx_memset(ha2_key.data, 0, ha2_key.len);
    p = ngx_snprintf(ha2_key.data, 1 + fields->uri.len, ":%s",
                     fields->uri.data);

    ngx_memset(HA2.data, 0, HA2.len);
    ngx_md5_init(&md5);
    ngx_md5_update(&md5, ha2_key.data, 1 + fields->uri.len);
    ngx_md5_final(hash, &md5);
    ngx_hex_dump(HA2.data, hash, 16);

    ngx_memset(digest_key.data, 0, digest_key.len);
    p = ngx_cpymem(digest_key.data, HA1.data, HA1.len - 1);
    *p++ = ':';
    p = ngx_cpymem(p, fields->nonce.data, fields->nonce.len);
    *p++ = ':';
    p = ngx_cpymem(p, fields->nc.data, fields->nc.len);
    *p++ = ':';
    p = ngx_cpymem(p, fields->cnonce.data, fields->cnonce.len);
    *p++ = ':';
    p = ngx_cpymem(p, fields->qop.data, fields->qop.len);
    *p++ = ':';
    p = ngx_cpymem(p, HA2.data, HA2.len - 1);

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, digest_key.data, digest_key.len - 1);
    ngx_md5_final(hash, &md5);
    ngx_hex_dump(digest.data, hash, 16);

    ngx_str_set(&hkey, "Authentication-Info");
    // sizeof() includes the null terminator, and digest.len also counts its
    // null terminator
    hval.len = sizeof("qop=\"auth\", rspauth=\"\", cnonce=\"\", nc=") +
               fields->cnonce.len + fields->nc.len + digest.len - 2;
    hval.data = ngx_pcalloc(r->pool, hval.len + 1);
    if (hval.data == NULL)
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    p = ngx_snprintf(hval.data, hval.len,
                     "qop=\"auth\", rspauth=\"%*s\", cnonce=\"%*s\", nc=%*s",
                     digest.len - 1, digest.data, fields->cnonce.len,
                     fields->cnonce.data, fields->nc.len, fields->nc.data);
    info_header = ngx_list_push(&r->headers_out.headers);
    if (info_header == NULL)
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    info_header->key = hkey;
    info_header->value = hval;
    info_header->hash = 1;
    return NGX_OK;
  } else {
  invalid:
    // nonce is invalid/expired or client reused an nc value. suspicious...
    ngx_shmtx_unlock(&shpool->mutex);
    return NGX_DECLINED;
  }
}

static ngx_int_t ngx_http_auth_digest_send_challenge(ngx_http_request_t *r,
                                                     ngx_str_t *realm,
                                                     ngx_uint_t is_stale) {
  ngx_str_t challenge;
  u_char *p;
  size_t realm_len = strnlen((const char *)realm->data, realm->len);

  r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
  if (r->headers_out.www_authenticate == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  r->headers_out.www_authenticate->hash = 1;
  ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");

  challenge.len =
      sizeof("Digest algorithm=\"MD5\", qop=\"auth\", realm=\"\", nonce=\"\"") -
      1 + realm_len + 16;
  if (is_stale)
    challenge.len += sizeof(", stale=\"true\"") - 1;
  challenge.data = ngx_pnalloc(r->pool, challenge.len);
  if (challenge.data == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  ngx_http_auth_digest_nonce_t nonce;
  nonce = ngx_http_auth_digest_next_nonce(r);
  if (nonce.t == 0 && nonce.rnd == 0) {
    // oom error when allocating nonce session in rbtree
    return NGX_HTTP_SERVICE_UNAVAILABLE;
  }

  p = ngx_cpymem(
      challenge.data, "Digest algorithm=\"MD5\", qop=\"auth\", realm=\"",
      sizeof("Digest algorithm=\"MD5\", qop=\"auth\", realm=\"") - 1);
  p = ngx_cpymem(p, realm->data, realm_len);
  p = ngx_cpymem(p, "\", nonce=\"", sizeof("\", nonce=\"") - 1);
  p = ngx_sprintf(p, "%08xl%08xl", nonce.rnd, nonce.t);

  if (is_stale) {
    p = ngx_cpymem(p, "\", stale=\"true\"", sizeof("\", stale=\"true\""));
  } else {
    p = ngx_cpymem(p, "\"", sizeof("\""));
  }
  r->headers_out.www_authenticate->value = challenge;

  return NGX_HTTP_UNAUTHORIZED;
}

static void ngx_http_auth_digest_close(ngx_file_t *file) {
  if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
    ngx_log_error(NGX_LOG_ALERT, file->log, ngx_errno,
                  ngx_close_file_n " \"%s\" failed", file->name.data);
  }
}

static char *ngx_http_auth_digest_set_user_file(ngx_conf_t *cf,
                                                ngx_command_t *cmd,
                                                void *conf) {
  ngx_http_auth_digest_loc_conf_t *alcf = conf;

  ngx_str_t *value;
  ngx_http_compile_complex_value_t ccv;

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

static char *ngx_http_auth_digest_set_realm(ngx_conf_t *cf, ngx_command_t *cmd,
                                            void *conf) {
  ngx_http_auth_digest_loc_conf_t *alcf = conf;

  ngx_str_t *value;
  ngx_http_compile_complex_value_t ccv;

  if (alcf->realm.value.len) {
    return "is duplicate";
  }

  value = cf->args->elts;

  ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

  ccv.cf = cf;
  ccv.value = &value[1];
  ccv.complex_value = &alcf->realm;
  ccv.zero = 1;
  ccv.conf_prefix = 0;
  ccv.root_prefix = 0;

  if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
    return NGX_CONF_ERROR;
  }

  return NGX_CONF_OK;
}

static char *ngx_http_auth_digest_set_shm_size(ngx_conf_t *cf,
                                               ngx_command_t *cmd, void *conf) {
  ssize_t new_shm_size;
  ngx_str_t *value;

  value = cf->args->elts;

  new_shm_size = ngx_parse_size(&value[1]);
  if (new_shm_size == NGX_ERROR) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Invalid memory area size `%V'",
                       &value[1]);
    return NGX_CONF_ERROR;
  }

  new_shm_size = ngx_align(new_shm_size, ngx_pagesize);

  if (new_shm_size < 8 * (ssize_t)ngx_pagesize) {
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "The auth_digest_shm_size value must be at least %udKiB",
                       (8 * ngx_pagesize) >> 10);
    new_shm_size = 8 * ngx_pagesize;
  }

  if (ngx_http_auth_digest_shm_size &&
      ngx_http_auth_digest_shm_size != (ngx_uint_t)new_shm_size) {
    ngx_conf_log_error(
        NGX_LOG_WARN, cf, 0,
        "Cannot change memory area size without restart, ignoring change");
  } else {
    ngx_http_auth_digest_shm_size = new_shm_size;
  }
  ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,
                     "Using %udKiB of shared memory for auth_digest",
                     new_shm_size >> 10);
  return NGX_CONF_OK;
}

static ngx_int_t ngx_http_auth_digest_init_shm_zone(ngx_shm_zone_t *shm_zone,
                                                    void *data) {
  ngx_slab_pool_t *shpool;
  ngx_rbtree_t *tree;
  ngx_rbtree_node_t *sentinel;
  ngx_atomic_t *lock;
  if (data) {
    shm_zone->data = data;
    return NGX_OK;
  }

  shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
  tree = ngx_slab_alloc(shpool, sizeof *tree);
  if (tree == NULL) {
    return NGX_ERROR;
  }

  sentinel = ngx_slab_alloc(shpool, sizeof *sentinel);
  if (sentinel == NULL) {
    return NGX_ERROR;
  }

  ngx_rbtree_init(tree, sentinel, ngx_http_auth_digest_rbtree_insert);
  shm_zone->data = tree;
  ngx_http_auth_digest_rbtree = tree;

  tree = ngx_slab_alloc(shpool, sizeof *tree);
  if (tree == NULL) {
    return NGX_ERROR;
  }

  sentinel = ngx_slab_alloc(shpool, sizeof *sentinel);
  if (sentinel == NULL) {
    return NGX_ERROR;
  }

  ngx_rbtree_init(tree, sentinel, ngx_http_auth_digest_ev_rbtree_insert);
  ngx_http_auth_digest_ev_rbtree = tree;

  lock = ngx_slab_alloc(shpool, sizeof(ngx_atomic_t));
  if (lock == NULL) {
    return NGX_ERROR;
  }
  ngx_http_auth_digest_cleanup_lock = lock;

  return NGX_OK;
}

static int ngx_http_auth_digest_rbtree_cmp(const ngx_rbtree_node_t *v_left,
                                           const ngx_rbtree_node_t *v_right) {
  if (v_left->key == v_right->key)
    return 0;
  else
    return (v_left->key < v_right->key) ? -1 : 1;
}

static int
ngx_http_auth_digest_ev_rbtree_cmp(const ngx_rbtree_node_t *v_left,
                                   const ngx_rbtree_node_t *v_right) {
  if (v_left->key == v_right->key) {
    ngx_http_auth_digest_ev_node_t *evleft =
        (ngx_http_auth_digest_ev_node_t *)v_left;
    ngx_http_auth_digest_ev_node_t *evright =
        (ngx_http_auth_digest_ev_node_t *)v_right;
    return ngx_http_auth_digest_srcaddr_cmp(
        &evleft->src_addr, evleft->src_addrlen, &evright->src_addr,
        evright->src_addrlen);
  }
  return (v_left->key < v_right->key) ? -1 : 1;
}

static void
ngx_rbtree_generic_insert(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
                          ngx_rbtree_node_t *sentinel,
                          int (*compare)(const ngx_rbtree_node_t *left,
                                         const ngx_rbtree_node_t *right)) {
  for (;;) {
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

static void ngx_http_auth_digest_rbtree_insert(ngx_rbtree_node_t *temp,
                                               ngx_rbtree_node_t *node,
                                               ngx_rbtree_node_t *sentinel) {

  ngx_rbtree_generic_insert(temp, node, sentinel,
                            ngx_http_auth_digest_rbtree_cmp);
}

static void ngx_http_auth_digest_ev_rbtree_insert(ngx_rbtree_node_t *temp,
                                                  ngx_rbtree_node_t *node,
                                                  ngx_rbtree_node_t *sentinel) {

  ngx_rbtree_generic_insert(temp, node, sentinel,
                            ngx_http_auth_digest_ev_rbtree_cmp);
}

static ngx_rbtree_node_t *
ngx_http_auth_digest_rbtree_find(ngx_rbtree_key_t key, ngx_rbtree_node_t *node,
                                 ngx_rbtree_node_t *sentinel) {

  if (node == sentinel)
    return NULL;

  ngx_rbtree_node_t *found = (node->key == key) ? node : NULL;
  if (found == NULL && node->left != sentinel) {
    found = ngx_http_auth_digest_rbtree_find(key, node->left, sentinel);
  }
  if (found == NULL && node->right != sentinel) {
    found = ngx_http_auth_digest_rbtree_find(key, node->right, sentinel);
  }

  return found;
}

static ngx_http_auth_digest_ev_node_t *
ngx_http_auth_digest_ev_rbtree_find(ngx_http_auth_digest_ev_node_t *this,
                                    ngx_rbtree_node_t *node,
                                    ngx_rbtree_node_t *sentinel) {
  int cmpval;
  if (node == sentinel)
    return NULL;

  cmpval = ngx_http_auth_digest_ev_rbtree_cmp((ngx_rbtree_node_t *)this, node);
  if (cmpval == 0) {
    return (ngx_http_auth_digest_ev_node_t *)node;
  }
  return ngx_http_auth_digest_ev_rbtree_find(
      this, (cmpval < 0) ? node->left : node->right, sentinel);
}

void ngx_http_auth_digest_cleanup(ngx_event_t *ev) {
  if (ev->timer_set)
    ngx_del_timer(ev);

  if (!(ngx_quit || ngx_terminate || ngx_exiting)) {
    ngx_add_timer(ev, NGX_HTTP_AUTH_DIGEST_CLEANUP_INTERVAL);
  }

  if (ngx_trylock(ngx_http_auth_digest_cleanup_lock)) {
    ngx_http_auth_digest_rbtree_prune(ev->log);
    ngx_http_auth_digest_ev_rbtree_prune(ev->log);
    ngx_unlock(ngx_http_auth_digest_cleanup_lock);
  }
}

static void ngx_http_auth_digest_rbtree_prune(ngx_log_t *log) {
  ngx_uint_t i;
  time_t now = ngx_time();
  ngx_slab_pool_t *shpool =
      (ngx_slab_pool_t *)ngx_http_auth_digest_shm_zone->shm.addr;

  ngx_shmtx_lock(&shpool->mutex);
  ngx_http_auth_digest_cleanup_list->nelts = 0;
  ngx_http_auth_digest_rbtree_prune_walk(ngx_http_auth_digest_rbtree->root,
                                         ngx_http_auth_digest_rbtree->sentinel,
                                         now, log);

  ngx_rbtree_node_t **elts =
      (ngx_rbtree_node_t **)ngx_http_auth_digest_cleanup_list->elts;
  for (i = 0; i < ngx_http_auth_digest_cleanup_list->nelts; i++) {
    ngx_rbtree_delete(ngx_http_auth_digest_rbtree, elts[i]);
    ngx_slab_free_locked(shpool, elts[i]);
  }
  ngx_shmtx_unlock(&shpool->mutex);

  // if the cleanup array grew during the run, shrink it back down
  if (ngx_http_auth_digest_cleanup_list->nalloc >
      NGX_HTTP_AUTH_DIGEST_CLEANUP_BATCH_SIZE) {
    ngx_array_t *old_list = ngx_http_auth_digest_cleanup_list;
    ngx_array_t *new_list = ngx_array_create(
        old_list->pool, NGX_HTTP_AUTH_DIGEST_CLEANUP_BATCH_SIZE,
        sizeof(ngx_rbtree_node_t *));
    if (new_list != NULL) {
      ngx_array_destroy(old_list);
      ngx_http_auth_digest_cleanup_list = new_list;
    } else {
      ngx_log_error(NGX_LOG_ERR, log, 0,
                    "auth_digest ran out of cleanup space");
    }
  }
}

static void ngx_http_auth_digest_rbtree_prune_walk(ngx_rbtree_node_t *node,
                                                   ngx_rbtree_node_t *sentinel,
                                                   time_t now, ngx_log_t *log) {
  if (node == sentinel)
    return;

  if (node->left != sentinel) {
    ngx_http_auth_digest_rbtree_prune_walk(node->left, sentinel, now, log);
  }

  if (node->right != sentinel) {
    ngx_http_auth_digest_rbtree_prune_walk(node->right, sentinel, now, log);
  }

  ngx_http_auth_digest_node_t *dnode = (ngx_http_auth_digest_node_t *)node;
  if (dnode->drop_time <= ngx_time()) {
    ngx_rbtree_node_t **dropnode =
        ngx_array_push(ngx_http_auth_digest_cleanup_list);
    dropnode[0] = node;
  }
}

static void ngx_http_auth_digest_ev_rbtree_prune(ngx_log_t *log) {
  ngx_uint_t i;
  time_t now = ngx_time();
  ngx_slab_pool_t *shpool =
      (ngx_slab_pool_t *)ngx_http_auth_digest_shm_zone->shm.addr;

  ngx_shmtx_lock(&shpool->mutex);
  ngx_http_auth_digest_cleanup_list->nelts = 0;
  ngx_http_auth_digest_ev_rbtree_prune_walk(
      ngx_http_auth_digest_ev_rbtree->root,
      ngx_http_auth_digest_ev_rbtree->sentinel, now, log);

  ngx_rbtree_node_t **elts =
      (ngx_rbtree_node_t **)ngx_http_auth_digest_cleanup_list->elts;
  for (i = 0; i < ngx_http_auth_digest_cleanup_list->nelts; i++) {
    ngx_rbtree_delete(ngx_http_auth_digest_ev_rbtree, elts[i]);
    ngx_slab_free_locked(shpool, elts[i]);
  }
  ngx_shmtx_unlock(&shpool->mutex);

  // if the cleanup array grew during the run, shrink it back down
  if (ngx_http_auth_digest_cleanup_list->nalloc >
      NGX_HTTP_AUTH_DIGEST_CLEANUP_BATCH_SIZE) {
    ngx_array_t *old_list = ngx_http_auth_digest_cleanup_list;
    ngx_array_t *new_list = ngx_array_create(
        old_list->pool, NGX_HTTP_AUTH_DIGEST_CLEANUP_BATCH_SIZE,
        sizeof(ngx_rbtree_node_t *));
    if (new_list != NULL) {
      ngx_array_destroy(old_list);
      ngx_http_auth_digest_cleanup_list = new_list;
    } else {
      ngx_log_error(NGX_LOG_ERR, log, 0,
                    "auth_digest ran out of cleanup space");
    }
  }
}

static void
ngx_http_auth_digest_ev_rbtree_prune_walk(ngx_rbtree_node_t *node,
                                          ngx_rbtree_node_t *sentinel,
                                          time_t now, ngx_log_t *log) {
  if (node == sentinel)
    return;

  if (node->left != sentinel) {
    ngx_http_auth_digest_ev_rbtree_prune_walk(node->left, sentinel, now, log);
  }

  if (node->right != sentinel) {
    ngx_http_auth_digest_ev_rbtree_prune_walk(node->right, sentinel, now, log);
  }

  ngx_http_auth_digest_ev_node_t *dnode =
      (ngx_http_auth_digest_ev_node_t *)node;
  if (dnode->drop_time <= ngx_time()) {
    ngx_rbtree_node_t **dropnode =
        ngx_array_push(ngx_http_auth_digest_cleanup_list);
    dropnode[0] = node;
  }
}

static ngx_http_auth_digest_nonce_t
ngx_http_auth_digest_next_nonce(ngx_http_request_t *r) {
  ngx_http_auth_digest_loc_conf_t *alcf;
  ngx_slab_pool_t *shpool;
  ngx_http_auth_digest_nonce_t nonce;
  ngx_uint_t key;
  ngx_http_auth_digest_node_t *node;

  shpool = (ngx_slab_pool_t *)ngx_http_auth_digest_shm_zone->shm.addr;
  alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_digest_module);

  // create a nonce value that's not in the active set
  while (1) {
    nonce.t = ngx_time();
    nonce.rnd = ngx_random();
    key = ngx_crc32_short((u_char *)&nonce.rnd, sizeof nonce.rnd) ^
          ngx_crc32_short((u_char *)&nonce.t, sizeof(nonce.t));

    ngx_shmtx_lock(&shpool->mutex);
    ngx_rbtree_node_t *found =
        ngx_http_auth_digest_rbtree_find(key, ngx_http_auth_digest_rbtree->root,
                                         ngx_http_auth_digest_rbtree->sentinel);

    if (found != NULL) {
      ngx_shmtx_unlock(&shpool->mutex);
      continue;
    }

    node = ngx_slab_alloc_locked(shpool,
                                 sizeof(ngx_http_auth_digest_node_t) +
                                     ngx_bitvector_size(1 + alcf->replays));
    if (node == NULL) {
      ngx_shmtx_unlock(&shpool->mutex);
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "auth_digest ran out of shm space. Increase the "
                    "auth_digest_shm_size limit.");
      nonce.t = 0;
      nonce.rnd = 0;
      return nonce;
    }
    node->expires = nonce.t + alcf->timeout;
    node->drop_time = nonce.t + alcf->timeout;
    ngx_memset(node->nc, 0xff, ngx_bitvector_size(1 + alcf->replays));
    ((ngx_rbtree_node_t *)node)->key = key;
    ngx_rbtree_insert(ngx_http_auth_digest_rbtree, &node->node);

    ngx_shmtx_unlock(&shpool->mutex);
    return nonce;
  }
}

static int ngx_http_auth_digest_srcaddr_key(struct sockaddr *sa, socklen_t len,
                                            ngx_uint_t *key) {
  struct sockaddr_in *sin;
#if (NGX_HAVE_INET6)
  struct sockaddr_in6 *s6;
#endif

  switch (sa->sa_family) {
  case AF_INET:
    sin = (struct sockaddr_in *)sa;
    *key = ngx_crc32_short((u_char *)&sin->sin_addr, sizeof(sin->sin_addr));
    return 1;
#if (NGX_HAVE_INET6)
  case AF_INET6:
    s6 = (struct sockaddr_in6 *)sa;
    *key = ngx_crc32_short((u_char *)&s6->sin6_addr, sizeof(s6->sin6_addr));
    return 1;
#endif
  default:
    break;
  }
  return 0;
}

static int ngx_http_auth_digest_srcaddr_cmp(struct sockaddr *sa1,
                                            socklen_t len1,
                                            struct sockaddr *sa2,
                                            socklen_t len2) {
  struct sockaddr_in *sin1, *sin2;
#if (NGX_HAVE_INET6)
  struct sockaddr_in6 *s61, *s62;
#endif
  if (len1 != len2) {
    return (len1 < len2) ? -1 : 1;
  }
  if (sa1->sa_family != sa2->sa_family) {
    return (sa1->sa_family < sa2->sa_family) ? -1 : 1;
  }

  switch (sa1->sa_family) {
  case AF_INET:
    sin1 = (struct sockaddr_in *)sa1;
    sin2 = (struct sockaddr_in *)sa2;
    return ngx_memcmp(&sin1->sin_addr, &sin2->sin_addr, sizeof(sin1->sin_addr));
#if (NGX_HAVE_INET6)
  case AF_INET6:
    s61 = (struct sockaddr_in6 *)sa1;
    s62 = (struct sockaddr_in6 *)sa2;
    return ngx_memcmp(&s61->sin6_addr, &s62->sin6_addr, sizeof(s61->sin6_addr));
#endif
  default:
    break;
  }
  return -999;
}

static void
ngx_http_auth_digest_evasion_tracking(ngx_http_request_t *r,
                                      ngx_http_auth_digest_loc_conf_t *alcf,
                                      ngx_int_t status) {
  ngx_slab_pool_t *shpool;
  ngx_uint_t key;
  ngx_http_auth_digest_ev_node_t testnode, *node;

  if (!ngx_http_auth_digest_srcaddr_key(r->connection->sockaddr,
                                        r->connection->socklen, &key)) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "skipping evasive tactics for this source address");
    return;
  }
  shpool = (ngx_slab_pool_t *)ngx_http_auth_digest_shm_zone->shm.addr;

  ngx_shmtx_lock(&shpool->mutex);
  ngx_memzero(&testnode, sizeof(testnode));
  testnode.node.key = key;
  ngx_memcpy(&testnode.src_addr, r->connection->sockaddr,
             r->connection->socklen);
  testnode.src_addrlen = r->connection->socklen;
  node = ngx_http_auth_digest_ev_rbtree_find(
      &testnode, ngx_http_auth_digest_ev_rbtree->root,
      ngx_http_auth_digest_ev_rbtree->sentinel);
  if (node == NULL) {
    // Don't bother creating a node if this was a successful auth
    if (status == NGX_HTTP_AUTH_DIGEST_STATUS_SUCCESS) {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "sucessful auth, not tracking");
      ngx_shmtx_unlock(&shpool->mutex);
      return;
    }
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "adding tracking node");
    node =
        ngx_slab_alloc_locked(shpool, sizeof(ngx_http_auth_digest_ev_node_t));
    if (node == NULL) {
      ngx_shmtx_unlock(&shpool->mutex);
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "auth_digest ran out of shm space. Increase the "
                    "auth_digest_shm_size limit.");
      return;
    }
    ngx_memcpy(&node->src_addr, r->connection->sockaddr,
               r->connection->socklen);
    node->src_addrlen = r->connection->socklen;
    ((ngx_rbtree_node_t *)node)->key = key;
    ngx_rbtree_insert(ngx_http_auth_digest_ev_rbtree, &node->node);
  }
  if (status == NGX_HTTP_AUTH_DIGEST_STATUS_SUCCESS) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "successful auth, clearing evasion counters");
    node->failcount = 0;
    node->drop_time = ngx_time();
  } else {
    // Reset the failure count to 1 if we're outside the evasion window
    if (ngx_time() > node->drop_time) {
      node->failcount = 1;
    } else {
      node->failcount += 1;
    }
    node->drop_time = ngx_time() + alcf->evasion_time;
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "failed auth, updating failcount=%d, drop_time=%d",
                  node->failcount, node->drop_time);
  }
  ngx_shmtx_unlock(&shpool->mutex);
}

static int ngx_http_auth_digest_evading(ngx_http_request_t *r,
                                        ngx_http_auth_digest_loc_conf_t *alcf) {
  ngx_slab_pool_t *shpool;
  ngx_uint_t key;
  ngx_http_auth_digest_ev_node_t testnode, *node;
  int evading = 0;

  if (!ngx_http_auth_digest_srcaddr_key(r->connection->sockaddr,
                                        r->connection->socklen, &key)) {
    return 0;
  }

  ngx_memzero(&testnode, sizeof(testnode));
  testnode.node.key = key;
  ngx_memcpy(&testnode.src_addr, r->connection->sockaddr,
             r->connection->socklen);
  testnode.src_addrlen = r->connection->socklen;

  shpool = (ngx_slab_pool_t *)ngx_http_auth_digest_shm_zone->shm.addr;

  ngx_shmtx_lock(&shpool->mutex);
  node = ngx_http_auth_digest_ev_rbtree_find(
      &testnode, ngx_http_auth_digest_ev_rbtree->root,
      ngx_http_auth_digest_ev_rbtree->sentinel);
  if (node != NULL && node->failcount >= alcf->maxtries &&
      ngx_time() < node->drop_time) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "ignoring authentication request - in evasion period");
    evading = 1;
  }
  ngx_shmtx_unlock(&shpool->mutex);
  return evading;
}
