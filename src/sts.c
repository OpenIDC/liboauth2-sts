/***************************************************************************
 *
 * Copyright (C) 2018-2020 - ZmartZone Holding BV - www.zmartzone.eu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 *
 **************************************************************************/

#include <ctype.h>
#include <stdio.h>

#include <cjose/cjose.h>

#include <oauth2/cache.h>
#include <oauth2/mem.h>
#include <oauth2/oauth2.h>
#include <oauth2/proto.h>
#include <oauth2/sts.h>

#include "sts_int.h"

#define STS_CFG_DEFAULT_CACHE_SHM_MAX_KEY_SIZE 1024;
#define STS_CFG_DEFAULT_CACHE_SHM_MAX_VAL_SIZE 4096;
#define STS_CFG_DEFAULT_CACHE_SHM_MAX_ENTRIES 2048;

#define STS_CFG_DEFAULT_CACHE_EXPIRES_IN (oauth2_time_t)300

#define STS_TYPE_DISABLED_STR "disabled"
#define STS_TYPE_WSTRUST_STR "wstrust"
#define STS_TYPE_ROPC_STR "ropc"
#define STS_TYPE_OTX_STR "otx"

#define STS_CFG_DEFAULT_ENABLED (oauth2_flag_t) false
#define STS_CFG_DEFAULT_CACHE_TYPE "shm"
#define STS_CFG_DEFAULT_TYPE STS_TYPE_DISABLED

#define STS_CFG_DEFAULT_STRIP_SOURCE_TOKEN 1
#define STS_CFG_DEFAULT_SSL_VALIDATION 1
#define STS_CFG_DEFAULT_HTTP_TIMEOUT 20

#define STS_DEFAULT_ACCEPT_SOURCE_TOKEN_IN                                     \
	(OAUTH2_CFG_TOKEN_IN_ENVVAR | OAUTH2_CFG_TOKEN_IN_HEADER)
#define STS_DEFAULT_PASS_TARGET_TOKEN_IN                                       \
	(OAUTH2_CFG_TOKEN_IN_ENVVAR | OAUTH2_CFG_TOKEN_IN_COOKIE)

#define STS_CONFIG_OPTION_SEPARATOR ":"

#define STS_TARGET_TOKEN_COOKIE_NAME_DEFAULT "sts_token"
#define STS_TARGET_TOKEN_ENVVAR_NAME_DEFAULT "MOD_STS_TARGET_TOKEN"
#define STS_TARGET_TOKEN_QUERY_PARAMNAME_DEFAULT "access_token"
#define STS_TARGET_TOKEN_POST_PARAMNAME_DEFAULT "access_token"
#define STS_TARGET_TOKEN_HEADER_NAME_DEFAULT OAUTH2_HTTP_HDR_AUTHORIZATION
#define STS_TARGET_TOKEN_HEADER_TYPE_DEFAULT OAUTH2_HTTP_HDR_BEARER

oauth2_sts_cfg_t *oauth2_sts_cfg_create(oauth2_log_t *log, const char *path)
{
	oauth2_sts_cfg_t *c = oauth2_mem_alloc(sizeof(oauth2_sts_cfg_t));

	c->log = log;

	c->type = OAUTH2_CFG_UINT_UNSET;

	c->ssl_validation = OAUTH2_CFG_FLAG_UNSET;
	c->http_timeout = OAUTH2_CFG_UINT_UNSET;

	c->wstrust_endpoint = NULL;
	c->wstrust_endpoint_auth = NULL;

	c->wstrust_applies_to = NULL;
	c->wstrust_token_type = NULL;
	c->wstrust_value_type = NULL;

	c->ropc = NULL;

	c->otx_endpoint = NULL;
	c->otx_endpoint_auth = NULL;
	c->otx_client_id = NULL;

	c->cache = NULL;
	c->cache_expiry_s = OAUTH2_CFG_TIME_UNSET;

	c->accept_source_token_in = NULL;
	c->pass_target_token_in.value = 0;

	c->request_parameters = NULL;
	c->path = oauth2_strdup(path);

	return c;
}

void oauth2_sts_cfg_merge(oauth2_log_t *log, oauth2_sts_cfg_t *cfg,
			  oauth2_sts_cfg_t *base, oauth2_sts_cfg_t *add)
{
	cfg->log = log;

	cfg->type = add->type != OAUTH2_CFG_UINT_UNSET ? add->type : base->type;

	cfg->ssl_validation = add->ssl_validation != OAUTH2_CFG_FLAG_UNSET
				  ? add->ssl_validation
				  : base->ssl_validation;
	cfg->http_timeout = add->http_timeout != OAUTH2_CFG_UINT_UNSET
				? add->http_timeout
				: base->http_timeout;

	cfg->wstrust_endpoint =
	    oauth2_strdup(add->wstrust_endpoint ? add->wstrust_endpoint
						: base->wstrust_endpoint);
	cfg->wstrust_endpoint_auth =
	    add->wstrust_endpoint_auth
		? oauth2_cfg_endpoint_auth_clone(NULL,
						 add->wstrust_endpoint_auth)
		: oauth2_cfg_endpoint_auth_clone(NULL,
						 base->wstrust_endpoint_auth);
	cfg->wstrust_applies_to =
	    oauth2_strdup(add->wstrust_applies_to ? add->wstrust_applies_to
						  : base->wstrust_applies_to);
	cfg->wstrust_token_type =
	    oauth2_strdup(add->wstrust_token_type ? add->wstrust_token_type
						  : base->wstrust_token_type);
	cfg->wstrust_value_type =
	    oauth2_strdup(add->wstrust_value_type ? add->wstrust_value_type
						  : base->wstrust_value_type);

	cfg->ropc = add->ropc ? oauth2_cfg_ropc_clone(NULL, add->ropc)
			      : oauth2_cfg_ropc_clone(NULL, base->ropc);

	cfg->otx_endpoint = oauth2_strdup(
	    add->otx_endpoint ? add->otx_endpoint : base->otx_endpoint);
	cfg->otx_endpoint_auth =
	    add->otx_endpoint_auth
		? oauth2_cfg_endpoint_auth_clone(NULL, add->otx_endpoint_auth)
		: oauth2_cfg_endpoint_auth_clone(NULL, base->otx_endpoint_auth);
	cfg->otx_client_id =
	    oauth2_strdup(add->otx_client_id != NULL ? add->otx_client_id
						     : base->otx_client_id);

	cfg->cache = add->cache ? oauth2_cache_clone(NULL, add->cache)
				: oauth2_cache_clone(NULL, base->cache);
	cfg->cache_expiry_s = add->cache_expiry_s != OAUTH2_CFG_TIME_UNSET
				  ? add->cache_expiry_s
				  : base->cache_expiry_s;

	cfg->accept_source_token_in =
	    add->accept_source_token_in
		? oauth2_cfg_source_token_clone(NULL,
						add->accept_source_token_in)
		: oauth2_cfg_source_token_clone(NULL,
						base->accept_source_token_in);

	// TODO: create merge/clone methods (DECLARE) for oauth2_cfg_token_in_t
	if (add->pass_target_token_in.value != 0) {
		cfg->pass_target_token_in.value =
		    add->pass_target_token_in.value;
		cfg->pass_target_token_in.query.param_name =
		    oauth2_strdup(add->pass_target_token_in.query.param_name);
		cfg->pass_target_token_in.post.param_name =
		    oauth2_strdup(add->pass_target_token_in.post.param_name);
		cfg->pass_target_token_in.cookie.name =
		    oauth2_strdup(add->pass_target_token_in.cookie.name);
		cfg->pass_target_token_in.envvar.name =
		    oauth2_strdup(add->pass_target_token_in.envvar.name);
		cfg->pass_target_token_in.header.name =
		    oauth2_strdup(add->pass_target_token_in.header.name);
		cfg->pass_target_token_in.header.type =
		    oauth2_strdup(add->pass_target_token_in.header.type);
	} else {
		cfg->pass_target_token_in.value =
		    base->pass_target_token_in.value;

		cfg->pass_target_token_in.query.param_name =
		    oauth2_strdup(base->pass_target_token_in.query.param_name);
		cfg->pass_target_token_in.post.param_name =
		    oauth2_strdup(base->pass_target_token_in.post.param_name);
		cfg->pass_target_token_in.cookie.name =
		    oauth2_strdup(base->pass_target_token_in.cookie.name);
		cfg->pass_target_token_in.envvar.name =
		    oauth2_strdup(base->pass_target_token_in.envvar.name);
		cfg->pass_target_token_in.header.name =
		    oauth2_strdup(base->pass_target_token_in.header.name);
		cfg->pass_target_token_in.header.type =
		    oauth2_strdup(base->pass_target_token_in.header.type);
	}

	cfg->request_parameters =
	    oauth2_nv_list_clone(cfg->log, add->request_parameters != NULL
					       ? add->request_parameters
					       : base->request_parameters);
	cfg->path = oauth2_strdup(add->path != NULL ? add->path : base->path);

	oauth2_debug(log, "merged: %p->%p", base, add);
}

void oauth2_sts_cfg_free(oauth2_log_t *log, oauth2_sts_cfg_t *cfg)
{
	if (cfg->wstrust_endpoint)
		oauth2_mem_free(cfg->wstrust_endpoint);
	if (cfg->wstrust_endpoint_auth)
		oauth2_cfg_endpoint_auth_free(cfg->log,
					      cfg->wstrust_endpoint_auth);
	if (cfg->wstrust_applies_to)
		oauth2_mem_free(cfg->wstrust_applies_to);
	if (cfg->wstrust_token_type)
		oauth2_mem_free(cfg->wstrust_token_type);
	if (cfg->wstrust_value_type)
		oauth2_mem_free(cfg->wstrust_value_type);

	if (cfg->ropc)
		oauth2_cfg_ropc_free(cfg->log, cfg->ropc);

	if (cfg->otx_endpoint)
		oauth2_mem_free(cfg->otx_endpoint);
	if (cfg->otx_endpoint_auth)
		oauth2_cfg_endpoint_auth_free(cfg->log, cfg->otx_endpoint_auth);
	if (cfg->otx_client_id)
		oauth2_mem_free(cfg->otx_client_id);

	if (cfg->accept_source_token_in)
		oauth2_cfg_source_token_free(NULL, cfg->accept_source_token_in);
	/*
	 * TODO: free
	 */
	//	if (cfg->pass_target_token_in)
	//		oauth2_cfg_target_token_free(NULL,
	// cfg->pass_target_token_in);

	if (cfg->cache)
		oauth2_cache_free(NULL, cfg->cache);

	if (cfg->request_parameters)
		oauth2_nv_list_free(cfg->log, cfg->request_parameters);
	if (cfg->path)
		oauth2_mem_free(cfg->path);

	oauth2_debug(cfg->log, "freed: %p", cfg);

	if (cfg->log)
		oauth2_log_free(cfg->log);

	oauth2_mem_free(cfg);
}

#define STS_CFG_SET_TAKE1_IMPL(member, type)                                   \
	const char *sts_cfg_set_##member(oauth2_sts_cfg_t *cfg,                \
					 const char *value)                    \
	{                                                                      \
		return oauth2_cfg_set_##type##_slot(                           \
		    cfg, offsetof(oauth2_sts_cfg_t, member), value);           \
	}

STS_CFG_SET_TAKE1_IMPL(ssl_validation, flag)
STS_CFG_SET_TAKE1_IMPL(http_timeout, uint)
STS_CFG_SET_TAKE1_IMPL(wstrust_endpoint, str)
STS_CFG_SET_TAKE1_IMPL(wstrust_applies_to, str)
STS_CFG_SET_TAKE1_IMPL(wstrust_token_type, str)
STS_CFG_SET_TAKE1_IMPL(wstrust_value_type, str)
// STS_CFG_SET_TAKE1_IMPL(ropc_endpoint, str)
// STS_CFG_SET_TAKE1_IMPL(ropc_client_id, str)
// STS_CFG_SET_TAKE1_IMPL(ropc_username, str)
STS_CFG_SET_TAKE1_IMPL(otx_endpoint, str)
STS_CFG_SET_TAKE1_IMPL(otx_client_id, str)
STS_CFG_SET_TAKE1_IMPL(cache_expiry_s, uint)

const char *sts_cfg_set_type(oauth2_sts_cfg_t *cfg, const char *value)
{
	const char *rv = NULL;
	if (strcmp(value, STS_TYPE_WSTRUST_STR) == 0) {
		cfg->type = STS_TYPE_WSTRUST;
	} else if (strcmp(value, STS_TYPE_ROPC_STR) == 0) {
		cfg->type = STS_TYPE_ROPC;
	} else if (strcmp(value, STS_TYPE_OTX_STR) == 0) {
		cfg->type = STS_TYPE_OTX;
	} else if (strcmp(value, STS_TYPE_DISABLED_STR) == 0) {
		cfg->type = STS_TYPE_DISABLED;
	} else {
		rv = "Invalid value: must be \"" STS_TYPE_WSTRUST_STR
		     "\", \"" STS_TYPE_ROPC_STR "\", \"" STS_TYPE_OTX_STR
		     "\"or \"" STS_TYPE_DISABLED_STR "\"";
	}
	return rv;
}

int sts_cfg_get_type(oauth2_sts_cfg_t *cfg)
{
	if (cfg->type == OAUTH2_CFG_UINT_UNSET) {
		return STS_CFG_DEFAULT_TYPE;
	}
	return cfg->type;
}

oauth2_flag_t sts_cfg_get_ssl_validation(oauth2_sts_cfg_t *cfg)
{
	if (cfg->ssl_validation == OAUTH2_CFG_FLAG_UNSET)
		return STS_CFG_DEFAULT_SSL_VALIDATION;
	return cfg->ssl_validation;
}

oauth2_uint_t sts_cfg_get_http_timeout(oauth2_sts_cfg_t *cfg)
{
	if (cfg->http_timeout == OAUTH2_CFG_UINT_UNSET)
		return STS_CFG_DEFAULT_HTTP_TIMEOUT;
	return cfg->http_timeout;
}

static char *_sts_cfg_set_endpoint_auth(oauth2_cfg_endpoint_auth_t **auth,
					const char *type, const char *value)
{
	char *rv = NULL;
	oauth2_nv_list_t *params = NULL;
	if (*auth)
		oauth2_cfg_endpoint_auth_free(NULL, *auth);
	*auth = oauth2_cfg_endpoint_auth_init(NULL);
	oauth2_parse_form_encoded_params(NULL, value, &params);
	rv = oauth2_cfg_endpoint_auth_add_options(NULL, *auth, type, params);
	oauth2_nv_list_free(NULL, params);
	return rv;
}

const char *sts_cfg_set_wstrust_endpoint_auth(oauth2_sts_cfg_t *cfg,
					      const char *type,
					      const char *value)
{
	char *rv = NULL;
	oauth2_cfg_endpoint_auth_t *auth = NULL;

	rv = _sts_cfg_set_endpoint_auth(&auth, type, value);

	if ((rv != NULL) || (auth == NULL))
		goto end;

	if ((oauth2_cfg_endpoint_auth_type(auth) !=
	     OAUTH2_ENDPOINT_AUTH_NONE) &&
	    (oauth2_cfg_endpoint_auth_type(auth) !=
	     OAUTH2_ENDPOINT_AUTH_BASIC) &&
	    (oauth2_cfg_endpoint_auth_type(auth) !=
	     OAUTH2_ENDPOINT_AUTH_CLIENT_CERT)) {
		rv = oauth2_strdup(
		    "unsupported endpoint authentication mechanism");
		oauth2_cfg_endpoint_auth_free(NULL, auth);
		goto end;
	}

	cfg->wstrust_endpoint_auth = auth;

end:

	return rv;
}

const char *sts_cfg_set_ropc(oauth2_sts_cfg_t *cfg, const char *value)
{
	if (cfg->ropc == NULL)
		cfg->ropc = oauth2_cfg_ropc_init(cfg->log);
	return oauth2_cfg_set_ropc_options(cfg->log, cfg->ropc, value);
}

const char *sts_cfg_set_otx_endpoint_auth(oauth2_sts_cfg_t *cfg,
					  const char *type, const char *value)
{
	return _sts_cfg_set_endpoint_auth(&cfg->otx_endpoint_auth, type, value);
}

const char *sts_cfg_set_request_parameters(oauth2_sts_cfg_t *cfg,
					   const char *name, const char *value)
{
	if (cfg->request_parameters == NULL)
		cfg->request_parameters = oauth2_nv_list_init(NULL);
	oauth2_nv_list_add(NULL, cfg->request_parameters, name, value);
	return NULL;
}

static oauth2_cache_t *_cache_default = NULL;

oauth2_cache_t *sts_cfg_get_cache(oauth2_log_t *log, oauth2_sts_cfg_t *cfg)
{
	oauth2_debug(log, "cfg->cache=%p, _cache_default=%p", cfg->cache,
		     _cache_default);
	if (cfg->cache == NULL) {
		if (_cache_default == NULL) {
			if (sts_cfg_set_cache(cfg, "shm", NULL) != NULL)
				abort();
			// TODO: when do we dispose of this?
			_cache_default = cfg->cache;
		}
		cfg->cache = oauth2_cache_clone(log, _cache_default);
	}
	return cfg->cache;
}

const char *sts_cfg_set_cache(oauth2_sts_cfg_t *cfg, const char *type,
			      const char *options)
{
	const char *rv = NULL;

	if (cfg->cache)
		oauth2_cache_free(cfg->log, cfg->cache);

	cfg->cache = oauth2_cache_init(cfg->log, type, options);
	if (cfg->cache == NULL) {
		rv = "oauth2_cache_init failed";
		goto end;
	}

	if (oauth2_cache_post_config(cfg->log, cfg->cache) == false) {
		rv = "oauth2_cache_post_config failed";
		goto end;
	}

end:

	return rv;
}

static oauth2_time_t sts_cfg_get_cache_expiry(oauth2_sts_cfg_t *cfg)
{
	if (cfg->cache_expiry_s == OAUTH2_CFG_TIME_UNSET)
		return STS_CFG_DEFAULT_CACHE_EXPIRES_IN;
	return cfg->cache_expiry_s;
}

const char *sts_cfg_set_accept_source_token_in(oauth2_sts_cfg_t *cfg,
					       const char *type,
					       const char *options)
{
	if (cfg->accept_source_token_in == NULL)
		cfg->accept_source_token_in =
		    oauth2_cfg_source_token_init(NULL);
	return oauth2_cfg_source_token_set_accept_in(
	    NULL, cfg->accept_source_token_in, type, options);
}

const char *sts_cfg_set_pass_target_token_in(oauth2_sts_cfg_t *cfg,
					     const char *method,
					     const char *options)
{
	static char allowed =
	    OAUTH2_CFG_TOKEN_IN_ENVVAR | OAUTH2_CFG_TOKEN_IN_HEADER |
	    OAUTH2_CFG_TOKEN_IN_QUERY | OAUTH2_CFG_TOKEN_IN_POST |
	    OAUTH2_CFG_TOKEN_IN_COOKIE | OAUTH2_CFG_TOKEN_IN_BASIC;

	char *rv = NULL;
	oauth2_nv_list_t *params = NULL;

	if (method == NULL) {
		rv = oauth2_strdup("Invalid value, method must be set");
		goto end;
	}

	if (oauth2_parse_form_encoded_params(NULL, options, &params) == false) {
		rv = strdup("oauth2_parse_form_encoded_params failed");
		goto end;
	}

	rv = oauth2_cfg_token_in_set(NULL, &cfg->pass_target_token_in, method,
				     params, allowed);

end:

	if (params)
		oauth2_nv_list_free(NULL, params);

	oauth2_debug(NULL, "leave: %s", rv);

	return rv;
}

char sts_get_pass_target_token_in(oauth2_sts_cfg_t *cfg)
{
	if (cfg->pass_target_token_in.value == 0)
		return STS_DEFAULT_PASS_TARGET_TOKEN_IN;
	return cfg->pass_target_token_in.value;
}

const char *sts_get_pass_target_token_in_hdr_name(oauth2_sts_cfg_t *cfg)
{
	return cfg->pass_target_token_in.header.name;
}

static bool _sts_set_target_token_in_envvar(
    oauth2_log_t *log, oauth2_sts_cfg_t *cfg, char *target_token,
    oauth2_cfg_server_callback_funcs_t *srv_cb, void *srv_cb_ctx)
{
	bool rc = false;
	const char *envvar_name = NULL;

	oauth2_debug(log, "enter");

	envvar_name = cfg->pass_target_token_in.envvar.name
			  ? cfg->pass_target_token_in.envvar.name
			  : STS_TARGET_TOKEN_ENVVAR_NAME_DEFAULT;

	oauth2_debug(log, "set environment variable: %s=%s", envvar_name,
		     target_token);

	rc = srv_cb->set(log, srv_cb_ctx, envvar_name, target_token);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool _sts_set_target_token_in_header(oauth2_log_t *log,
					    oauth2_sts_cfg_t *cfg,
					    oauth2_http_request_t *request,
					    char *target_token)
{
	bool rc = false;
	const char *header_name = NULL;
	const char *header_type = NULL;
	char *header_value = NULL;

	oauth2_debug(log, "enter");

	header_name = cfg->pass_target_token_in.header.name
			  ? cfg->pass_target_token_in.header.name
			  : STS_TARGET_TOKEN_HEADER_NAME_DEFAULT;
	header_type = cfg->pass_target_token_in.header.type
			  ? cfg->pass_target_token_in.header.type
			  : STS_TARGET_TOKEN_HEADER_TYPE_DEFAULT;

	if (header_type)
		header_value =
		    oauth2_stradd(NULL, header_type, " ", target_token);

	oauth2_debug(log, "set header to backend: %s: %s", header_name,
		     header_value);

	rc = oauth2_http_request_header_set(log, request, header_name,
					    header_value);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool _sts_set_target_token_in_query(oauth2_log_t *log,
					   oauth2_sts_cfg_t *cfg,
					   oauth2_http_request_t *request,
					   char *target_token)
{
	bool rc = false;
	const char *query_param_name = NULL;

	oauth2_debug(log, "enter");

	query_param_name = cfg->pass_target_token_in.query.param_name
			       ? cfg->pass_target_token_in.query.param_name
			       : STS_TARGET_TOKEN_QUERY_PARAMNAME_DEFAULT;

	oauth2_debug(log, "set query parameter to backend: %s=%s",
		     query_param_name, target_token);

	rc = oauth2_http_request_query_param_add(log, request, query_param_name,
						 target_token);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool _sts_set_target_token_in_post(
    oauth2_log_t *log, oauth2_sts_cfg_t *cfg, oauth2_http_request_t *request,
    char *target_token, oauth2_cfg_server_callback_funcs_t *srv_cb,
    void *srv_cb_ctx)
{
	bool rc = false;
	const char *content_type = NULL;
	const char *post_param_name = NULL;

	oauth2_debug(log, "enter");

	content_type =
	    oauth2_http_request_header_content_type_get(log, request);
	if ((oauth2_http_request_method_get(log, request) !=
	     OAUTH2_HTTP_METHOD_POST) ||
	    (strcasecmp(content_type, OAUTH2_CONTENT_TYPE_FORM_ENCODED) != 0)) {
		oauth2_debug(log, "no form-encoded HTTP POST");
		goto end;
	}

	post_param_name = cfg->pass_target_token_in.post.param_name
			      ? cfg->pass_target_token_in.post.param_name
			      : STS_TARGET_TOKEN_POST_PARAMNAME_DEFAULT;

	oauth2_debug(log, "set POST parameter to backend: %s=%s",
		     post_param_name, target_token);

	// TODO: web server specific callback
	// rc = sts_userdata_set_post_param(log, r, post_param_name,
	// target_token);

	//	if (srv_cb->form_post(log, srv_cb->ctx, &params) == false) {
	//		oauth2_error(log, "HTTP POST read callback failed");
	//		goto end;
	//	}

end:

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

static bool _sts_set_target_token_in_cookie(oauth2_log_t *log,
					    oauth2_sts_cfg_t *cfg,
					    oauth2_http_request_t *request,
					    char *target_token)
{
	bool rc = false;
	char *cookie_name = NULL;

	oauth2_debug(log, "enter");

	cookie_name = cfg->pass_target_token_in.cookie.name
			  ? cfg->pass_target_token_in.cookie.name
			  : STS_TARGET_TOKEN_COOKIE_NAME_DEFAULT;

	rc = oauth2_http_request_cookie_set(log, request, cookie_name,
					    target_token);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}

// TODO: set target in basic
static bool _sts_set_target_token(oauth2_log_t *log, oauth2_sts_cfg_t *cfg,
				  oauth2_http_request_t *request,
				  char *target_token,
				  oauth2_cfg_server_callback_funcs_t *srv_cb,
				  void *srv_cb_ctx)
{
	bool rc = true;

	char pass_target_token_in = sts_get_pass_target_token_in(cfg);

	if (target_token == NULL) {
		rc = false;
		goto end;
	}

	if (rc && (pass_target_token_in & OAUTH2_CFG_TOKEN_IN_ENVVAR))
		rc = _sts_set_target_token_in_envvar(log, cfg, target_token,
						     srv_cb, srv_cb_ctx);

	if (rc && (pass_target_token_in & OAUTH2_CFG_TOKEN_IN_HEADER))
		rc = _sts_set_target_token_in_header(log, cfg, request,
						     target_token);

	if (rc && (pass_target_token_in & OAUTH2_CFG_TOKEN_IN_QUERY)) {
		rc = _sts_set_target_token_in_query(log, cfg, request,
						    target_token);
	}

	if (rc && (pass_target_token_in & OAUTH2_CFG_TOKEN_IN_POST)) {
		rc = _sts_set_target_token_in_post(
		    log, cfg, request, target_token, srv_cb, srv_cb_ctx);
	}

	if (rc && (pass_target_token_in & OAUTH2_CFG_TOKEN_IN_COOKIE))
		rc = _sts_set_target_token_in_cookie(log, cfg, request,
						     target_token);

end:

	return rc;
}

static bool _sts_request_param_add(oauth2_log_t *log, void *rec,
				   const char *key, const char *value)
{
	oauth2_nv_list_t *params = (oauth2_nv_list_t *)rec;
	oauth2_nv_list_add(log, params, key, value);
	return true;
}

void sts_merge_request_parameters(oauth2_log_t *log, oauth2_sts_cfg_t *cfg,
				  oauth2_nv_list_t *params)
{
	if (cfg->request_parameters) {
		oauth2_nv_list_loop(log, cfg->request_parameters,
				    _sts_request_param_add, params);
	}
}

bool sts_util_oauth_call(oauth2_log_t *log, oauth2_sts_cfg_t *cfg,
			 oauth2_http_call_ctx_t *ctx,
			 const char *token_endpoint,
			 const oauth2_nv_list_t *params, char **rtoken,
			 oauth2_uint_t *status_code)
{
	bool rc = false;
	char *response = NULL;
	json_t *result = NULL;
	char *tkn = NULL;

	oauth2_http_call_ctx_ssl_verify_set(
	    log, ctx, sts_cfg_get_ssl_validation(cfg) != 0);
	oauth2_http_call_ctx_timeout_set(log, ctx,
					 sts_cfg_get_http_timeout(cfg));
	// oauth2_http_call_ctx_outgoing_proxy_set(log, ctx, outgoing_proxy);

	if (oauth2_http_post_form(log, token_endpoint, params, ctx, &response,
				  status_code) == false)
		goto end;

	if ((*status_code < 200) || (*status_code >= 300))
		goto end;

	if (oauth2_json_decode_check_error(log, response, &result) == false)
		goto end;

	if (oauth2_json_string_get(log, result, OAUTH2_ACCESS_TOKEN, &tkn,
				   NULL) == false)
		goto end;

	if (tkn == NULL) {
		oauth2_error(log, "no access token found in result");
		goto end;
	}

	*rtoken = oauth2_strdup(tkn);

	rc = true;

	/*
	 char **token_type = NULL;
	 sts_util_json_object_get_string(r->pool, result, "token_type",
	 token_type,
	 NULL);

	 if (token_type != NULL) {
	 if (oidc_proto_validate_token_type(r, provider, *token_type) == FALSE)
	 {
	 oidc_warn(r, "access token type did not validate, dropping it");
	 *access_token = NULL;
	 }
	 }

	 sts_util_json_object_get_int(r->pool, result, OIDC_PROTO_EXPIRES_IN,
	 expires_in,
	 -1);

	 sts_util_json_object_get_string(r->pool, result,
	 OIDC_PROTO_REFRESH_TOKEN,
	 refresh_token,
	 NULL);
	 */

end:

	if (response)
		oauth2_mem_free(response);
	if (tkn)
		oauth2_mem_free(tkn);
	if (result)
		json_decref(result);

	return rc;
}

static bool sts_token_exchange_exec(oauth2_log_t *log, oauth2_sts_cfg_t *cfg,
				    const char *token, const char *user,
				    char **rtoken,
				    oauth2_http_status_code_t *status_code)
{
	bool rc = false;

	switch (sts_cfg_get_type(cfg)) {
	case STS_TYPE_WSTRUST:
		rc = sts_wstrust_exec(log, cfg, token, rtoken, status_code);
		break;
	case STS_TYPE_ROPC:
		rc = sts_ropc_exec(log, cfg, token, user, rtoken, status_code);
		break;
	case STS_TYPE_OTX:
		rc = sts_otx_exec(log, cfg, token, rtoken, status_code);
		break;
	case STS_TYPE_DISABLED:
		break;
	default:
		oauth2_error(log, "unknown STS type %d", cfg->type);
		break;
	}

	return rc;
}

bool sts_handler(oauth2_log_t *log, oauth2_sts_cfg_t *cfg, char *source_token,
		 const char *user, char **target_token,
		 oauth2_http_status_code_t *status_code)
{
	bool rc = false;
	char *cache_key = NULL;

	cache_key = oauth2_stradd(NULL, cfg->path, ":", source_token);
	oauth2_cache_get(log, sts_cfg_get_cache(log, cfg), cache_key,
			 target_token);

	oauth2_debug(log, "cache: %p, path: %s, target_token: %s",
		     sts_cfg_get_cache(log, cfg), cfg->path, *target_token);

	if (*target_token == NULL) {
		if (sts_token_exchange_exec(log, cfg, source_token, user,
					    target_token,
					    status_code) == false) {
			oauth2_error(log, "sts_util_token_exchange failed");
			goto end;
		}

		if (*target_token != NULL)
			oauth2_cache_set(log, sts_cfg_get_cache(log, cfg),
					 cache_key, *target_token,
					 sts_cfg_get_cache_expiry(cfg));
	}

	rc = true;

end:

	if (cache_key)
		oauth2_mem_free(cache_key);

	return rc;
}

oauth2_cfg_source_token_t *sts_accept_source_token_in_get(oauth2_log_t *log,
							  oauth2_sts_cfg_t *cfg)
{
	if (cfg->accept_source_token_in == NULL)
		cfg->accept_source_token_in = oauth2_cfg_source_token_init(log);
	return cfg->accept_source_token_in;
}

bool sts_request_handler(oauth2_log_t *log, oauth2_sts_cfg_t *cfg,
			 oauth2_http_request_t *request, const char *user,
			 char **source_token,
			 oauth2_cfg_server_callback_funcs_t *srv_cb,
			 void *srv_cb_ctx,
			 oauth2_http_status_code_t *status_code)
{
	bool rc = false;
	char *target_token = NULL;

	oauth2_debug(log, "enter");

	*source_token = oauth2_get_source_token(
	    log, sts_accept_source_token_in_get(log, cfg), request, srv_cb,
	    srv_cb_ctx);
	if (*source_token == NULL)
		goto end;

	rc = sts_handler(log, cfg, *source_token, user, &target_token,
			 status_code);
	if (rc == false)
		goto end;

	rc = _sts_set_target_token(log, cfg, request, target_token, srv_cb,
				   srv_cb_ctx);

end:

	if (target_token)
		oauth2_mem_free(target_token);

	oauth2_debug(log, "leave");

	return rc;
}
