/***************************************************************************
 *
 * Copyright (C) 2018-2024 - ZmartZone Holding BV
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 *
 **************************************************************************/

#include <stdlib.h>
#include <time.h>

#include <oauth2/http.h>
#include <oauth2/mem.h>
#include <oauth2/oauth2.h>
#include <oauth2/sts.h>
#ifdef OAUTH2_WITH_JQ
#include <oauth2/jq.h>
#endif

#include "sts_int.h"

static const char *sts_cfg_jwt_get_alg(oauth2_cfg_sts_t *cfg)
{
	if (cfg->jwt_alg == NULL)
		return CJOSE_HDR_ALG_RS256;
	return cfg->jwt_alg;
}

oauth2_cache_t *sts_cfg_jwt_get_jq_cache(oauth2_log_t *log,
					 oauth2_sts_cfg_t *cfg)
{
	oauth2_debug(log, "cfg->jwt_jq_cache=%p (name=%s)", cfg->jwt_jq_cache,
		     cfg->jwt_jq_cache_name);
	if (cfg->jwt_jq_cache == NULL) {
		cfg->jwt_jq_cache =
		    oauth2_cache_obtain(log, cfg->jwt_jq_cache_name);
	}
	return cfg->jwt_jq_cache;
}

const char *sts_cfg_set_jwt(oauth2_log_t *log, oauth2_sts_cfg_t *cfg,
			    const char *jwk, const oauth2_nv_list_t *params,
			    const char *expr)
{
	char *rv = NULL;
	cjose_err err;
	char *cser = NULL;

	err.code = CJOSE_ERR_NONE;

	cfg->jwt_jwk = cjose_jwk_import(jwk, strlen(jwk), &err);
	if (cfg->jwt_jwk == NULL) {
		rv = oauth2_stradd(oauth2_strdup("cjose_jwk_import error: "),
				   jwk, " : ", err.message);
		goto end;
	}

	cfg->jwt_alg = oauth2_strdup(oauth2_nv_list_get(log, params, "alg"));

	cser = oauth2_jwt_create(log, cfg->jwt_jwk, sts_cfg_jwt_get_alg(cfg),
				 NULL, NULL, NULL, NULL, 0, false, false, NULL);
	if (cser == NULL) {
		rv = oauth2_stradd(NULL,
				   "could not create a signed JWT with the "
				   "configured JWK and algorithm: ",
				   sts_cfg_jwt_get_alg(cfg),
				   ", make sure the JWK is a private key and "
				   "the alg value matches the key");
		goto end;
	}
	oauth2_mem_free(cser);

	cfg->jwt_iss = oauth2_strdup(oauth2_nv_list_get(log, params, "iss"));
	cfg->jwt_sub = oauth2_strdup(oauth2_nv_list_get(log, params, "sub"));
	cfg->jwt_client_id =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "client_id"));
	cfg->jwt_aud = oauth2_strdup(oauth2_nv_list_get(log, params, "aud"));

	cfg->jwt_jq_expr = oauth2_strdup(expr);
	if (cfg->jwt_jq_expr != NULL) {
#ifndef OAUTH2_WITH_JQ
		rv = oauth2_strdup(
		    "a JQ expression is defined but JQ support is not compiled "
		    "into this version of liboauth2");
		goto end;
#else
		if (oauth2_jq_filter_compile(log, cfg->jwt_jq_expr, NULL) ==
		    false) {
			rv = oauth2_stradd(
			    NULL, "could not compile the JQ expression: '",
			    cfg->jwt_jq_expr, "'");
			goto end;
		}
#endif
	}

	cfg->jwt_jq_cache_name =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "jq.cache.name"));

	cfg->jwt_jq_cache = oauth2_cache_obtain(log, cfg->jwt_jq_cache_name);
	if (cfg->jwt_jq_cache == NULL)
		rv = oauth2_stradd(NULL, "JQ cache: '", cfg->jwt_jq_cache_name,
				   "', could not be obtained, probably it is "
				   "not defined (yet)");

end:

	return rv;
}

bool sts_jwt_exec(oauth2_log_t *log, oauth2_cfg_sts_t *cfg, const char *token,
		  char **rtoken, oauth2_uint_t *status_code)
{
	bool rc = false;
	json_t *payload = NULL;
	oauth2_uint_t exp = 0;
	bool include_iat = true;
	bool include_jti = true;

	oauth2_debug(log, "enter");

#ifdef OAUTH2_WITH_JQ
	char *ftoken = NULL;
	if (cfg->jwt_jq_expr != NULL) {
		if (oauth2_jq_filter(log, sts_cfg_jwt_get_jq_cache(log, cfg),
				     token, cfg->jwt_jq_expr,
				     &ftoken) == false) {
			oauth2_warn(log, "oauth2_jq_filter failed!");
		} else {
			token = ftoken;
		}
	}
#endif

	if (oauth2_json_decode_object(log, token, &payload) == false)
		goto end;

	exp = (json_object_get(payload, OAUTH2_CLAIM_EXP) == NULL) ? 60 : 0;
	include_iat = (json_object_get(payload, OAUTH2_CLAIM_IAT) == NULL);
	include_jti = (json_object_get(payload, OAUTH2_CLAIM_JTI) == NULL);

	*rtoken = oauth2_jwt_create(log, cfg->jwt_jwk, sts_cfg_jwt_get_alg(cfg),
				    cfg->jwt_iss, cfg->jwt_sub,
				    cfg->jwt_client_id, cfg->jwt_aud, exp,
				    include_iat, include_jti, payload);

	rc = (*rtoken != NULL);

	*status_code = rc ? 200 : 500;

end:

	if (payload)
		json_decref(payload);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}
