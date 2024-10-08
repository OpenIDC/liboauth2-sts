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

#include <oauth2/oauth2.h>
#include <oauth2/sts.h>

#include "sts_int.h"

#define STS_OTX_CLIENT_ID_DEFAULT NULL

#define STS_OTX_GRANT_TYPE_NAME "grant_type"
#define STS_OTX_GRANT_TYPE_VALUE                                               \
	"urn:ietf:params:oauth:grant-type:token-exchange"
#define STS_OTX_SUBJECT_TOKEN_NAME "subject_token"
#define STS_OTX_SUBJECT_TOKEN_TYPE_NAME "subject_token_type"
#define STS_OTX_SUBJECT_TOKEN_TYPE_VALUE                                       \
	"urn:ietf:params:oauth:token-type:access_token"

const char *sts_cfg_set_otx(oauth2_log_t *log, oauth2_sts_cfg_t *cfg,
			    const char *url, const oauth2_nv_list_t *params)
{
	char *rv = NULL;

	cfg->otx_endpoint = oauth2_cfg_endpoint_init(log);
	if (cfg->otx_endpoint == NULL) {
		rv = oauth2_strdup("oauth2_cfg_endpoint_init failed");
		goto end;
	}

	rv = oauth2_cfg_set_endpoint(log, cfg->otx_endpoint, url, params, NULL);
	if (rv != NULL)
		goto end;

	if (oauth2_parse_form_encoded_params(
		log, oauth2_nv_list_get(log, params, "params"),
		&cfg->otx_request_parameters) == false)
		goto end;

	cfg->otx_client_id =
	    oauth2_strdup(oauth2_nv_list_get(log, params, "client_id"));

end:

	return rv;
}

static const char *sts_otx_get_client_id(oauth2_cfg_sts_t *cfg)
{
	if (cfg->otx_client_id == NULL)
		return STS_OTX_CLIENT_ID_DEFAULT;
	return cfg->otx_client_id;
}

bool sts_otx_exec(oauth2_log_t *log, oauth2_cfg_sts_t *cfg, const char *token,
		  char **rtoken, oauth2_uint_t *status_code)
{

	bool rc = false;
	oauth2_nv_list_t *params = NULL;
	const char *client_id = sts_otx_get_client_id(cfg);
	oauth2_http_call_ctx_t *ctx = NULL;

	oauth2_debug(log, "enter");

	params = oauth2_nv_list_init(log);
	oauth2_nv_list_add(log, params, STS_OTX_GRANT_TYPE_NAME,
			   STS_OTX_GRANT_TYPE_VALUE);
	oauth2_nv_list_add(log, params, STS_OTX_SUBJECT_TOKEN_NAME, token);

	// TODO: this is not really specified...
	if ((oauth2_cfg_endpoint_auth_type(oauth2_cfg_endpoint_get_auth(
		 cfg->otx_endpoint)) == OAUTH2_ENDPOINT_AUTH_NONE) &&
	    (client_id != NULL))
		oauth2_nv_list_add(log, params, OAUTH2_CLIENT_ID, client_id);

	if (cfg->otx_request_parameters)
		oauth2_nv_list_merge_into(log, cfg->otx_request_parameters,
					  params);
	else
		oauth2_nv_list_add(log, params, STS_OTX_SUBJECT_TOKEN_TYPE_NAME,
				   STS_OTX_SUBJECT_TOKEN_TYPE_VALUE);

	ctx = oauth2_http_call_ctx_init(log);
	if (ctx == NULL)
		goto end;

	if (oauth2_http_ctx_auth_add(
		log, ctx, oauth2_cfg_endpoint_get_auth(cfg->otx_endpoint),
		params) == false)
		goto end;

	oauth2_http_call_ctx_ssl_verify_set(
	    log, ctx, oauth2_cfg_endpoint_get_ssl_verify(cfg->otx_endpoint));
	oauth2_http_call_ctx_timeout_set(
	    log, ctx, oauth2_cfg_endpoint_get_http_timeout(cfg->otx_endpoint));

	rc = sts_util_oauth_call(log, cfg, ctx,
				 oauth2_cfg_endpoint_get_url(cfg->otx_endpoint),
				 params, rtoken, status_code);

end:

	if (params)
		oauth2_nv_list_free(log, params);
	if (ctx)
		oauth2_http_call_ctx_free(log, ctx);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}
