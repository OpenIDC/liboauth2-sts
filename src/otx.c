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

const char *sts_cfg_set_otx(oauth2_sts_cfg_t *cfg, const char *url,
			    const oauth2_nv_list_t *params)
{
	char *rv = NULL;

	cfg->otx_endpoint = oauth2_cfg_endpoint_init(cfg->log);
	if (cfg->otx_endpoint == NULL) {
		rv = oauth2_strdup("oauth2_cfg_endpoint_init failed");
		goto end;
	}

	rv = oauth2_cfg_set_endpoint(cfg->log, cfg->otx_endpoint, url, params,
				     NULL);
	if (rv != NULL)
		goto end;

	cfg->otx_client_id =
	    oauth2_strdup(oauth2_nv_list_get(cfg->log, params, "client_id"));

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
		sts_merge_request_parameters(
		    log, cfg, cfg->otx_request_parameters, params);
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
