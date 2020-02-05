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

//#define STS_OTX_ENDPOINT_DEFAULT "https://localhost:9031/as/token.oauth2"
#define STS_OTX_ENDPOINT_DEFAULT NULL
#define STS_OTX_ENDPOINT_AUTH_DEFAULT STS_ENDPOINT_AUTH_NONE
#define STS_OTX_CLIENT_ID_DEFAULT NULL

#define STS_OTX_GRANT_TYPE_NAME "grant_type"
#define STS_OTX_GRANT_TYPE_VALUE                                               \
	"urn:ietf:params:oauth:grant-type:token-exchange"
#define STS_OTX_SUBJECT_TOKEN_NAME "subject_token"
#define STS_OTX_SUBJECT_TOKEN_TYPE_NAME "subject_token_type"
#define STS_OTX_SUBJECT_TOKEN_TYPE_VALUE                                       \
	"urn:ietf:params:oauth:token-type:access_token"
#define STS_OTX_ACCESS_TOKEN "access_token"
/*
int sts_otx_config_check_vhost(oauth2_log_t *log, apr_pool_t *pool, server_rec
*s, sts_server_config *cfg)
{
	if (cfg->otx_endpoint == NULL) {
		oauth2_error(log, STSOTXEndpoint
			  " must be set in OAuth 2.0 Token Exchange mode");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	return OK;
}
*/
static const char *sts_otx_get_endpoint(oauth2_cfg_sts_t *cfg)
{
	if (cfg->otx_endpoint == NULL)
		return STS_OTX_ENDPOINT_DEFAULT;
	return cfg->otx_endpoint;
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
	if ((oauth2_cfg_endpoint_auth_type(cfg->otx_endpoint_auth) ==
	     OAUTH2_ENDPOINT_AUTH_NONE) &&
	    (client_id != NULL))
		oauth2_nv_list_add(log, params, OAUTH2_CLIENT_ID, client_id);

	if (cfg->request_parameters)
		sts_merge_request_parameters(log, cfg, params);
	else
		oauth2_nv_list_add(log, params, STS_OTX_SUBJECT_TOKEN_TYPE_NAME,
				   STS_OTX_SUBJECT_TOKEN_TYPE_VALUE);

	ctx = oauth2_http_call_ctx_init(log);
	if (ctx == NULL)
		goto end;

	if (oauth2_http_ctx_auth_add(log, ctx, cfg->otx_endpoint_auth,
				     params) == false)
		goto end;

	rc = sts_util_oauth_call(log, cfg, ctx, sts_otx_get_endpoint(cfg),
				 params, rtoken, status_code);

end:

	if (params)
		oauth2_nv_list_free(log, params);
	if (ctx)
		oauth2_http_call_ctx_free(log, ctx);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}
