/***************************************************************************
 *
 * Copyright (C) 2018-2019 - ZmartZone Holding BV - www.zmartzone.eu
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

#include <oauth2/http.h>
#include <oauth2/oauth2.h>
#include <oauth2/sts.h>

#include "sts_int.h"

#define STS_ROPC_ENDPOINT_DEFAULT NULL
#define STS_ROPC_ENDPOINT_AUTH_DEFAULT STS_ENDPOINT_AUTH_NONE
#define STS_ROPC_CLIENT_ID_DEFAULT NULL
#define STS_ROPC_USERNAME_DEFAULT NULL

#define STS_ROPC_GRANT_TYPE_VALUE "password"
#define STS_ROPC_USERNAME "username"
#define STS_ROPC_PASSWORD "password"
/*
int sts_ropc_config_check_vhost(oauth2_log_t *log, apr_pool_t *pool, server_rec
*s, sts_config *cfg)
{
	if (cfg->ropc_endpoint == NULL) {
		oauth2_error(log, STSROPCEndpoint " must be set in ROPC mode");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	if (cfg->ropc_client_id == NULL) {
		oauth2_error(log, STSROPCClientID " must be set in ROPC mode");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	return OK;
}
*/
static const char *sts_ropc_get_endpoint(oauth2_cfg_sts_t *cfg)
{
	if (cfg->ropc_endpoint == NULL)
		return STS_ROPC_ENDPOINT_DEFAULT;
	return cfg->ropc_endpoint;
}

static const char *sts_ropc_get_client_id(oauth2_cfg_sts_t *cfg)
{
	if (cfg->ropc_client_id == NULL)
		return STS_ROPC_CLIENT_ID_DEFAULT;
	return cfg->ropc_client_id;
}

static const char *sts_ropc_get_username(oauth2_cfg_sts_t *cfg,
					 const char *user)
{
	if (cfg->ropc_username == NULL)
		// return the client_id by default
		return sts_ropc_get_client_id(cfg);
	if (strcmp(cfg->ropc_username, "*") == 0)
		// special handling to pull the authenticated username from a
		// previously triggered module
		return user;
	return cfg->ropc_username;
}

bool sts_ropc_exec(oauth2_log_t *log, oauth2_cfg_sts_t *cfg, const char *token,
		   const char *user, char **rtoken, oauth2_uint_t *status_code)
{

	bool rc = false;
	oauth2_nv_list_t *params = NULL;
	oauth2_http_call_ctx_t *ctx = NULL;
	const char *client_id = sts_ropc_get_client_id(cfg);
	const char *username = sts_ropc_get_username(cfg, user);

	oauth2_debug(log, "enter");

	params = oauth2_nv_list_init(log);
	oauth2_nv_list_add(log, params, OAUTH2_GRANT_TYPE,
			   STS_ROPC_GRANT_TYPE_VALUE);

	if ((oauth2_cfg_endpoint_auth_type(cfg->ropc_endpoint_auth) ==
	     OAUTH2_ENDPOINT_AUTH_NONE) &&
	    (client_id != NULL))
		oauth2_nv_list_add(log, params, OAUTH2_CLIENT_ID, client_id);

	if (username != NULL)
		oauth2_nv_list_add(log, params, STS_ROPC_USERNAME, username);
	oauth2_nv_list_add(log, params, STS_ROPC_PASSWORD, token);

	sts_merge_request_parameters(log, cfg, params);

	ctx = oauth2_http_call_ctx_init(log);
	if (ctx == NULL)
		goto end;

	if (oauth2_http_ctx_auth_add(log, ctx, cfg->ropc_endpoint_auth,
				     params) == false)
		goto end;

	rc = sts_util_oauth_call(log, cfg, ctx, sts_ropc_get_endpoint(cfg),
				 params, rtoken, status_code);

end:

	if (params)
		oauth2_nv_list_free(log, params);
	if (ctx)
		oauth2_http_call_ctx_free(log, ctx);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}
