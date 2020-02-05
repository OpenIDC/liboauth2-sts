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

#include <oauth2/http.h>
#include <oauth2/oauth2.h>
#include <oauth2/proto.h>
#include <oauth2/sts.h>

#include "sts_int.h"

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

static const char *sts_ropc_get_username(oauth2_cfg_sts_t *cfg,
					 const char *user)
{
	const char *username = oauth2_cfg_ropc_get_username(cfg->ropc);
	if (username == NULL) {
		// return the client_id by default
		username = oauth2_cfg_ropc_get_client_id(cfg->ropc);
		goto end;
	}
	if (strcmp(username, "*") == 0)
		// special handling to pull the authenticated username from a
		// previously triggered module
		username = user;
end:

	return username;
}

bool sts_ropc_exec(oauth2_log_t *log, oauth2_cfg_sts_t *cfg, const char *token,
		   const char *user, char **rtoken, oauth2_uint_t *status_code)
{
	// TODO:
	// sts_merge_request_parameters(log, cfg, params);
	return oauth2_ropc_exec(log, cfg->ropc,
				sts_ropc_get_username(cfg, user), token, rtoken,
				status_code);
}
