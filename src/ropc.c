/***************************************************************************
 *
 * Copyright (C) 2018-2023 - ZmartZone Holding BV - www.zmartzone.eu
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
 * @Author: Hans Zandbelt - hans.zandbelt@openidc.com
 *
 **************************************************************************/

#include <oauth2/http.h>
#include <oauth2/oauth2.h>
#include <oauth2/proto.h>
#include <oauth2/sts.h>

#include "sts_int.h"

const char *sts_cfg_set_ropc(oauth2_log_t *log, oauth2_sts_cfg_t *cfg,
			     const char *url, const char *options)
{
	char *rv = NULL;

	cfg->ropc = oauth2_cfg_ropc_init(log);
	if (cfg->ropc == NULL) {
		rv = oauth2_strdup("oauth2_cfg_ropc_init failed");
		goto end;
	}

	rv = oauth2_cfg_set_ropc(log, cfg->ropc, url, options);

end:

	return rv;
}

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
	return oauth2_ropc_exec(log, cfg->ropc,
				sts_ropc_get_username(cfg, user), token, rtoken,
				status_code);
}
