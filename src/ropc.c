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
