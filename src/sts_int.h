#ifndef _OAUTH2_STS_INT_H_
#define _OAUTH2_STS_INT_H_

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

#include <oauth2/cache.h>
#include <oauth2/cfg.h>
#include <oauth2/http.h>

typedef struct oauth2_sts_cfg_t {

	oauth2_log_t *log;

	oauth2_uint_t type;
	oauth2_flag_t ssl_validation;
	oauth2_uint_t http_timeout;

	char *wstrust_endpoint;
	oauth2_cfg_endpoint_auth_t *wstrust_endpoint_auth;
	char *wstrust_applies_to;
	char *wstrust_token_type;
	char *wstrust_value_type;

	char *ropc_endpoint;
	oauth2_cfg_endpoint_auth_t *ropc_endpoint_auth;
	char *ropc_client_id;
	char *ropc_username;

	char *otx_endpoint;
	oauth2_cfg_endpoint_auth_t *otx_endpoint_auth;
	char *otx_client_id;

	oauth2_cache_t *cache;
	oauth2_time_t cache_expiry_s;

	oauth2_nv_list_t *request_parameters;

	oauth2_cfg_source_token_t *accept_source_token_in;
	oauth2_cfg_token_in_t pass_target_token_in;

	char *path;

} oauth2_cfg_sts_t;

oauth2_flag_t sts_cfg_get_ssl_validation(oauth2_cfg_sts_t *cfg);
oauth2_uint_t sts_cfg_get_http_timeout(oauth2_cfg_sts_t *cfg);

void sts_merge_request_parameters(oauth2_log_t *log, oauth2_cfg_sts_t *cfg,
				  oauth2_nv_list_t *params);

bool sts_util_oauth_call(oauth2_log_t *log, oauth2_cfg_sts_t *cfg,
			 oauth2_http_call_ctx_t *ctx,
			 const char *token_endpoint,
			 const oauth2_nv_list_t *params, char **rtoken,
			 oauth2_uint_t *status_code);

bool sts_wstrust_exec(oauth2_log_t *log, oauth2_cfg_sts_t *cfg,
		      const char *token, char **rtoken,
		      oauth2_uint_t *status_code);
bool sts_ropc_exec(oauth2_log_t *log, oauth2_cfg_sts_t *cfg, const char *token,
		   const char *user, char **rtoken, oauth2_uint_t *status_code);
bool sts_otx_exec(oauth2_log_t *log, oauth2_cfg_sts_t *cfg, const char *token,
		  char **rtoken, oauth2_uint_t *status_code);

#endif /* _OAUTH2_STS_INT_H_ */
