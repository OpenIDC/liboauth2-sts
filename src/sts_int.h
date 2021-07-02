#ifndef _OAUTH2_STS_INT_H_
#define _OAUTH2_STS_INT_H_

/***************************************************************************
 *
 * Copyright (C) 2018-2021 - ZmartZone Holding BV - www.zmartzone.eu
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

typedef enum oauth2_sts_cfg_on_error_t {
	OAUTH2_STS_ON_ERROR_RETURN,
	OAUTH2_STS_PASS
} oauth2_sts_cfg_on_error_t;

typedef struct oauth2_sts_cfg_t {

	oauth2_uint_t type;

	oauth2_cfg_endpoint_t *wstrust_endpoint;
	char *wstrust_applies_to;
	char *wstrust_token_type;
	char *wstrust_value_type;

	oauth2_cfg_ropc_t *ropc;

	oauth2_cfg_endpoint_t *otx_endpoint;
	char *otx_client_id;
	oauth2_nv_list_t *otx_request_parameters;

	oauth2_cache_t *cache;
	char *cache_name;
	oauth2_time_t cache_expiry_s;

	oauth2_cfg_source_token_t *accept_source_token_in;
	oauth2_cfg_token_in_t pass_target_token_in;

	oauth2_sts_cfg_on_error_t on_error;

	char *path;

} oauth2_cfg_sts_t;

void sts_merge_request_parameters(oauth2_log_t *log, oauth2_sts_cfg_t *cfg,
				  oauth2_nv_list_t *source,
				  oauth2_nv_list_t *target);

bool sts_util_oauth_call(oauth2_log_t *log, oauth2_cfg_sts_t *cfg,
			 oauth2_http_call_ctx_t *ctx,
			 const char *token_endpoint,
			 const oauth2_nv_list_t *params, char **rtoken,
			 oauth2_uint_t *status_code);

const char *sts_cfg_set_wstrust(oauth2_log_t *log, oauth2_sts_cfg_t *cfg,
				const char *url,
				const oauth2_nv_list_t *params);
bool sts_wstrust_exec(oauth2_log_t *log, oauth2_cfg_sts_t *cfg,
		      const char *token, char **rtoken,
		      oauth2_uint_t *status_code);

const char *sts_cfg_set_ropc(oauth2_log_t *log, oauth2_sts_cfg_t *cfg,
			     const char *url, const char *options);
bool sts_ropc_exec(oauth2_log_t *log, oauth2_cfg_sts_t *cfg, const char *token,
		   const char *user, char **rtoken, oauth2_uint_t *status_code);

const char *sts_cfg_set_otx(oauth2_log_t *log, oauth2_sts_cfg_t *cfg,
			    const char *url, const oauth2_nv_list_t *params);
bool sts_otx_exec(oauth2_log_t *log, oauth2_cfg_sts_t *cfg, const char *token,
		  char **rtoken, oauth2_uint_t *status_code);

#endif /* _OAUTH2_STS_INT_H_ */
