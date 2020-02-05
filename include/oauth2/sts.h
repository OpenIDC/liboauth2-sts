#ifndef _OAUTH2_STS_H_
#define _OAUTH2_STS_H_

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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <oauth2/cache.h>
#include <oauth2/cfg.h>
#include <oauth2/http.h>
#include <oauth2/log.h>

/*
 * configuration
 */

// TODO: do we want to share these names across Apache/NGINX?
#define STSType "STSType"
#define STSSSLValidateServer "STSSSLValidateServer"
#define STSHTTPTimeOut "STSHTTPTimeOut"
#define STSRequestParameter "STSRequestParameter"
#define STSWSTrustEndpoint "STSWSTrustEndpoint"
#define STSWSTrustEndpointAuth "STSWSTrustEndpointAuth"
#define STSWSTrustAppliesTo "STSWSTrustAppliesTo"
#define STSWSTrustTokenType "STSWSTrustTokenType"
#define STSWSTrustValueType "STSWSTrustValueType"
#define STSROPC "STSROPC"
#define STSOTXEndpoint "STSOTXEndpoint"
#define STSOTXEndpointAuth "STSOTXEndpointAuth"
#define STSOTXClientID "STSOTXClientID"
#define STSCacheExpiresIn "STSCacheExpiresIn"
#define STSAcceptSourceTokenIn "STSAcceptSourceTokenIn"
#define STSPassTargetTokenIn "STSPassTargetTokenIn"
#define STSCache "STSCache"

#define STS_TYPE_DISABLED 0
#define STS_TYPE_WSTRUST 1
#define STS_TYPE_ROPC 2
#define STS_TYPE_OTX 3

OAUTH2_CFG_TYPE_DECLARE(sts, cfg)

oauth2_sts_cfg_t *oauth2_sts_cfg_create(oauth2_log_t *log, const char *path);

#define STS_CFG_SET_FUNC(member, ...)                                          \
	const char *sts_cfg_set_##member(oauth2_sts_cfg_t *, ##__VA_ARGS__);
#define STS_CFG_SET_TAKE1(member) STS_CFG_SET_FUNC(member, const char *)
#define STS_CFG_SET_TAKE2(member)                                              \
	STS_CFG_SET_FUNC(member, const char *, const char *)

STS_CFG_SET_TAKE1(type)
STS_CFG_SET_TAKE1(ssl_validation)
STS_CFG_SET_TAKE1(http_timeout)

STS_CFG_SET_TAKE1(wstrust_endpoint)
STS_CFG_SET_TAKE2(wstrust_endpoint_auth)
STS_CFG_SET_TAKE1(wstrust_applies_to)
STS_CFG_SET_TAKE1(wstrust_token_type)
STS_CFG_SET_TAKE1(wstrust_value_type)

STS_CFG_SET_TAKE1(ropc)

STS_CFG_SET_TAKE1(otx_endpoint)
STS_CFG_SET_TAKE2(otx_endpoint_auth)
STS_CFG_SET_TAKE1(otx_client_id)

STS_CFG_SET_TAKE1(cache_expiry_s)
STS_CFG_SET_TAKE2(request_parameters)
STS_CFG_SET_TAKE2(cache)

// TODO: add post_config that checks the setup per protocol

/*
 * main handler
 */
const char *sts_cfg_set_accept_source_token_in(oauth2_sts_cfg_t *cfg,
					       const char *type,
					       const char *options);

const char *sts_cfg_set_pass_target_token_in(oauth2_sts_cfg_t *cfg,
					     const char *method,
					     const char *options);

int sts_cfg_get_type(oauth2_sts_cfg_t *cfg);
oauth2_cfg_source_token_t *
sts_accept_source_token_in_get(oauth2_log_t *log, oauth2_sts_cfg_t *cfg);
char sts_get_pass_target_token_in(oauth2_sts_cfg_t *cfg);
const char *sts_get_pass_target_token_in_hdr_name(oauth2_sts_cfg_t *cfg);

bool sts_request_handler(oauth2_log_t *log, oauth2_sts_cfg_t *cfg,
			 oauth2_http_request_t *request, const char *user,
			 char **source_token,
			 oauth2_cfg_server_callback_funcs_t *srv_cb,
			 void *srv_cb_ctx,
			 oauth2_http_status_code_t *status_code);
bool sts_handler(oauth2_log_t *log, oauth2_sts_cfg_t *cfg, char *source_token,
		 const char *user, char **target_token,
		 oauth2_http_status_code_t *status_code);

#endif /* _OAUTH2_STS_H_ */
