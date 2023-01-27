#ifndef _OAUTH2_STS_H_
#define _OAUTH2_STS_H_

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

#define STSCache "STSCache"
#define STSAcceptSourceTokenIn "STSAcceptSourceTokenIn"
#define STSPassTargetTokenIn "STSPassTargetTokenIn"
#define STSExchange "STSExchange"
#define STSCryptoPassphrase "STSCryptoPassphrase"

// STSExchange <type> <url> <options> (cache.name, cache.expiry, auth,
// ssl_verify, http_timeout, request.parameter, applies_to, token_type,
// value_type)

#define STS_TYPE_DISABLED 0
#define STS_TYPE_WSTRUST 1
#define STS_TYPE_ROPC 2
#define STS_TYPE_OTX 3

OAUTH2_CFG_TYPE_DECLARE(sts, cfg)

oauth2_sts_cfg_t *oauth2_sts_cfg_create(oauth2_log_t *log, const char *path);

// TODO: add post_config that checks the setup per protocol

/*
 * main handler
 */
const char *sts_cfg_set_accept_source_token_in(oauth2_log_t *log,
					       oauth2_sts_cfg_t *cfg,
					       const char *type,
					       const char *options);

const char *sts_cfg_set_pass_target_token_in(oauth2_log_t *log,
					     oauth2_sts_cfg_t *cfg,
					     const char *method,
					     const char *options);

const char *sts_cfg_set_exchange(oauth2_log_t *log, oauth2_sts_cfg_t *cfg,
				 const char *type, const char *url,
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
