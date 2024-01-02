/***************************************************************************
 *
 * Copyright (C) 2018-2024 - ZmartZone Holding BV - www.zmartzone.eu
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

const char *sts_cfg_set_cc(oauth2_log_t *log, oauth2_sts_cfg_t *cfg,
			   const char *url, const char *options)
{
	char *rv = NULL;

	cfg->cc = oauth2_cfg_cc_init(log);
	if (cfg->cc == NULL) {
		rv = oauth2_strdup("oauth2_cfg_cc_init failed");
		goto end;
	}

	rv = oauth2_cfg_set_cc(log, cfg->cc, url, options);

end:

	return rv;
}

bool sts_cc_exec(oauth2_log_t *log, oauth2_cfg_sts_t *cfg, char **rtoken,
		 oauth2_uint_t *status_code)
{
	return oauth2_cc_exec(log, cfg->cc, rtoken, status_code);
}
