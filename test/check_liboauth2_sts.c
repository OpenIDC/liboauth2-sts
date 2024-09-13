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

#include <check.h>
#include <stdlib.h>

#include <oauth2/jose.h>
#include <oauth2/log.h>
#include <oauth2/mem.h>

#include "oauth2/oauth2.h"
#include "oauth2/sts.h"

static oauth2_log_t *_log = 0;

static char *s_payload1 = NULL;
static char *s_payload2 = NULL;
static char *s_jwk = NULL;

static void setup(void)
{
	_log = oauth2_init(OAUTH2_LOG_TRACE1, 0);

	s_payload1 = "{\"iss\":\"https://example.org\"}";
	s_payload2 = "{\"aud\":\"https://another.org\"}";
	s_jwk =
	    "{\"kty\":\"RSA\",\"kid\":\"IbLjLR7-C1q0-"
	    "ypkueZxGIJwBQNaLg46DZMpnPW1kps\",\"e\":\"AQAB\",\"n\":"
	    "\"iGeTXbfV5bMppx7o7qMLCuVIKqbBa_qOzBiNNpe0K8rjg7-1z9GCuSlqbZtM0_"
	    "5BQ6bGonnSPD--"
	    "PowhFdivS4WNA33O0Kl1tQ0wdH3TOnwueIO9ahfW4q0BGFvMObneK-tjwiNMj1l-"
	    "cZt8pvuS-3LtTWIzC-"
	    "hTZM4caUmy5olm5PVdmru6C6V5rxkbYBPITFSzl5mpuo_C6RV_"
	    "MYRwAh60ghs2OEvIWDrJkZnYaF7sjHC9j-"
	    "4kfcM5oY7Zhg8KuHyloudYNzlqjVAPd0MbkLkh1pa8fmHsnN6cgfXYtFK7Z8WjYDUA"
	    "hTH1JjZCVSFN55A-51dgD4cQNzieLEEkJw\","
	    "\"d\":\"Xc9d-"
	    "kZERQVC0Dzh1b0sCwJE75Bf1fMr4hHAjJsovjV641ElqRdd4Borp9X2sJVcLTq1wWg"
	    "mvmjYXgvhdTTg2f-"
	    "vS4dqhPcGjM3VVUhzzPU6wIdZ7W0XzC1PY4E-ozTBJ1Nr-"
	    "EhujuftnhRhVjYOkAAqU94FXVsaf2mBAKg-"
	    "8WzrWx2MeWjfLcE79DmSL9Iw2areKVRGlKddIIPnHb-"
	    "Mw9HB7ZCyVTC1v5sqhQPy6qPo8XHdQju_EYRlIOMksU8kcb20R_ezib_"
	    "rHuVwJVlTNk6MvFUIj4ayXdX13Qy4kTBRiQM7pumPaypEE4CrAfTWP0AYnEwz_"
	    "FGluOpMZNzoAQ\"}";
}

static void teardown(void)
{
	oauth2_shutdown(_log);
}

START_TEST(test_sts_jwt)
{
	bool rc = false;
	oauth2_sts_cfg_t *cfg = NULL;
	const char *rv = NULL;
	oauth2_uint_t status_code = 0;
	char *target_token = NULL;
	char *expr = NULL;
	oauth2_cfg_token_verify_t *verify = NULL;
	json_t *json_payload = NULL;
	char *val = NULL;

	cfg = oauth2_sts_cfg_create(_log, "/");

#ifdef OAUTH2_WITH_JQ
	rv = sts_cfg_set_exchange(_log, cfg, "jwt", s_jwk, NULL, "bla");
	ck_assert_str_eq(rv, "could not compile the JQ expression: 'bla'");
	expr = ". + { mykey: \"myval\" }";
#endif

	rv = sts_cfg_set_exchange(_log, cfg, "jwt", s_jwk,
				  "sub=mysub&jq.cache.name=default", expr);
	ck_assert_ptr_eq(rv, NULL);

	rc = sts_handler(_log, cfg, s_payload1, NULL, &target_token,
			 &status_code);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(target_token, NULL);
	ck_assert_int_eq(status_code, 200);

	rv = oauth2_cfg_token_verify_add_options(_log, &verify, "jwk", s_jwk,
						 "verify.iat=required");
	ck_assert_ptr_eq(rv, NULL);
	rc = oauth2_token_verify(_log, NULL, verify, target_token,
				 &json_payload);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(json_payload, NULL);

	rc = oauth2_json_string_get(_log, json_payload, "sub", &val, NULL);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(val, NULL);
	ck_assert_str_eq(val, "mysub");
	oauth2_mem_free(val);

	rc = oauth2_json_string_get(_log, json_payload, "iss", &val, NULL);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(val, NULL);
	ck_assert_str_eq(val, "https://example.org");
	oauth2_mem_free(val);

#ifdef OAUTH2_WITH_JQ
	rc = oauth2_json_string_get(_log, json_payload, "mykey", &val, NULL);
	ck_assert_int_eq(rc, true);
	ck_assert_ptr_ne(val, NULL);
	ck_assert_str_eq(val, "myval");
	oauth2_mem_free(val);
#endif

	json_decref(json_payload);
	oauth2_cfg_token_verify_free(_log, verify);

	oauth2_mem_free(target_token);
	oauth2_sts_cfg_free(_log, cfg);
}

static Suite *oauth2_check_sts_suite()
{
	Suite *s = suite_create("sts");
	TCase *c = tcase_create("core");

	tcase_add_checked_fixture(c, setup, teardown);

	tcase_add_test(c, test_sts_jwt);

	suite_add_tcase(s, c);

	return s;
}

int main(void)
{
	int n_failed;
	SRunner *sr = srunner_create(suite_create("liboauth2_sts"));
	srunner_add_suite(sr, oauth2_check_sts_suite());
	srunner_run_all(sr, CK_VERBOSE);
	n_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (n_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
