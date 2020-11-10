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

#include <stdlib.h>
#include <time.h>

#include <oauth2/http.h>
#include <oauth2/mem.h>
#include <oauth2/oauth2.h>
#include <oauth2/sts.h>

#include "sts_int.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#define STS_WSTRUST_TOKEN_TYPE_SAML20                                          \
	"http://docs.oasis-open.org/wss/"                                      \
	"oasis-wss-saml-token-profile-1.1#SAMLV2.0"
#define STS_WSTRUST_TOKEN_TYPE_SAML11                                          \
	"http://docs.oasis-open.org/wss/"                                      \
	"oasis-wss-saml-token-profile-1.1#SAMLV1.1"

#define STS_WSTRUST_APPLIES_TO_DEFAULT NULL
#define STS_WSTRUST_TOKEN_TYPE_DEFAULT STS_WSTRUST_TOKEN_TYPE_SAML20
#define STS_WSTRUST_VALUE_TYPE_DEFAULT NULL

#define STS_WSTRUST_XML_SOAP_NS "http://www.w3.org/2003/05/soap-envelope"
#define STS_WSTRUST_XML_WSTRUST_NS                                             \
	"http://docs.oasis-open.org/ws-sx/ws-trust/200512"
#define STS_WSTRUST_XML_WSSE_NS                                                \
	"http://docs.oasis-open.org/wss/2004/01/"                              \
	"oasis-200401-wss-wssecurity-secext-1.0.xsd"
#define STS_WSTRUST_XML_WSU_NS                                                 \
	"http://docs.oasis-open.org/wss/2004/01/"                              \
	"oasis-200401-wss-wssecurity-utility-1.0.xsd"
#define STS_WSTRUST_XML_WSA_NS "http://www.w3.org/2005/08/addressing"
#define STS_WSTRUST_XML_WSP_NS "http://schemas.xmlsoap.org/ws/2004/09/policy"

#define STS_WSTRUST_ACTION STS_WSTRUST_XML_WSTRUST_NS "/RST/Issue"
#define STS_WSTRUST_REQUEST_TYPE STS_WSTRUST_XML_WSTRUST_NS "/Issue"
#define STS_WSTRUST_KEY_TYPE STS_WSTRUST_XML_WSTRUST_NS "/SymmetricKey"

const char *sts_cfg_set_wstrust(oauth2_sts_cfg_t *cfg, const char *url,
				const oauth2_nv_list_t *params)
{
	char *rv = NULL;

	cfg->wstrust_endpoint = oauth2_cfg_endpoint_init(cfg->log);
	if (cfg->wstrust_endpoint == NULL) {
		rv = oauth2_strdup("oauth2_cfg_endpoint_init failed");
		goto end;
	}

	rv = oauth2_cfg_set_endpoint(cfg->log, cfg->wstrust_endpoint, url,
				     params, NULL);
	if (rv != NULL)
		goto end;

	cfg->wstrust_applies_to =
	    oauth2_strdup(oauth2_nv_list_get(cfg->log, params, "applies_to"));
	cfg->wstrust_token_type =
	    oauth2_strdup(oauth2_nv_list_get(cfg->log, params, "token_type"));
	cfg->wstrust_value_type =
	    oauth2_strdup(oauth2_nv_list_get(cfg->log, params, "value_type"));

end:

	return rv;
}

static const char *sts_cfg_wstrust_get_applies_to(oauth2_cfg_sts_t *cfg)
{
	if (cfg->wstrust_applies_to == NULL)
		return STS_WSTRUST_APPLIES_TO_DEFAULT;
	return cfg->wstrust_applies_to;
}

static const char *sts_cfg_wstrust_get_token_type(oauth2_cfg_sts_t *cfg)
{
	if (cfg->wstrust_token_type == NULL)
		return STS_WSTRUST_TOKEN_TYPE_DEFAULT;
	return cfg->wstrust_token_type;
}

static const char *sts_cfg_wstrust_get_value_type(oauth2_cfg_sts_t *cfg)
{
	if (cfg->wstrust_value_type == NULL)
		return STS_WSTRUST_VALUE_TYPE_DEFAULT;
	return cfg->wstrust_value_type;
}

// clang-format off
const char *wstrust_binary_token_template =
    "<wsse:BinarySecurityToken xmlns:wsu=\"" STS_WSTRUST_XML_WSU_NS "\" wsu:Id=\"%s\" ValueType=\"%s\">"
    "%s"
    "</wsse:BinarySecurityToken>";
// clang-format on

#define STS_WSTRUST_RST_SIZE_MAX 2048

static char *sts_wstrust_get_rst_binary(oauth2_cfg_sts_t *cfg,
					const char *token,
					const char *value_type)
{
	char *rv = NULL;
	char buf[STS_WSTRUST_RST_SIZE_MAX];
	char *wsuId = "Me";
	char *b64 = NULL;

	if (oauth2_base64_encode(NULL, (const uint8_t *)token, strlen(token),
				 &b64) == false)
		goto end;

	oauth2_snprintf(buf, STS_WSTRUST_RST_SIZE_MAX,
			wstrust_binary_token_template, wsuId, value_type, b64);
	oauth2_mem_free(b64);

	rv = oauth2_strdup(buf);

end:

	return rv;
}

static char *sts_wstrust_get_rst(oauth2_cfg_sts_t *cfg, const char *token)
{
	const char *value_type = sts_cfg_wstrust_get_value_type(cfg);
	if (value_type == NULL)
		return oauth2_strdup(token);
	return sts_wstrust_get_rst_binary(cfg, token, value_type);
}

// clang-format off
static const char *sts_wstrust_soap_call_template =
    "<s:Envelope xmlns:s=\"" STS_WSTRUST_XML_SOAP_NS "\">"
    "	<s:Header>"
    "		<wsse:Security xmlns:wsse=\"" STS_WSTRUST_XML_WSSE_NS "\">"
    "			<wsu:Timestamp xmlns:wsu=\"" STS_WSTRUST_XML_WSU_NS "\" wsu:Id=\"%s\">"
    "				<wsu:Created>%s</wsu:Created>"
    "				<wsu:Expires>%s</wsu:Expires>"
    "			</wsu:Timestamp>"
    "%s"
    "		</wsse:Security>"
    "		<wsa:To xmlns:wsa=\"" STS_WSTRUST_XML_WSA_NS "\">%s</wsa:To>"
    "		<wsa:Action xmlns:wsa=\"" STS_WSTRUST_XML_WSA_NS "\">%s</wsa:Action>"
    "	</s:Header>"
    "	<s:Body><wst:RequestSecurityToken xmlns:wst=\"" STS_WSTRUST_XML_WSTRUST_NS "\">"
    "		<wst:TokenType>%s</wst:TokenType>"
    "		<wst:RequestType>%s</wst:RequestType>"
    "		<wsp:AppliesTo xmlns:wsp=\"" STS_WSTRUST_XML_WSP_NS "\">"
    "			<wsa:EndpointReference xmlns:wsa=\"" STS_WSTRUST_XML_WSA_NS "\">"
    "				<wsa:Address>%s</wsa:Address>"
    "			</wsa:EndpointReference>"
    "		</wsp:AppliesTo>"
    "		<wst:KeyType>%s</wst:KeyType>"
    "		</wst:RequestSecurityToken>"
    "	</s:Body>"
    "</s:Envelope>";
// clang-format on

#define STS_WSTRUST_STR_SIZE 255
/*
 static void print_xpath_nodes(request_rec *r, xmlDocPtr doc,
 xmlNodeSetPtr nodes) {
 xmlNodePtr cur;
 int size;
 int i;

 size = (nodes) ? nodes->nodeNr : 0;

 sts_debug(r, "Result (%d nodes):\n", size);
 for (i = 0; i < size; ++i) {

 if (nodes->nodeTab[i]->type == XML_NAMESPACE_DECL) {
 xmlNsPtr ns;

 ns = (xmlNsPtr) nodes->nodeTab[i];
 cur = (xmlNodePtr) ns->next;
 if (cur->ns) {
 sts_debug(r, "= namespace \"%s\"=\"%s\" for node %s:%s\n",
 ns->prefix, ns->href, cur->ns->href, cur->name);
 } else {
 sts_debug(r, "= namespace \"%s\"=\"%s\" for node %s\n",
 ns->prefix, ns->href, cur->name);
 }
 } else if (nodes->nodeTab[i]->type == XML_ELEMENT_NODE) {
 cur = nodes->nodeTab[i];
 if (cur->ns) {
 sts_debug(r, "= element node \"%s:%s\"\n", cur->ns->href,
 cur->name);
 } else {
 sts_debug(r, "= element node \"%s\"\n", cur->name);
 }
 } else {
 cur = nodes->nodeTab[i];
 sts_debug(r, "= node \"%s\": type %d\n", cur->name, cur->type);
 }
 }
 }
 */
static int sts_execute_xpath_expression(oauth2_log_t *log,
					oauth2_cfg_sts_t *cfg,
					const char *sXmlStr,
					const char *sPathExpr, char **rvalue)
{
	xmlDocPtr doc = NULL;
	xmlXPathContextPtr xpathCtx = NULL;
	xmlXPathObjectPtr xpathObj = NULL;
	xmlChar *xmlPathExpr = NULL;
	const xmlChar *xmlValue = NULL;
	xmlBufferPtr xmlBuf = NULL;
	int rv = -1;

	doc = xmlParseMemory(sXmlStr, strlen(sXmlStr));
	if (doc == NULL) {
		oauth2_error(log, "Error: unable to parse string \"%s\"\n",
			     sXmlStr);
		goto out;
	}

	xpathCtx = xmlXPathNewContext(doc);
	if (xpathCtx == NULL) {
		oauth2_error(log,
			     "Error: unable to create new XPath context\n");
		goto out;
	}

	if (xmlXPathRegisterNs(xpathCtx, (const xmlChar *)"s",
			       (const xmlChar *)STS_WSTRUST_XML_SOAP_NS) != 0) {
		oauth2_error(log, "Error: unable to register NS");
		goto out;
	}

	if (xmlXPathRegisterNs(xpathCtx, (const xmlChar *)"wst",
			       (const xmlChar *)STS_WSTRUST_XML_WSTRUST_NS) !=
	    0) {
		oauth2_error(log, "Error: unable to register NS");
		goto out;
	}

	if (xmlXPathRegisterNs(xpathCtx, (const xmlChar *)"wsse",
			       (const xmlChar *)STS_WSTRUST_XML_WSSE_NS) != 0) {
		oauth2_error(log, "Error: unable to register NS");
		goto out;
	}

	xmlPathExpr = xmlCharStrdup(sPathExpr);
	xpathObj = xmlXPathEvalExpression(xmlPathExpr, xpathCtx);
	if (xpathObj == NULL) {
		oauth2_error(
		    log, "Error: unable to evaluate xpath expression \"%s\"\n",
		    xmlPathExpr);
		goto out;
	}

	/* Print results */
	// print_xpath_nodes(r, doc, xpathObj->nodesetval);
	if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr > 0) {
		xmlBuf = xmlBufferCreate();
		xmlNodeDump(xmlBuf, doc,
			    xpathObj->nodesetval->nodeTab[0]->xmlChildrenNode,
			    0, 0);

		xmlValue = xmlBufferContent(xmlBuf);
		if (xmlValue != NULL)
			*rvalue = oauth2_strdup((const char *)xmlValue);
	}

	if (*rvalue == NULL)
		oauth2_warn(log, "no value found for xpath expression: %s",
			    sPathExpr);
	else
		oauth2_debug(log,
			     "returning value for xpath expression: %s [%s]",
			     *rvalue, sPathExpr);

	rv = 0;

out:

	if (xmlBuf)
		xmlBufferFree(xmlBuf);
	if (xmlPathExpr)
		xmlFree(xmlPathExpr);
	if (xpathObj)
		xmlXPathFreeObject(xpathObj);
	if (xpathCtx)
		xmlXPathFreeContext(xpathCtx);
	if (doc)
		xmlFreeDoc(doc);

	return rv;
}

#define STS_WSTRUST_EXPR_TOKEN_TEMPLATE                                        \
	"/s:Envelope"                                                          \
	"/s:Body"                                                              \
	"/wst:RequestSecurityTokenResponseCollection"                          \
	"/wst:RequestSecurityTokenResponse"                                    \
	"/wst:RequestedSecurityToken"

#define STS_WSTRUST_EXPR_BINARY_TOKEN_TEMPLATE                                 \
	STS_WSTRUST_EXPR_TOKEN_TEMPLATE                                        \
	"/wsse:BinarySecurityToken[@ValueType='%s']"

#define STS_WSTRUST_XPATH_EXPR_MAX 1024

// TBD: parse timestamps etc. in the RSTR or leave that (still) up to the token
// recipient
static int sts_wstrust_parse_token(oauth2_log_t *log, oauth2_cfg_sts_t *cfg,
				   const char *response, const char *token_type,
				   char **rtoken)
{
	char *rvalue = NULL;
	size_t len = 0;
	char expr[STS_WSTRUST_XPATH_EXPR_MAX];

	xmlInitParser();

	if ((strcmp(token_type, STS_WSTRUST_TOKEN_TYPE_SAML20) == 0) ||
	    (strcmp(token_type, STS_WSTRUST_TOKEN_TYPE_SAML11) == 0)) {

		// straight copy of the complete (XML) token
		if ((sts_execute_xpath_expression(
			 log, cfg, response, STS_WSTRUST_EXPR_TOKEN_TEMPLATE,
			 &rvalue) < 0) ||
		    (rvalue == NULL)) {
			oauth2_error(log,
				     "sts_execute_xpath_expression failed!");
			goto out;
		}

		*rtoken = rvalue;

	} else {

		// base64 decode BinarySecurityToken; TBD: possibly do this in
		// an
		// optional/configurable way
		oauth2_snprintf(expr, STS_WSTRUST_XPATH_EXPR_MAX,
				STS_WSTRUST_EXPR_BINARY_TOKEN_TEMPLATE,
				token_type);
		if ((sts_execute_xpath_expression(log, cfg, response, expr,
						  &rvalue) < 0) ||
		    (rvalue == NULL)) {
			oauth2_error(log,
				     "sts_execute_xpath_expression failed!");
			goto out;
		}

		oauth2_base64_decode(log, rvalue, (uint8_t **)rtoken, &len);
		(*rtoken)[len] = '\0';
		oauth2_mem_free(rvalue);
	}

out:

	xmlCleanupParser();

	return (rvalue != NULL);
}

#define STS_WSTRUST_HEADER_SOAP_ACTION "soapAction"
#define STS_WSTRUST_CONTENT_TYPE_SOAP_UTF8 "application/soap+xml; charset=utf-8"

// TODO: dynamically allocate?
#define STS_WSTRUST_REQ_SIZE_MAX 32768

bool sts_wstrust_exec(oauth2_log_t *log, oauth2_cfg_sts_t *cfg,
		      const char *token, char **rtoken,
		      oauth2_uint_t *status_code)
{
	char *response = NULL, *rst = NULL;
	const char *id1 = "_0";
	char created[STS_WSTRUST_STR_SIZE];
	char expires[STS_WSTRUST_STR_SIZE];
	time_t t;
	struct tm tm;
	const char *token_type = sts_cfg_wstrust_get_token_type(cfg);
	bool rc = false;
	oauth2_http_call_ctx_t *ctx = NULL;
	char data[STS_WSTRUST_REQ_SIZE_MAX];

	oauth2_debug(log, "enter");

	time(&t);

	gmtime_r(&t, &tm);
	strftime(created, STS_WSTRUST_STR_SIZE, "%Y-%m-%dT%H:%M:%SZ", &tm);

	t += 300;

	gmtime_r(&t, &tm);
	strftime(expires, STS_WSTRUST_STR_SIZE, "%Y-%m-%dT%H:%M:%SZ", &tm);

	rst = sts_wstrust_get_rst(cfg, token);
	oauth2_snprintf(
	    data, STS_WSTRUST_REQ_SIZE_MAX, sts_wstrust_soap_call_template, id1,
	    created, expires, rst,
	    oauth2_cfg_endpoint_get_url(cfg->wstrust_endpoint),
	    STS_WSTRUST_ACTION, token_type, STS_WSTRUST_REQUEST_TYPE,
	    sts_cfg_wstrust_get_applies_to(cfg), STS_WSTRUST_KEY_TYPE);

	ctx = oauth2_http_call_ctx_init(log);
	if (ctx == NULL)
		goto end;

	if (oauth2_http_ctx_auth_add(
		log, ctx, oauth2_cfg_endpoint_get_auth(cfg->wstrust_endpoint),
		NULL) == false)
		goto end;

	oauth2_http_call_ctx_content_type_set(
	    log, ctx, STS_WSTRUST_CONTENT_TYPE_SOAP_UTF8);
	oauth2_http_call_ctx_ssl_verify_set(
	    log, ctx,
	    oauth2_cfg_endpoint_get_ssl_verify(cfg->wstrust_endpoint));
	oauth2_http_call_ctx_timeout_set(
	    log, ctx,
	    oauth2_cfg_endpoint_get_http_timeout(cfg->wstrust_endpoint));

	oauth2_http_call_ctx_hdr_set(
	    log, ctx, STS_WSTRUST_HEADER_SOAP_ACTION,
	    oauth2_cfg_endpoint_get_url(cfg->wstrust_endpoint));

	if (oauth2_http_call(log,
			     oauth2_cfg_endpoint_get_url(cfg->wstrust_endpoint),
			     data, ctx, &response, status_code) == false)
		goto end;

	if ((*status_code < 200) || (*status_code >= 300))
		goto end;

	rc = sts_wstrust_parse_token(log, cfg, response, token_type, rtoken);

end:

	if (rst)
		oauth2_mem_free(rst);
	if (ctx)
		oauth2_http_call_ctx_free(log, ctx);
	if (response)
		oauth2_mem_free(response);

	oauth2_debug(log, "leave: %d", rc);

	return rc;
}
