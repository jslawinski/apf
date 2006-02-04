/*
 * active port forwarder - software for secure forwarding
 * Copyright (C) 2003-2006 jeremian <jeremian [at] poczta.fm>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include <config.h>

#include <stdlib.h>
#include <string.h>

#include "http_proxy_options_struct.h"
#include "string_functions.h"

/*
 * Function name: HttpProxyOptions_new
 * Description: Create and initialize new HttpProxyOptions structure.
 * Returns: Pointer to newly created HttpProxyOptions structure.
 */

HttpProxyOptions*
HttpProxyOptions_new()
{
  HttpProxyOptions* tmp = calloc(1, sizeof(HttpProxyOptions));
  if (tmp == NULL) {
    return NULL;
  }
  tmp->proxyauth_type = PROXYAUTH_TYPE_NOTSET;
  return tmp;
}

/*
 * Function name: HttpProxyOptions_free
 * Description: Free the memory allocated for HttpProxyOptions structure.
 * Arguments: hpo - pointer to pointer to HttpProxyOptions structure
 */

void
HttpProxyOptions_free(HttpProxyOptions** hpo)
{
  if (hpo == NULL) {
    return;
  }
  if ((*hpo) == NULL) {
    return;
  }
  if ((*hpo)->proxyname) {
    free((*hpo)->proxyname);
    (*hpo)->proxyname = NULL;
  }
  if ((*hpo)->proxyport) {
    free((*hpo)->proxyport);
    (*hpo)->proxyport = NULL;
  }
  if ((*hpo)->proxyauth_cred) {
    free((*hpo)->proxyauth_cred);
    (*hpo)->proxyauth_cred = NULL;
  }
  free((*hpo));
  (*hpo) = NULL;
}

/*
 * Function name: HttpProxyOptions_set_proxyname
 * Description: Set name of the http proxy server.
 * Arguments: hpo - pointer to HttpProxyOptions structure
 *            proxyname - name of the http proxy server
 */

void
HttpProxyOptions_set_proxyname(HttpProxyOptions* hpo, char* proxyname)
{
  if (hpo == NULL) {
    return;
  }
  string_cp(&(hpo->proxyname), proxyname);
}

/*
 * Function name: HttpProxyOptions_set_proxyport
 * Description: Set port on which http proxy server is listening.
 * Arguments: hpo - pointer to HttpProxyOptions structure
 *            proxyport - port on which http proxy server is listening
 */

void
HttpProxyOptions_set_proxyport(HttpProxyOptions* hpo, char* proxyport)
{
  if (hpo == NULL) {
    return;
  }
  string_cp(&(hpo->proxyport), proxyport);
}

/*
 * Function name: HttpProxyOptions_set_proxyauth_cred
 * Description: Set credentials for http proxy server.
 * Arguments: hpo - pointer to HttpProxyOptions structure
 *            proxyauth_cred - credentials for http proxy server
 */

void
HttpProxyOptions_set_proxyauth_cred(HttpProxyOptions* hpo, char* proxyauth_cred)
{
  if (hpo == NULL) {
    return;
  }
  string_cp(&(hpo->proxyauth_cred), proxyauth_cred);
}

/*
 * Function name: HttpProxyOptions_set_proxyauth_type
 * Description: Set type of the proxy authorization.
 * Arguments: hpo - pointer to HttpProxyOptions structure
 *            proxyauth_type - type of the proxy authorization
 */

void
HttpProxyOptions_set_proxyauth_type(HttpProxyOptions* hpo, char proxyauth_type)
{
  if (hpo == NULL) {
    return;
  }
  if (hpo->proxyauth_type != PROXYAUTH_TYPE_NOTSET) {
    hpo->proxyauth_type = PROXYAUTH_TYPE_WRONG;
    return;
  }
  hpo->proxyauth_type = proxyauth_type;
}

/*
 * Function name: HttpProxyOptions_get_proxyname
 * Description: Get name of the http proxy server
 * Arguments: hpo - pointer to HttpProxyOptions structure
 * Returns: Name of the http proxy server or NULL, if name not set.
 */

char*
HttpProxyOptions_get_proxyname(HttpProxyOptions* hpo)
{
  if (hpo == NULL) {
    return NULL;
  }
  return hpo->proxyname;
}

/*
 * Function name: HttpProxyOptions_get_proxyport
 * Description: Get port on which http proxy server is listening.
 * Arguments: hpo - pointer to HttpProxyOptions structure
 * Returns: Port on which http proxy server is listening or NULL, if port not set.
 */

char*
HttpProxyOptions_get_proxyport(HttpProxyOptions* hpo)
{
  if (hpo == NULL) {
    return NULL;
  }
  return hpo->proxyport;
}

/*
 * Function name: HttpProxyOptions_get_proxyauth_cred
 * Description: Get credentials for http proxy server.
 * Arguments: hpo - pointer to HttpProxyOptions structure
 * Returns: Credentials for http proxy server or NULL, if not set.
 */

char*
HttpProxyOptions_get_proxyauth_cred(HttpProxyOptions* hpo)
{
  if (hpo == NULL) {
    return NULL;
  }
  return hpo->proxyauth_cred;
}

/*
 * Function name: HttpProxyOptions_get_proxyauth_type
 * Description: Get type of the proxy authorization.
 * Arguments: hpo - pointer to HttpProxyOptions structure
 * Returns: Type of the proxy authorization.
 */

char
HttpProxyOptions_get_proxyauth_type(HttpProxyOptions* hpo)
{
  if (hpo == NULL) {
    return PROXYAUTH_TYPE_WRONG;
  }
  return hpo->proxyauth_type;
}

/*
 * Function name: HttpProxyOptions_use_https
 * Description: Enable use of https proxy instead of http proxy.
 * Arguments: hpo - pointer to HttpProxyOptions structure
 */

void
HttpProxyOptions_use_https(HttpProxyOptions* hpo)
{
  if (hpo == NULL) {
    return;
  }
  hpo->useHttps = USEHTTPS_ON;
}

/*
 * Function name: HttpProxyOptions_is_https
 * Description: Check if the use of https proxy is enabled.
 * Arguments: hpo - pointer to HttpProxyOptions structure
 * Returns: USEHTTPS_OFF - http proxy will be used
 *          USEHTTPS_ON - https proxy will be used
 */

char
HttpProxyOptions_is_https(HttpProxyOptions* hpo)
{
  if (hpo == NULL) {
    return USEHTTPS_OFF;
  }
  return hpo->useHttps;
}
