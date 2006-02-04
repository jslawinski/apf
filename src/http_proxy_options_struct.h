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

#ifndef _JS_HTTP_PROXY_OPTIONS_STRUCT_H
#define _JS_HTTP_PROXY_OPTIONS_STRUCT_H

#define PROXYAUTH_TYPE_NOTSET 0
#define PROXYAUTH_TYPE_WRONG -1
#define PROXYAUTH_TYPE_BASIC 1

#define USEHTTPS_OFF 0
#define USEHTTPS_ON 1

typedef struct {
  char* proxyname;
  char* proxyport;
  char* proxyauth_cred;
  char proxyauth_type;
  char useHttps;
} HttpProxyOptions;

/* 'constructor' */
HttpProxyOptions* HttpProxyOptions_new();
/* 'destructor' */
void HttpProxyOptions_free(HttpProxyOptions** hpo);
/* setters */
void HttpProxyOptions_set_proxyname(HttpProxyOptions* hpo, char* proxyname);
void HttpProxyOptions_set_proxyport(HttpProxyOptions* hpo, char* proxyport);
void HttpProxyOptions_set_proxyauth_cred(HttpProxyOptions* hpo, char* proxyauth_cred);
void HttpProxyOptions_set_proxyauth_type(HttpProxyOptions* hpo, char proxyauth_type);
/* getters */
char* HttpProxyOptions_get_proxyname(HttpProxyOptions* hpo);
char* HttpProxyOptions_get_proxyport(HttpProxyOptions* hpo);
char* HttpProxyOptions_get_proxyauth_cred(HttpProxyOptions* hpo);
char HttpProxyOptions_get_proxyauth_type(HttpProxyOptions* hpo);
/* other */
void HttpProxyOptions_use_https(HttpProxyOptions* hpo);
char HttpProxyOptions_is_https(HttpProxyOptions* hpo);

#endif

