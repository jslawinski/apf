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

#include "client_initialization.h"
#include "first_run.h"
#include "network.h"
#include "base64.h"
#include "ssl_routines.h"
#include "client_configuration_struct.h"

int
initialize_client_stage1(ClientRealm* cr, SSL_CTX* ctx, unsigned char* buff, char wanttoexit,
    char ignorePublicKeys)
{
  int n, nlen, elen, len, tmp;
  unsigned int olen;
  X509* server_cert;
  const EVP_MD *md;
  EVP_PKEY* pkey;
  EVP_MD_CTX md_ctx;
  unsigned char *encoded = NULL;
  char b64_encoded[100];
  unsigned char *key_buf = NULL;
  switch (ClientRealm_get_tunnelType(cr)) {
    case 0: {
      if (ip_connect(&tmp, ClientRealm_get_serverName(cr),
            ClientRealm_get_managePort(cr),
            ClientRealm_get_ipFamily(cr),
            ClientRealm_get_localName(cr),
            ClientRealm_get_localPort(cr))) {
#ifdef AF_INET6
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "tcp_connect_%s error for %s, %s",
            (ClientRealm_get_ipFamily(cr) & 0x02) ?
              "ipv4":(ClientRealm_get_ipFamily(cr) & 0x04) ?
                "ipv6":"unspec", ClientRealm_get_serverName(cr), ClientRealm_get_managePort(cr));
#else
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "tcp_connect error for %s, %s", ClientRealm_get_serverName(cr), ClientRealm_get_managePort(cr));
#endif
        if (wanttoexit) {
          exit(1);
        }
        else {
          return 1;
        }
      } 
      SslFd_set_fd(ClientRealm_get_masterSslFd(cr), tmp);
      break;
            }
#ifdef HAVE_LIBPTHREAD 
    case 1: {
      if (initialize_http_proxy_client(&tmp, cr, ctx)) {
#ifdef AF_INET6
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "http_proxy_connect_%s error for %s, %s (proxy: %s, %s)",
            (ClientRealm_get_ipFamily(cr) & 0x02) ?
              "ipv4":(ClientRealm_get_ipFamily(cr) & 0x04) ?
                "ipv6":"unspec", ClientRealm_get_serverName(cr),
                ClientRealm_get_managePort(cr),
                HttpProxyOptions_get_proxyname(ClientRealm_get_httpProxyOptions(cr)),
                HttpProxyOptions_get_proxyport(ClientRealm_get_httpProxyOptions(cr)));
#else 
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "http_proxy_connect error for %s, %s (proxy: %s, %s)", ClientRealm_get_serverName(cr),
            ClientRealm_get_managePort(cr),
            HttpProxyOptions_get_proxyname(ClientRealm_get_httpProxyOptions(cr)),
            HttpProxyOptions_get_proxyport(ClientRealm_get_httpProxyOptions(cr)));
#endif 
        if (wanttoexit) {
          exit(1);
        }
        else {
          return 1;
        }
      }
      SslFd_set_fd(ClientRealm_get_masterSslFd(cr), tmp);
      break;
            }
#endif
    default: {
               aflog(LOG_T_INIT, LOG_I_CRIT,
                   "Unknown tunnel type");
               if (wanttoexit) {
                 exit(1);
               }
               else {
                 return 1;
               }
               break;
             }
  }
  
  SslFd_set_ssl(ClientRealm_get_masterSslFd(cr), SSL_new(ctx));
  if (SSL_set_fd(SslFd_get_ssl(ClientRealm_get_masterSslFd(cr)),
        SslFd_get_fd(ClientRealm_get_masterSslFd(cr))) != 1) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "Problem with initializing ssl... exiting");
    if (wanttoexit) {
      exit(1);
    }
    else {
      close(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)));
      return 2;
    }
  }

  aflog(LOG_T_INIT, LOG_I_INFO,
      "Trying SSL_connect");
  if ((n = SSL_connect(SslFd_get_ssl(ClientRealm_get_masterSslFd(cr)))) == 1) {
    if ((server_cert = SSL_get_peer_certificate(SslFd_get_ssl(ClientRealm_get_masterSslFd(cr)))) == NULL) {
      aflog(LOG_T_MAIN, LOG_I_CRIT,
          "Server did not present a certificate... exiting");
      exit(1);
    }
    /* FIXME: change almost everything here */
    pkey = X509_get_pubkey(server_cert);
    if (pkey == NULL) {
      aflog(LOG_T_MAIN, LOG_I_CRIT,
          "Server's public key is invalid... exiting");
      exit(1);
    }
    nlen = BN_num_bytes(pkey->pkey.rsa->n);
    elen = BN_num_bytes(pkey->pkey.rsa->e);
    len = nlen + elen;
    key_buf = malloc(len);
    if (key_buf == NULL) {
      aflog(LOG_T_MAIN, LOG_I_CRIT,
          "Cannot allocate memory for server's public key checking... exiting");
      exit(1);
    }
    BN_bn2bin(pkey->pkey.rsa->n, key_buf);
    BN_bn2bin(pkey->pkey.rsa->e, key_buf + nlen);
    md = EVP_md5();
    EVP_DigestInit(&md_ctx, md);
    EVP_DigestUpdate(&md_ctx, key_buf, len);
    encoded = calloc(1, EVP_MAX_MD_SIZE+1);
    if (encoded == NULL) {
      aflog(LOG_T_MAIN, LOG_I_CRIT,
          "Cannot allocate memory for server's public key checking... exiting");
      exit(1);
    }
    EVP_DigestFinal(&md_ctx, encoded, &olen);

    if (b64_ntop(encoded, olen, b64_encoded, 100) == -1) {
      aflog(LOG_T_MAIN, LOG_I_CRIT,
          "Problem with base64 encoding... exiting");
      exit(1);
    }
    
    switch (check_public_key(get_store_filename(), ClientRealm_get_serverName(cr), b64_encoded)) {
      case SSL_PUBLIC_KEY_VALID:
        /* public key is ok - do nothing */
        break;
      case SSL_PUBLIC_KEY_NOT_KNOWN:
        aflog(LOG_T_MAIN, LOG_I_WARNING,
            "WARNING: implicitly added new server's public key to the list of known hosts");
        add_public_key(get_store_filename(), ClientRealm_get_serverName(cr), b64_encoded);
        break;
      default:
        if (ignorePublicKeys) {
          aflog(LOG_T_MAIN, LOG_I_WARNING,
              "WARNING: Invalid server's public key... ignoring");
        }
        else {
          aflog(LOG_T_MAIN, LOG_I_CRIT,
              "Invalid server's public key... exiting");
          aflog(LOG_T_MAIN, LOG_I_CRIT,
              "Please delete conflicting entry in %s or use '--ignorepkeys' option",
              get_store_filename());
          exit(1);
        }
    }

    memset(key_buf, 0, len);
    free(key_buf);
    free(encoded);

    aflog(LOG_T_INIT, LOG_I_INFO,
        "SSL_connect successful");
  }
  else {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "SSL_connect has failed (%d | %d)... exiting", n,
        SSL_get_error(SslFd_get_ssl(ClientRealm_get_masterSslFd(cr)), n));
    if (wanttoexit) {
      exit(1);
    }
    else {
      close(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)));
      return 3;
    }
  }

  buff[0] = AF_S_LOGIN;
  buff[1] = ClientRealm_get_password(cr)[0];
  buff[2] = ClientRealm_get_password(cr)[1];
  buff[3] = ClientRealm_get_password(cr)[2];
  buff[4] = ClientRealm_get_password(cr)[3];

  return 0;
}

int
initialize_client_stage2(ClientRealm* cr, unsigned char* buff, char wanttoexit)
{
  SslFd_send_message(ClientRealm_get_realmType(cr) | TYPE_SSL | TYPE_ZLIB,
      ClientRealm_get_masterSslFd(cr), buff, 5);
  buff[0] = 0;
  SslFd_get_message(ClientRealm_get_realmType(cr) | TYPE_SSL | TYPE_ZLIB,
      ClientRealm_get_masterSslFd(cr), buff, -5);

  if ( buff[0] == 0 ) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "Connection with afserver failed");
    if (wanttoexit) {
      exit(1);
    }
    else {
      close(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)));
      return 1;
    }
  }
  if ( buff[0] == AF_S_WRONG ) {
    aflog(LOG_T_INIT, LOG_I_ERR,
        "Wrong password");
    if (wanttoexit) {
      exit(1);
    }
    else {
      close(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)));
      return 1;
    }
  }
  if ( buff[0] == AF_S_CANT_OPEN ) {
    aflog(LOG_T_INIT, LOG_I_ERR,
        "Server is full");
    if (wanttoexit) {
      exit(1);
    }
    else {
      close(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)));
      return 1;
    }
  }
  if ( buff[0] != AF_S_LOGIN ) {
    aflog(LOG_T_INIT, LOG_I_ERR,
        "Incompatible server type or server full");
    if (wanttoexit) {
      exit(1);
    }
    else {
      close(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)));
      return 1;
    }
  }

  ClientRealm_set_realmType(cr, buff[3]);
  ClientRealm_set_usersLimit(cr, buff[1] * 256 + buff[2]);
  return 0;
}

int
initialize_client_stage3(ClientRealm* cr, int* buflength, fd_set* allset, fd_set* wset, int* maxfdp1,
    char wanttoexit)
{
  int i;
  socklen_t len;
  ConnectUser** usersTable;
  usersTable = calloc(ClientRealm_get_usersLimit(cr), sizeof(ConnectUser*));
  if (usersTable == NULL) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "Calloc error - unable to successfully communicate with server");
    if (wanttoexit) {
      exit(1);
    }
    else {
      close(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)));
      return 1;
    }
  }
  ClientRealm_set_usersTable(cr, usersTable);
  for (i = 0; i < ClientRealm_get_usersLimit(cr); ++i) {
    usersTable[i] = ConnectUser_new();
    if (usersTable[i] == NULL) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "Calloc error - unable to successfully communicate with server");
      if (wanttoexit) {
        exit(1);
      }
      else {
        close(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)));
        return 1;
      }
    }
  }

  len = 4;
  if (getsockopt(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)), SOL_SOCKET, SO_SNDBUF, buflength, &len) == -1) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "Can't get socket send buffer size - exiting...");
    if (wanttoexit) {
      exit(1);
    }
    else {
      close(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)));
      return 2;
    }
  }
  
  FD_ZERO(allset);
  FD_ZERO(wset);

  FD_SET(SslFd_get_fd(ClientRealm_get_masterSslFd(cr)), allset);
  (*maxfdp1) = SslFd_get_fd(ClientRealm_get_masterSslFd(cr)) + 1;
  return 0;
}
