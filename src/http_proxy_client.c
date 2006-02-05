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

#include "http_proxy_functions.h"
#include "http_proxy_client.h"
#include "thread_management.h"
#include "network.h"
#include "stats.h"
#include "logging.h"
#include "base64.h"

#ifdef HAVE_LIBPTHREAD
typedef struct {
  int sockfd;
  char *host;
  char *serv;
  HttpProxyOptions* hpo;
  char type;
  SSL_CTX* ctx;
} proxy_argT;

/*
 * Function name: clean_return
 * Description: Closes the connection and exits the thread.
 * Arguments: sockfd - the descriptor of the connection
 */

static void
clean_return(int sockfd)
{
  aflog(LOG_T_MAIN, LOG_I_DEBUG,
      "http proxy: clean_return");
  close(sockfd);
  pthread_exit(NULL);
}

/*
 * Function name: http_proxy_client
 * Description: Function responsible for the client part of the http proxy connection.
 * Arguments: vptr - the structure with all the information needed for http proxy tunnel
 */

void*
http_proxy_client(void *vptr)
{
  char tab[9000];
  connection conn;
  header hdr;
	int j, n, maxfdp1;
  fd_set rset, allset;
  struct timeval tv;
  int timeout = 5;
  int tmp;
  char *host, *serv, *proxyname, *proxyport, *credentials, *name = "";
  char b64cred[100];
  char type, authtype, https;
  SSL_CTX* ctx;
  proxy_argT *proxy_argptr;

  start_critical_section();
  proxy_argptr = (proxy_argT *) vptr;
  
  host = proxy_argptr->host;
  serv = proxy_argptr->serv;
  proxyname = HttpProxyOptions_get_proxyname(proxy_argptr->hpo);
  proxyport = HttpProxyOptions_get_proxyport(proxy_argptr->hpo);
  credentials = HttpProxyOptions_get_proxyauth_cred(proxy_argptr->hpo);
  type = proxy_argptr->type;
  authtype = HttpProxyOptions_get_proxyauth_type(proxy_argptr->hpo);
  conn.sockfd = proxy_argptr->sockfd;
  https = HttpProxyOptions_is_https(proxy_argptr->hpo);
  ctx = proxy_argptr->ctx;

  broadcast_condition();
  end_critical_section();

  conn.postFd = SslFd_new();
  conn.getFd = SslFd_new();
  conn.tmpFd = SslFd_new();
  if ((conn.postFd == NULL) || (conn.getFd == NULL) || (conn.tmpFd == NULL)) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "http%s proxy: Can't allocate memory... exiting.", name);
    exit(1);
  }
  
  if (https) {
    name = "s";
    SslFd_set_ssl(conn.postFd, SSL_new(ctx));
    SslFd_set_ssl(conn.getFd, SSL_new(ctx));
    SslFd_set_ssl(conn.tmpFd, SSL_new(ctx));
    if ((SslFd_get_ssl(conn.postFd) == NULL) ||
        (SslFd_get_ssl(conn.getFd) == NULL) ||
        (SslFd_get_ssl(conn.tmpFd) == NULL)) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "http%s proxy: Can't allocate memory... exiting.", name);
      exit(1);
    }
  }
  
  if (authtype == PROXYAUTH_TYPE_WRONG) {
    aflog(LOG_T_MAIN, LOG_I_WARNING,
        "Wrong type of proxy authorizaton --> switching to no authorization");
    credentials = NULL;
  }
  
  if (credentials) {
    if (b64_ntop((unsigned char*)credentials, strlen(credentials), b64cred, 100) == -1) {
      aflog(LOG_T_MAIN, LOG_I_ERR,
          "Cannot encode credentials for proxy authorization");
      b64cred[0] = 0;
    }
    else {
      if (authtype == PROXYAUTH_TYPE_NOTSET) {
        authtype = PROXYAUTH_TYPE_BASIC;
      }
    }
  }

  FD_ZERO(&allset);
  tv.tv_usec = 0;
  tv.tv_sec = timeout;

  memset(conn.id, 0, 10);
  for (j = 0; j < 9; ++j) {
    conn.id[j] = myrand(65, 90);
  }
  conn.id[9] = 0;

  /* postfd */
  aflog(LOG_T_MAIN, LOG_I_DEBUG,
      "http%s proxy: connecting (postfd)...", name);
  if (ip_connect(&tmp, proxyname, proxyport, type, NULL, NULL)) {
    clean_return(conn.sockfd);
  }
  SslFd_set_fd(conn.postFd, tmp);
  if (https) {
    if (SSL_set_fd(SslFd_get_ssl(conn.postFd), SslFd_get_fd(conn.postFd)) != 1) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "https proxy: Problem with initializing ssl");
      clean_return(conn.sockfd);
    }
    if (SSL_connect(SslFd_get_ssl(conn.postFd)) != 1) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "https proxy: SSL_connect has failed");
      clean_return(conn.sockfd);
    }
  }

  memset(tab, 0, 9000);
  switch (authtype) {
    case PROXYAUTH_TYPE_BASIC:
      sprintf(tab,
          "POST http://%s:%s/yahpt.html?id=%s HTTP/1.1\r\n"
          "Host: %s:%s\r\n"
          "Content-Length: 90000\r\n"
          "Connection: close\r\n"
          "Proxy-Authorization: Basic %s\r\n\r\n", host, serv, conn.id, host, serv, b64cred);
      break;
    default:
      sprintf(tab,
          "POST http://%s:%s/yahpt.html?id=%s HTTP/1.1\r\n"
          "Host: %s:%s\r\n"
          "Content-Length: 90000\r\n"
          "Connection: close\r\n\r\n", host, serv, conn.id, host, serv);
  }
  j = strlen (tab);
  aflog(LOG_T_MAIN, LOG_I_DEBUG,
      "http%s proxy: writing POST request...", name);
  if (http_write(https, conn.postFd, (unsigned char*) tab, j) <= 0) {
    clean_return(conn.sockfd);
  }

  /* getfd */
  aflog(LOG_T_MAIN, LOG_I_DEBUG,
      "http%s proxy: connecting (getfd)...", name);
  if (ip_connect(&tmp, proxyname, proxyport, type, NULL, NULL)) {
    clean_return(conn.sockfd);
  }
  SslFd_set_fd(conn.getFd, tmp);
  if (https) {
    if (SSL_set_fd(SslFd_get_ssl(conn.getFd), SslFd_get_fd(conn.getFd)) != 1) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "https proxy: Problem with initializing ssl");
      clean_return(conn.sockfd);
    }
    if (SSL_connect(SslFd_get_ssl(conn.getFd)) != 1) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "https proxy: SSL_connect has failed");
      clean_return(conn.sockfd);
    }
  }

  memset(tab, 0, 9000);
  switch (authtype) {
    case PROXYAUTH_TYPE_BASIC:
      sprintf(tab,
          "GET http://%s:%s/yahpt.html?id=%s HTTP/1.1\r\n"
          "Host: %s:%s\r\n"
          "Connection: close\r\n"
          "Proxy-Authorization: Basic %s\r\n\r\n", host, serv, conn.id, host, serv, b64cred);
      break;
    default:
      sprintf(tab,
          "GET http://%s:%s/yahpt.html?id=%s HTTP/1.1\r\n"
          "Host: %s:%s\r\n"
          "Connection: close\r\n\r\n", host, serv, conn.id, host, serv);
  }
  j = strlen (tab);
  aflog(LOG_T_MAIN, LOG_I_DEBUG,
      "http%s proxy: writing GET request...", name);
  if (http_write(https, conn.getFd, (unsigned char*) tab, j) <= 0) {
    clean_return(conn.sockfd);
  }

  set_fd(conn.sockfd, &maxfdp1, &allset);
  set_fd(SslFd_get_fd(conn.postFd), &maxfdp1, &allset);
  set_fd(SslFd_get_fd(conn.getFd), &maxfdp1, &allset);
  conn.state = C_OPEN;

  memset(tab, 0, 9000);

  aflog(LOG_T_MAIN, LOG_I_DEBUG,
      "http%s proxy: parsing header from getfd", name);
  if (parse_header(conn.getFd, tab, &hdr, https)) {
    clean_return(conn.sockfd);
  }
  aflog(LOG_T_MAIN, LOG_I_DEBUG,
      "http%s proxy: checking hdr.type", name);
  if (hdr.type != H_TYPE_OK) {
    clean_return(conn.sockfd);
  }
  if (hdr.length) {
    conn.received += hdr.length;
    aflog(LOG_T_MAIN, LOG_I_DEBUG,
        "http%s proxy: reading message...", name);
    if (read_message(conn.sockfd, hdr.length, &conn, tab, hdr.ptr)) {
      clean_return(conn.sockfd);
    }
  }

	while (1) {
    rset = allset;

    if (select(maxfdp1, &rset, NULL, NULL, &tv) == 0) {
      aflog(LOG_T_MAIN, LOG_I_DDEBUG,
          "http%s proxy: timeout", name);
      tv.tv_sec = timeout;
      if (conn.state == C_CLOSED) {
        continue;
      }
      if (conn.sent_ptr+1 >= 90000) {
        aflog(LOG_T_MAIN, LOG_I_DDEBUG,
            "http%s proxy: send T", name);
        http_write(https, conn.postFd, (unsigned char*) "T", 1);
        conn.sent_ptr = 0;
        clear_sslFd(conn.postFd, &allset);
        /* postfd */
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http%s proxy: connecting (postfd)...", name);
        if (ip_connect(&tmp, proxyname, proxyport, type, NULL, NULL)) {
          clean_return(conn.sockfd);
        }
        SslFd_set_fd(conn.postFd, tmp);
        if (https) {
          if (SSL_set_fd(SslFd_get_ssl(conn.postFd), SslFd_get_fd(conn.postFd)) != 1) {
            aflog(LOG_T_INIT, LOG_I_CRIT,
                "https proxy: Problem with initializing ssl");
            clean_return(conn.sockfd);
          }
          if (SSL_connect(SslFd_get_ssl(conn.postFd)) != 1) {
            aflog(LOG_T_INIT, LOG_I_CRIT,
                "https proxy: SSL_connect has failed");
            clean_return(conn.sockfd);
          }
        }

        memset(tab, 0, 9000);
        switch (authtype) {
          case PROXYAUTH_TYPE_BASIC:
            sprintf(tab,
                "POST http://%s:%s/yahpt.html?id=%s HTTP/1.1\r\n"
                "Host: %s:%s\r\n"
                "Content-Length: 90000\r\n"
                "Connection: close\r\n"
                "Proxy-Authorization: Basic %s\r\n\r\n", host, serv, conn.id, host, serv, b64cred);
            break;
          default:
            sprintf(tab,
                "POST http://%s:%s/yahpt.html?id=%s HTTP/1.1\r\n"
                "Host: %s:%s\r\n"
                "Content-Length: 90000\r\n"
                "Connection: close\r\n\r\n", host, serv, conn.id, host, serv);
        }
        j = strlen (tab);
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http%s proxy: writing POST request...", name);
        if (http_write(https, conn.postFd, (unsigned char *) tab, j) <= 0) {
          clean_return(conn.sockfd);
        }       
        conn.sent_ptr = 0;
        conn.ptr = 0;
        conn.length = 0;

        set_fd(SslFd_get_fd(conn.postFd), &maxfdp1, &allset);
      }
      else {
        aflog(LOG_T_MAIN, LOG_I_DDEBUG,
            "http%s proxy: send T", name);
        http_write(https, conn.postFd, (unsigned char *) "T", 1);
        conn.sent_ptr += 1;
      }
      continue;
    }

    /* sockfd */
    if (FD_ISSET(conn.sockfd, &rset)) {
      aflog(LOG_T_MAIN, LOG_I_DDEBUG,
          "http%s proxy: FD_ISSET(conn.sockfd)", name);
      if (conn.state == C_CLOSED) {
        /* postfd */
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http%s proxy: connecting (postfd)...", name);
        if (ip_connect(&tmp, proxyname, proxyport, type, NULL, NULL)) {
          clean_return(conn.sockfd);
        }
        SslFd_set_fd(conn.postFd, tmp);
        if (https) {
          if (SSL_set_fd(SslFd_get_ssl(conn.postFd), SslFd_get_fd(conn.postFd)) != 1) {
            aflog(LOG_T_INIT, LOG_I_CRIT,
                "https proxy: Problem with initializing ssl");
            clean_return(conn.sockfd);
          }
          if (SSL_connect(SslFd_get_ssl(conn.postFd)) != 1) {
            aflog(LOG_T_INIT, LOG_I_CRIT,
                "https proxy: SSL_connect has failed");
            clean_return(conn.sockfd);
          }
        }
        conn.state = C_OPEN;
      }
      n = read(conn.sockfd, conn.buf+5, 8995);
      if (n <= 0) {
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http%s proxy: send Q", name);
        http_write(https, conn.postFd, (unsigned char *) "Q", 1);
        clean_return(conn.sockfd);
      }
      conn.buf[0] = 'M';
      tmp = htonl(n);
      memcpy(&conn.buf[1], &tmp, 4);
      if (conn.sent_ptr+5 + n >= 90000) {
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http%s proxy: send message", name);
        http_write(https, conn.postFd, (unsigned char *) conn.buf, 90000 - conn.sent_ptr);
        conn.ptr = 90000 - conn.sent_ptr;
        conn.length = 5+n - conn.ptr;
        conn.sent_ptr = 0;
        clear_sslFd(conn.postFd, &allset);
        
        /* postfd */
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http%s proxy: connecting (postfd)...", name);
        if (ip_connect(&tmp, proxyname, proxyport, type, NULL, NULL)) {
          clean_return(conn.sockfd);
        }
        SslFd_set_fd(conn.postFd, tmp);
        if (https) {
          if (SSL_set_fd(SslFd_get_ssl(conn.postFd), SslFd_get_fd(conn.postFd)) != 1) {
            aflog(LOG_T_INIT, LOG_I_CRIT,
                "https proxy: Problem with initializing ssl");
            clean_return(conn.sockfd);
          }
          if (SSL_connect(SslFd_get_ssl(conn.postFd)) != 1) {
            aflog(LOG_T_INIT, LOG_I_CRIT,
                "https proxy: SSL_connect has failed");
            clean_return(conn.sockfd);
          }
        }
      
        memset(tab, 0, 9000);
        switch (authtype) {
          case PROXYAUTH_TYPE_BASIC:
            sprintf(tab,
                "POST http://%s:%s/yahpt.html?id=%s HTTP/1.1\r\n"
                "Host: %s:%s\r\n"
                "Content-Length: 90000\r\n"
                "Connection: close\r\n"
                "Proxy-Authorization: Basic %s\r\n\r\n", host, serv, conn.id, host, serv, b64cred);
            break;
          default:
            sprintf(tab,
                "POST http://%s:%s/yahpt.html?id=%s HTTP/1.1\r\n"
                "Host: %s:%s\r\n"
                "Content-Length: 90000\r\n"
                "Connection: close\r\n\r\n", host, serv, conn.id, host, serv);
        }
        j = strlen (tab);
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http%s proxy: writing POST request...", name);
        if (http_write(https, conn.postFd, (unsigned char *) tab, j) <= 0) {
        clean_return(conn.sockfd);
        }       
        if (conn.length > 0) {
          aflog(LOG_T_MAIN, LOG_I_DEBUG,
              "http%s proxy: writing old data...", name);
          if (http_write(https, conn.postFd, (unsigned char *) (conn.buf+conn.ptr), conn.length) <= 0) {
            clean_return(conn.sockfd);
          }       
        }
        conn.sent_ptr = conn.length;
        conn.ptr = 0;
        conn.length = 0;

        set_fd(SslFd_get_fd(conn.postFd), &maxfdp1, &allset);
      }
      else {
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http%s proxy: send message", name);
        http_write(https, conn.postFd, (unsigned char *) conn.buf, 5+n);
        conn.sent_ptr += 5+n;
      }
    }
    
    /* getfd */
    if (FD_ISSET(SslFd_get_fd(conn.getFd), &rset)) {
      aflog(LOG_T_MAIN, LOG_I_DDEBUG,
          "http%s proxy: FD_ISSET(conn.getfd)", name);
      n = http_read(https, conn.getFd, (unsigned char*) tab, 9000);
      conn.received += n;
      if (n == 0) {
        conn.received = 0;
        clear_sslFd(conn.getFd, &allset);
          
        /* getfd */
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http%s proxy: connecting (getfd)...", name);
        if (ip_connect(&tmp, proxyname, proxyport, type, NULL, NULL)) {
          clean_return(conn.sockfd);
        }
        SslFd_set_fd(conn.getFd, tmp);
        if (https) {
          if (SSL_set_fd(SslFd_get_ssl(conn.getFd), SslFd_get_fd(conn.getFd)) != 1) {
            aflog(LOG_T_INIT, LOG_I_CRIT,
                "https proxy: Problem with initializing ssl");
            clean_return(conn.sockfd);
          }
          if (SSL_connect(SslFd_get_ssl(conn.getFd)) != 1) {
            aflog(LOG_T_INIT, LOG_I_CRIT,
                "https proxy: SSL_connect has failed");
            clean_return(conn.sockfd);
          }
        }

        memset(tab, 0, 9000);
        switch (authtype) {
          case PROXYAUTH_TYPE_BASIC:
            sprintf(tab,
                "GET http://%s:%s/yahpt.html?id=%s HTTP/1.1\r\n"
                "Host: %s:%s\r\n"
                "Connection: close\r\n"
                "Proxy-Authorization: Basic %s\r\n\r\n", host, serv, conn.id, host, serv, b64cred);
            break;
          default:
            sprintf(tab,
                "GET http://%s:%s/yahpt.html?id=%s HTTP/1.1\r\n"
                "Host: %s:%s\r\n"
                "Connection: close\r\n\r\n", host, serv, conn.id, host, serv);
        }
        j = strlen (tab);
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http%s proxy: writing GET request...", name);
        if (http_write(https, conn.getFd, (unsigned char *) tab, j) <= 0) {
          clean_return(conn.sockfd);
        }
        memset(tab, 0, 9000);
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http%s proxy: parsing header from getfd", name);
        if (parse_header(conn.getFd, tab, &hdr, https)) {
          clean_return(conn.sockfd);
        }
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http%s proxy: checking hdr.type", name);
        if (hdr.type != H_TYPE_OK) {
          clean_return(conn.sockfd);
        }

        set_fd(SslFd_get_fd(conn.getFd), &maxfdp1, &allset);
        if (hdr.length) {
          conn.received += hdr.length;
          aflog(LOG_T_MAIN, LOG_I_DEBUG,
              "http%s proxy: reading message...", name);
          if (read_message(conn.sockfd, hdr.length, &conn, tab, hdr.ptr)) {
            clean_return(conn.sockfd);
          }
        }
      }
      else {
        if (read_message(conn.sockfd, n, &conn, tab, 0)) {
          clean_return(conn.sockfd);
        }
      }
    }
    
    /* postfd */
    if (FD_ISSET(SslFd_get_fd(conn.postFd), &rset)) {
      aflog(LOG_T_MAIN, LOG_I_DDEBUG,
          "http%s proxy: FD_ISSET(conn.postfd)", name);
      clear_sslFd(conn.postFd, &allset);
      conn.state = C_CLOSED;
    }
  }
  clean_return(conn.sockfd);
}

/*
 * Function name: initialize_http_proxy_client
 * Description: Initializes the thread responsible for http proxy connection.
 * Arguments: sockfd - the new connection descriptor will be stored here
 *            cr - the pointer to ClientRealm structure
 *            ctx - the pointer to SSL_CTX structure
 * Returns: 0 - success,
 *          !0 - failure.
 */

int
initialize_http_proxy_client(int* sockfd, ClientRealm* cr, SSL_CTX* ctx)
{
  int retval;
  int sockets[2];
  pthread_t proxy_thread;
  static proxy_argT arg;

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets)) {
    return 1;
  }
  (*sockfd) = sockets[0];

  if (HttpProxyOptions_get_proxyname(ClientRealm_get_httpProxyOptions(cr)) == NULL) {
    return 1;
  }

  start_critical_section();

  arg.host = ClientRealm_get_serverName(cr);
  arg.serv = ClientRealm_get_managePort(cr);
  arg.hpo = ClientRealm_get_httpProxyOptions(cr);
  arg.type = ClientRealm_get_ipFamily(cr);
  arg.sockfd = sockets[1];
  arg.ctx = ctx;

  retval = pthread_create(&proxy_thread, NULL, &http_proxy_client, &arg);

  wait_for_condition();

  end_critical_section();

  return retval;
}

#endif
