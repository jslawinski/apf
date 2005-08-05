/*
 * active port forwarder - software for secure forwarding
 * Copyright (C) 2003,2004,2005 jeremian <jeremian [at] poczta.fm>
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

#include "make_ssl_handshake.h"
#include "http_proxy_server.h"
#include "thread_management.h"
#include "stats.h"
#include "logging.h"
#include "network.h"

#ifdef HAVE_LIBPTHREAD

typedef struct {
  int sockfd;
  char *host;
  char *serv;
  socklen_t *addrlenp;
  char type;
  int limit;
  char https;
  SSL_CTX* ctx;
} sproxy_argT;

int
afserver_connect(int* sockfd, int afserverfd, struct sockaddr* cliaddr, socklen_t* addrlenp, char type)
{
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets)) {
    return 1;
  }
  if (write(afserverfd, &sockets[0], 4) != 4) {
    return 2;
  }
  if (write(afserverfd, &type, 1) != 1) {
    return 3;
  }
  if (write(afserverfd, addrlenp, 4) != 4) {
    return 3;
  }
  if (write(afserverfd, cliaddr, *addrlenp) != *addrlenp) {
    return 5;
  }
  (*sockfd) = sockets[1];
  return 0;
}

void*
http_proxy_server(void *vptr)
{
	int listenfd, afserverfd;
  SslFd* connFd;
	struct sockaddr* cliaddr;
  char tab[9000];
  connection* table;
  header hdr;
	int i, n, maxfdp1;
  fd_set rset, allset;
  struct timeval tv;
  int maxclients, tmp;
  int timeout = 5;
  socklen_t *addrlenp;
  char type, nothttp, https;
  char *host, *serv, *name = "";
  SSL_CTX* ctx;
  sproxy_argT *proxy_argptr;

  start_critical_section();
  proxy_argptr = (sproxy_argT *) vptr;

  afserverfd = proxy_argptr->sockfd;
  host = proxy_argptr->host;
  serv = proxy_argptr->serv;
  addrlenp = proxy_argptr->addrlenp;
  type = proxy_argptr->type;
  maxclients = proxy_argptr->limit+1;
  https = proxy_argptr->https;
  ctx = proxy_argptr->ctx;

  broadcast_condition();
  end_critical_section();

  if (https) {
    name = "s";
  }

  table = calloc(maxclients, sizeof(connection));
  if (table == NULL) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "http%s proxy: Can't allocate memory... exiting.", name);
    exit(1);
  }
  for (i = 0; i < maxclients; ++i) {
    table[i].postFd = SslFd_new();
    table[i].getFd = SslFd_new();
    table[i].tmpFd = SslFd_new();
    if ((table[i].postFd == NULL) || (table[i].getFd == NULL) || (table[i].tmpFd == NULL)) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "http%s proxy: Can't allocate memory... exiting.", name);
      exit(1);
    }
    if (https) {
      SslFd_set_ssl(table[i].postFd, SSL_new(ctx));
      SslFd_set_ssl(table[i].getFd, SSL_new(ctx));
      SslFd_set_ssl(table[i].tmpFd, SSL_new(ctx));
      if ((SslFd_get_ssl(table[i].postFd) == NULL) ||
          (SslFd_get_ssl(table[i].getFd) == NULL) ||
          (SslFd_get_ssl(table[i].tmpFd) == NULL)) {
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "http%s proxy: Can't allocate memory... exiting.", name);
        exit(1);
      }
    }
  }
  connFd = SslFd_new();
  if (connFd == NULL) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "http%s proxy: Can't allocate memory... exiting.", name);
    exit(1);
  }
  if (https) {
    SslFd_set_ssl(connFd, SSL_new(ctx));
    if (SslFd_get_ssl(connFd) == NULL) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "http%s proxy: Can't allocate memory... exiting.", name);
      exit(1);
    }
  }
  
	if (ip_listen(&listenfd, host, serv, addrlenp, type)) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "http%s proxy: Can't listen on %s:%s", name, host, serv);
    exit(1);
  }
	cliaddr = malloc(*addrlenp);
  
  FD_ZERO(&allset);
  FD_SET(listenfd, &allset);
  maxfdp1 = listenfd + 1;
  tv.tv_usec = 0;
  tv.tv_sec = timeout;
  
	while (1) {
    rset = allset;

    if (select(maxfdp1, &rset, NULL, NULL, &tv) == 0) {
      aflog(LOG_T_MAIN, LOG_I_DDEBUG,
          "http%s proxy: timeout", name);
      tv.tv_sec = timeout;
      for (i = 0; i < maxclients; ++i) {
        if ((table[i].state == C_CLOSED) || (table[i].state & C_GET_WAIT) || (table[i].type == 1)) {
          continue;
        }
        aflog(LOG_T_MAIN, LOG_I_DDEBUG,
            "http%s proxy: send T to table[%d].getfd", name, i);
        if (table[i].sent_ptr+1 >= 90000) {
          http_write(https, table[i].getFd, (unsigned char*) "T", 1);
          table[i].sent_ptr = 0;
          clear_sslFd(table[i].getFd, &allset);
          FD_CLR(table[i].sockfd, &allset);
          table[i].state |= C_GET_WAIT;
        }
        else {
          http_write(https, table[i].getFd, (unsigned char*) "T", 1);
          table[i].sent_ptr += 1;
        }
      }
      continue;
    }

    /* http proxy tunnels */
    for (i = 0; i < maxclients; ++i) {
      if ((table[i].state == C_CLOSED) || (table[i].type == 1)) {
        continue;
      }
      
      /* sockfd */
      if ((!(table[i].state & C_GET_WAIT)) && (FD_ISSET(table[i].sockfd, &rset))) {
        aflog(LOG_T_MAIN, LOG_I_DDEBUG,
            "http%s proxy: FD_ISSET(table[%d].sockfd)", name, i);
        n = read(table[i].sockfd, table[i].buf+5, 8995);
        if (n <= 0) {
          http_write(https, table[i].getFd, (unsigned char*) "Q", 1);
          delete_user(table, i, &allset);
          continue;
        }
        table[i].buf[0] = 'M';
        tmp = htonl(n);
        memcpy(&table[i].buf[1], &tmp, 4);
        if (table[i].sent_ptr+5 + n >= 90000) {
          http_write(https, table[i].getFd, (unsigned char*) table[i].buf, 90000 - table[i].sent_ptr);
          table[i].ptr = 90000 - table[i].sent_ptr;
          table[i].length = 5+n - table[i].ptr;
          table[i].sent_ptr = 0;
          clear_sslFd(table[i].getFd, &allset);
          FD_CLR(table[i].sockfd, &allset);
          table[i].state |= C_GET_WAIT;
          continue;
        }
        else {
          http_write(https, table[i].getFd, (unsigned char*) table[i].buf, n+5);
          table[i].sent_ptr += n+5;
        }
      }
      
      /* getfd */
      if (FD_ISSET(SslFd_get_fd(table[i].getFd), &rset)) {
        aflog(LOG_T_MAIN, LOG_I_DDEBUG,
            "http%s proxy: FD_ISSET(table[%d].getfd)", name, i);
        delete_user(table, i, &allset);
        continue;
      }
      
      /* postfd */
      if (FD_ISSET(SslFd_get_fd(table[i].postFd), &rset)) {
        aflog(LOG_T_MAIN, LOG_I_DDEBUG,
            "http%s proxy: FD_ISSET(table[%d].postfd)", name, i);
        n = http_read(https, table[i].postFd, (unsigned char*) tab, 9000);
        if (n != 0) {
          table[i].received += n;
          if (read_message(table[i].sockfd, n, &table[i], tab, 0)) {
            delete_user(table, i, &allset);
          }
        }
        if ((n == 0) || (table[i].received == 90000)) {
          table[i].received = 0;
          clear_sslFd(table[i].postFd, &allset);
          table[i].state |= C_POST_WAIT;
          if (table[i].tmpstate == 1) {
            aflog(LOG_T_MAIN, LOG_I_DEBUG,
                "http%s proxy: get old POST request...", name);
            table[i].state &= ~C_POST_WAIT;
            SslFd_swap_content(table[i].postFd, table[i].tmpFd);
            set_fd(SslFd_get_fd(table[i].postFd), &maxfdp1, &allset);
            table[i].tmpstate = 0;
            if (table[i].tmpheader.length) {
              table[i].received += table[i].tmpheader.length;
              if (read_message(table[i].sockfd, table[i].tmpheader.length, &table[i],
                    table[i].tmpbuf, table[i].tmpheader.ptr)) {
                delete_user(table, i, &allset);
              } 
            } 
          } 
          continue;
        }
      }
    }

    /* direct tunnels */
    for (i = 0; i < maxclients; ++i) {
      if ((table[i].state == C_OPEN) && (table[i].type == 1)) {
        
        if (FD_ISSET(table[i].sockfd, &rset)) {
          n = read(table[i].sockfd, table[i].buf, 9000);
          if (n > 0) {
            writen(SslFd_get_fd(table[i].postFd), (unsigned char*) table[i].buf, n);
          }
          else {
            delete_user(table, i, &allset);
            continue;
          }
        }
        
        if (FD_ISSET(SslFd_get_fd(table[i].postFd), &rset)) {
          n = read(SslFd_get_fd(table[i].postFd), tab, 9000);
          if (n > 0) {
            writen(table[i].sockfd, (unsigned char*) tab, n);
          }
          else {
            delete_user(table, i, &allset);
            continue;
          }
        }
        
      }
    }
      
    /* listen */
    if (FD_ISSET(listenfd, &rset)) {
      aflog(LOG_T_MAIN, LOG_I_DDEBUG,
          "http%s proxy: FD_ISSET(listenfd)", name);
      tmp = accept(listenfd, cliaddr, addrlenp);
      if (tmp != -1) {
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http%s proxy: New connection...", name);
        SslFd_set_fd(connFd, tmp);
        if (https) {
          make_ssl_initialize(connFd);
          if (make_ssl_accept(connFd)) {
            aflog(LOG_T_MAIN, LOG_I_DEBUG,
                "https proxy: DENIED by SSL_accept");
            close(SslFd_get_fd(connFd));
            SSL_clear(SslFd_get_ssl(connFd));
            continue;
          }
        }
      }
      else {
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http%s proxy: New connection --> EAGAIN", name);
        continue;
      }
      memset(tab, 0, 9000);
      nothttp = 0;
      if (parse_header(connFd, tab, &hdr, https)) {
        nothttp = 1;
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http%s proxy: no http header...", name);
      }
      n = -1;
      for (i = 0; i < maxclients; ++i) {
        if (table[i].state == C_CLOSED) {
          if (n == -1)
            n = i;
        }
        else {
          if ((!nothttp) && (strcmp(table[i].id, hdr.id) == 0)) {
            break;
          }
        }
      }
      if (i < maxclients) { /* the client exists */
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http%s proxy: the client exist...", name);
        if (hdr.type == H_TYPE_GET) {
          aflog(LOG_T_MAIN, LOG_I_DEBUG,
              "http%s proxy: type GET...", name);
          if (!(table[i].state & C_GET_WAIT)) {
            aflog(LOG_T_MAIN, LOG_I_DEBUG,
                "http%s proxy: not waiting for GET...", name);
            table[i].sent_ptr = 0;
            FD_CLR(table[i].sockfd, &allset);
            clear_sslFd(table[i].getFd, &allset);
            table[i].state |= C_GET_WAIT;
          }
          if (!(table[i].state & C_OPEN)) {
            aflog(LOG_T_MAIN, LOG_I_DEBUG,
                "http%s proxy: not opened...", name);
            if (afserver_connect(&table[i].sockfd, afserverfd, cliaddr, addrlenp, 1)) {
              memset(tab, 0, 9000);
              sprintf(tab,"HTTP/1.1 400 Bad Request\r\n\r\n");
              n = strlen (tab); 
              http_write(https, connFd, (unsigned char*) tab, n);
              close_fd((&(connFd->fd)));
              SSL_clear(SslFd_get_ssl(connFd));
              clear_sslFd(table[i].postFd, &allset);
              table[i].state = C_CLOSED;
              continue;
            }
            table[i].state |= C_OPEN;
            aflog(LOG_T_MAIN, LOG_I_DEBUG,
                "http%s proxy: OPEN...", name);
          }
          table[i].state &= ~C_GET_WAIT;
          table[i].sent_ptr = 0;
          SslFd_swap_content(table[i].getFd, connFd);
          set_fd(table[i].sockfd, &maxfdp1, &allset);
          set_fd(SslFd_get_fd(table[i].getFd), &maxfdp1, &allset);
          memset(tab, 0, 9000);
          sprintf(tab,
              "HTTP/1.1 200 OK\r\n"
              "Content-Length: 90000\r\n"
              "Connection: close\r\n"
              "Pragma: no-cache\r\n"
              "Cache-Control: no-cache, no-store, must-revalidate\r\n"
              "Expires: 0\r\n"
              "Content-Type: text/html\r\n\r\n");
          n = strlen(tab);
          if (writen(SslFd_get_fd(table[i].getFd), (unsigned char*) tab, n) <= 0) {
            delete_user(table, i, &allset);
            continue;
          }
          if (table[i].length) {
            if (writen(SslFd_get_fd(table[i].getFd),
                  (unsigned char*) (table[i].buf+table[i].ptr), table[i].length) <= 0) {
              delete_user(table, i, &allset);
              continue;
            }
          }
          table[i].sent_ptr = table[i].length;
          table[i].ptr = 0;
          table[i].length = 0;
        }
        else if (hdr.type == H_TYPE_POST) {
          aflog(LOG_T_MAIN, LOG_I_DEBUG,
              "http%s proxy: type POST...", name);
          if (!(table[i].state & C_POST_WAIT)) {
            aflog(LOG_T_MAIN, LOG_I_DEBUG,
                "http%s proxy: unexpected POST request...", name);
            if (table[i].tmpstate == 0) {
              aflog(LOG_T_MAIN, LOG_I_DEBUG,
                  "http%s proxy: buffering POST request...", name);
              table[i].tmpstate = 1;
              SslFd_swap_content(table[i].tmpFd, connFd);
              memcpy(table[i].tmpbuf, tab, 9000);
              table[i].tmpheader = hdr;
            }
            else {
              aflog(LOG_T_MAIN, LOG_I_DEBUG,
                  "http%s proxy: no space to buffer POST request (received from first postfd: %d)", name,
                  table[i].received);
              delete_user(table, i, &allset);
            }
          }
          else {
            if (hdr.length) {
              table[i].received += hdr.length;
              if (read_message(table[i].sockfd, hdr.length, &table[i], tab, hdr.ptr)) {
                delete_user(table, i, &allset);
              }
            } 
            table[i].state &= ~C_POST_WAIT;
            SslFd_swap_content(table[i].postFd, connFd);
            set_fd(SslFd_get_fd(table[i].postFd), &maxfdp1, &allset);
          }
        }
        else {
          aflog(LOG_T_MAIN, LOG_I_DEBUG,
              "http%s proxy: unrecognized type...", name);
          delete_user(table, i, &allset);
        }
      }
      else if (n != -1) { /* there are free slots */
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http%s proxy: there are free slots...", name);
        if (!nothttp) {
          aflog(LOG_T_MAIN, LOG_I_DEBUG,
              "http%s proxy: http header...", name);
          if (hdr.type == H_TYPE_POST) { /* POST request must be first */
            aflog(LOG_T_MAIN, LOG_I_DEBUG,
                "http%s proxy: type POST...", name);
            table[n].state = C_GET_WAIT;
            memcpy(table[n].id,hdr.id, 9);
            SslFd_swap_content(table[n].postFd, connFd);
            set_fd(SslFd_get_fd(table[n].postFd), &maxfdp1, &allset);
          }
          else {
            aflog(LOG_T_MAIN, LOG_I_DEBUG,
                "http%s proxy: closing this connection...", name);
            close_fd((&(connFd->fd)));
            SSL_clear(SslFd_get_ssl(connFd));
            continue;
          }
        }
        else {
          table[n].state = C_OPEN;
          SslFd_set_fd(table[n].postFd, SslFd_get_fd(connFd));
          table[n].type = 1;
          set_fd(SslFd_get_fd(table[n].postFd), &maxfdp1, &allset);
          if (afserver_connect(&table[n].sockfd, afserverfd, cliaddr, addrlenp, 0)) {
            clear_sslFd(table[n].postFd, &allset);
            table[n].state = C_CLOSED;
            continue;
          }
          set_fd(table[n].sockfd, &maxfdp1, &allset);
          write(table[n].sockfd, tab, hdr.allreaded);
        }
      }
      else {
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http%s proxy: closing this connection...", name);
        close_fd((&(connFd->fd)));
        continue;
      }
    }
	}
	
	return 0;
}


int
initialize_http_proxy_server(int* sockfd, const char *host, const char *serv, socklen_t *addrlenp, const char type, int limit, char https, SSL_CTX* ctx)
{
  int retval;
  int sockets[2];
  pthread_t proxy_thread;
  static sproxy_argT arg;

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets)) {
    return 1;
  }
  (*sockfd) = sockets[0];

  start_critical_section();
  
  arg.host = (char*) host;
  arg.serv = (char*) serv;
  arg.addrlenp = addrlenp;
  arg.limit = limit;
  arg.type = (char) type;
  arg.sockfd = sockets[1];
  arg.https = https;
  arg.ctx = ctx;

  retval = pthread_create(&proxy_thread, NULL, &http_proxy_server, &arg);
  
  wait_for_condition();
  
  end_critical_section();
  
  return retval;
}

#endif
