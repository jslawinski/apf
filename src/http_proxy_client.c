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

#include "http_proxy_functions.h"
#include "http_proxy_client.h"
#include "thread_management.h"
#include "network.h"
#include "stats.h"
#include "logging.h"

#ifdef HAVE_LIBPTHREAD
typedef struct {
  int sockfd;
  char *host;
  char *serv;
  char *proxyname;
  char *proxyport;
  char type;
} proxy_argT;

static void
clean_return(int sockfd)
{
  aflog(LOG_T_MAIN, LOG_I_DEBUG,
      "http proxy: clean_return");
  close(sockfd);
  pthread_exit(NULL);
}

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
  char *host, *serv, *proxyname, *proxyport;
  char type;
  proxy_argT *proxy_argptr;

  start_critical_section();
  proxy_argptr = (proxy_argT *) vptr;
  
  host = proxy_argptr->host;
  serv = proxy_argptr->serv;
  proxyname = proxy_argptr->proxyname;
  proxyport = proxy_argptr->proxyport;
  type = proxy_argptr->type;
  conn.sockfd = proxy_argptr->sockfd;

  broadcast_condition();
  end_critical_section();

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
      "http proxy: connecting (postfd)...");
  if (ip_connect(&conn.postfd, proxyname, proxyport, type)) {
    clean_return(conn.sockfd);
  }


  memset(tab, 0, 9000);
  sprintf(tab,
      "POST http://%s:%s/yahpt.html?id=%s HTTP/1.1\r\n"
      "Host: %s:%s\r\n"
      "Content-Length: 90000\r\n"
      "Connection: close\r\n\r\n", host, serv, conn.id, host, serv);
  j = strlen (tab);
  aflog(LOG_T_MAIN, LOG_I_DEBUG,
      "http proxy: writing POST request...");
  if (writen(conn.postfd, (unsigned char*) tab, j) <= 0) {
    clean_return(conn.sockfd);
  }

  /* getfd */
  aflog(LOG_T_MAIN, LOG_I_DEBUG,
      "http proxy: connecting (getfd)...");
  if (ip_connect(&conn.getfd, proxyname, proxyport, type)) {
    clean_return(conn.sockfd);
  }

  memset(tab, 0, 9000);
  sprintf(tab,
      "GET http://%s:%s/yahpt.html?id=%s HTTP/1.1\r\n"
      "Host: %s:%s\r\n"
      "Connection: close\r\n\r\n", host, serv, conn.id, host, serv);
  j = strlen (tab);
  aflog(LOG_T_MAIN, LOG_I_DEBUG,
      "http proxy: writing GET request...");
  if (writen(conn.getfd, (unsigned char*) tab, j) <= 0) {
    clean_return(conn.sockfd);
  }

  set_fd(conn.sockfd, &maxfdp1, &allset);
  set_fd(conn.postfd, &maxfdp1, &allset);
  set_fd(conn.getfd, &maxfdp1, &allset);
  conn.state = C_OPEN;

  memset(tab, 0, 9000);

  aflog(LOG_T_MAIN, LOG_I_DEBUG,
      "http proxy: parsing header from getfd");
  if (parse_header(conn.getfd, tab, &hdr)) {
    clean_return(conn.sockfd);
  }
  aflog(LOG_T_MAIN, LOG_I_DEBUG,
      "http proxy: checking hdr.type");
  if (hdr.type != H_TYPE_OK) {
    clean_return(conn.sockfd);
  }
  if (hdr.length) {
    conn.received += hdr.length;
    aflog(LOG_T_MAIN, LOG_I_DEBUG,
        "http proxy: reading message...");
    if (read_message(conn.sockfd, hdr.length, &conn, tab, hdr.ptr)) {
      clean_return(conn.sockfd);
    }
  }

	while (1) {
    rset = allset;

    if (select(maxfdp1, &rset, NULL, NULL, &tv) == 0) {
      aflog(LOG_T_MAIN, LOG_I_DDEBUG,
          "http proxy: timeout");
      tv.tv_sec = timeout;
      if (conn.state == C_CLOSED) {
        continue;
      }
      if (conn.sent_ptr+1 >= 90000) {
        aflog(LOG_T_MAIN, LOG_I_DDEBUG,
            "http proxy: send T");
        writen(conn.postfd, (unsigned char*) "T", 1);
        conn.sent_ptr = 0;
        clear_fd(&conn.postfd, &allset);
        /* postfd */
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http proxy: connecting (postfd)...");
        if (ip_connect(&conn.postfd, proxyname, proxyport, type)) {
          clean_return(conn.sockfd);
        }
      
        memset(tab, 0, 9000);
        sprintf(tab,
            "POST http://%s:%s/yahpt.html?id=%s HTTP/1.1\r\n"
            "Host: %s:%s\r\n"
            "Content-Length: 90000\r\n"
            "Connection: close\r\n\r\n", host, serv, conn.id, host, serv);
        j = strlen (tab);
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http proxy: writing POST request...");
        if (writen(conn.postfd, (unsigned char *) tab, j) <= 0) {
          clean_return(conn.sockfd);
        }       
        conn.sent_ptr = 0;
        conn.ptr = 0;
        conn.length = 0;

        set_fd(conn.postfd, &maxfdp1, &allset);
      }
      else {
        aflog(LOG_T_MAIN, LOG_I_DDEBUG,
            "http proxy: send T");
        writen(conn.postfd, (unsigned char *) "T", 1);
        conn.sent_ptr += 1;
      }
      continue;
    }

    /* sockfd */
    if (FD_ISSET(conn.sockfd, &rset)) {
      aflog(LOG_T_MAIN, LOG_I_DDEBUG,
          "http proxy: FD_ISSET(conn.sockfd)");
      if (conn.state == C_CLOSED) {
        /* postfd */
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http proxy: connecting (postfd)...");
        if (ip_connect(&conn.postfd, proxyname, proxyport, type)) {
          clean_return(conn.sockfd);
        }
        conn.state = C_OPEN;
      }
      n = read(conn.sockfd, conn.buf+5, 8995);
      if (n <= 0) {
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http proxy: send Q");
        writen(conn.postfd, (unsigned char *) "Q", 1);
        clean_return(conn.sockfd);
      }
      conn.buf[0] = 'M';
      tmp = htonl(n);
      memcpy(&conn.buf[1], &tmp, 4);
      if (conn.sent_ptr+5 + n >= 90000) {
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http proxy: send message");
        writen(conn.postfd, (unsigned char *) conn.buf, 90000 - conn.sent_ptr);
        conn.ptr = 90000 - conn.sent_ptr;
        conn.length = 5+n - conn.ptr;
        conn.sent_ptr = 0;
        clear_fd(&conn.postfd, &allset);
        
        /* postfd */
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http proxy: connecting (postfd)...");
        if (ip_connect(&conn.postfd, proxyname, proxyport, type)) {
          clean_return(conn.sockfd);
        }
      
        memset(tab, 0, 9000);
        sprintf(tab,
            "POST http://%s:%s/yahpt.html?id=%s HTTP/1.1\r\n"
            "Host: %s:%s\r\n"
            "Content-Length: 90000\r\n"
            "Connection: close\r\n\r\n", host, serv, conn.id, host, serv);
        j = strlen (tab);
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http proxy: writing POST request...");
        if (writen(conn.postfd, (unsigned char *) tab, j) <= 0) {
        clean_return(conn.sockfd);
        }       
        if (conn.length > 0) {
          aflog(LOG_T_MAIN, LOG_I_DEBUG,
              "http proxy: writing old data...");
          if (writen(conn.postfd, (unsigned char *) (conn.buf+conn.ptr), conn.length) <= 0) {
            clean_return(conn.sockfd);
          }       
        }
        conn.sent_ptr = conn.length;
        conn.ptr = 0;
        conn.length = 0;

        set_fd(conn.postfd, &maxfdp1, &allset);
      }
      else {
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http proxy: send message");
        writen(conn.postfd, (unsigned char *) conn.buf, 5+n);
        conn.sent_ptr += 5+n;
      }
    }
    
    /* getfd */
    if (FD_ISSET(conn.getfd, &rset)) {
      aflog(LOG_T_MAIN, LOG_I_DDEBUG,
          "http proxy: FD_ISSET(conn.getfd)");
      n = read(conn.getfd, tab, 9000);
      conn.received += n;
      if (n == 0) {
        conn.received = 0;
        FD_CLR(conn.getfd, &allset);
        close(conn.getfd);
          
        /* getfd */
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http proxy: connecting (getfd)...");
        if (ip_connect(&conn.getfd, proxyname, proxyport, type)) {
          clean_return(conn.sockfd);
        }

        memset(tab, 0, 9000);
        sprintf(tab,
            "GET http://%s:%s/yahpt.html?id=%s HTTP/1.1\r\n"
            "Host: %s:%s\r\n"
            "Connection: close\r\n\r\n", host, serv, conn.id, host, serv);
        j = strlen (tab);
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http proxy: writing GET request...");
        if (writen(conn.getfd, (unsigned char *) tab, j) <= 0) {
          clean_return(conn.sockfd);
        }
        memset(tab, 0, 9000);
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http proxy: parsing header from getfd");
        if (parse_header(conn.getfd, tab, &hdr)) {
          clean_return(conn.sockfd);
        }
        aflog(LOG_T_MAIN, LOG_I_DEBUG,
            "http proxy: checking hdr.type");
        if (hdr.type != H_TYPE_OK) {
          clean_return(conn.sockfd);
        }

        set_fd(conn.getfd, &maxfdp1, &allset);
        if (hdr.length) {
          conn.received += hdr.length;
          aflog(LOG_T_MAIN, LOG_I_DEBUG,
              "http proxy: reading message...");
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
    if (FD_ISSET(conn.postfd, &rset)) {
      aflog(LOG_T_MAIN, LOG_I_DDEBUG,
          "http proxy: FD_ISSET(conn.postfd)");
      clear_fd(&conn.postfd, &allset);
      conn.state = C_CLOSED;
    }
  }
  clean_return(conn.sockfd);
}

int
initialize_http_proxy_client(int* sockfd, const char *host, const char *serv,
    const char *proxyname, const char *proxyport, const char type)
{
  int retval;
  int sockets[2];
  pthread_t proxy_thread;
  static proxy_argT arg;

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets)) {
    return 1;
  }
  (*sockfd) = sockets[0];

  if (proxyname == NULL) {
    return 1;
  }

  start_critical_section();

  arg.host = (char*) host;
  arg.serv = (char*) serv;
  arg.proxyname = (char*) proxyname;
  arg.proxyport = (char*) proxyport;
  arg.type = (char) type;
  arg.sockfd = sockets[1];

  retval = pthread_create(&proxy_thread, NULL, &http_proxy_client, &arg);

  wait_for_condition();

  end_critical_section();

  return retval;
}

#endif
