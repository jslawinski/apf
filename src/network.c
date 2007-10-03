/*
 * active port forwarder - software for secure forwarding
 * Copyright (C) 2003-2007 jeremian <jeremian [at] poczta.fm>
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

#include "inet_ntop.h"
#include "network.h"
#include "activefor.h"
#include "stats.h"
#include "logging.h"
#include <string.h>
#include <errno.h>
#include <zlib.h>
#include <assert.h>

/*
 * Function name: ip_listen
 * Description: Creates the listening socket.
 * Arguments: sockfd - the created socket
 *            host - the name of the host
 *            serv - the name of the service (port)
 *            addrlenp - pointer to the length of the sockaddr structure
 *            type - the type of the socket
 * Returns: 0 - success,
 *          !0 - failure.
 */

int
ip_listen(int* sockfd, const char *host, const char *serv, socklen_t *addrlenp, const char type)
{
  const int        on = 1;
#if defined(HAVE_GETADDRINFO) && defined(AF_INET6)
  int              n;
  struct addrinfo  hints, *res, *ressave;

  aflog(LOG_T_INIT, LOG_I_DDEBUG,
      "ip_listen: host=[%s] serv=[%s], type=[%d]", host, serv, type);
  
  bzero(&hints, sizeof(struct addrinfo));
  hints.ai_flags = AI_PASSIVE;
  if (type & 0x02) {
    hints.ai_family = AF_INET;
  }
  else if (type & 0x04) {
    hints.ai_family = AF_INET6;
  }
  else {
    hints.ai_family = AF_UNSPEC;
  }
  
  if (type & 0x01) {
    hints.ai_socktype = SOCK_STREAM;
  }
  else {
    hints.ai_socktype = SOCK_DGRAM;
  }

  if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0) {
    return n;
  }
  ressave = res;

  do {
    (*sockfd) = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if ((*sockfd) < 0) {
      continue;    /* error, try next one */
    }

    if (type & 0x01) { /* tcp_listen */
      setsockopt((*sockfd), SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
      setsockopt((*sockfd), SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
    }
    
    if (bind((*sockfd), res->ai_addr, res->ai_addrlen) == 0) {
      break;      /* success */
    }

    close((*sockfd));  /* bind error, close and try next one */
  } while ( (res = res->ai_next) != NULL);

  if (res == NULL) {  /* errno from final socket() or bind() */
    return 1;
  }

  if (type & 0x01) { /* tcp_listen */
    listen((*sockfd), 1);
  }

  if (addrlenp) {
    *addrlenp = res->ai_addrlen;  /* return size of protocol address */
  }

  freeaddrinfo(ressave);
#else
  struct sockaddr_in servaddr;
  struct hostent* hostaddr = NULL;
  int port;
  
  aflog(LOG_T_INIT, LOG_I_DDEBUG,
      "ip_listen: host=[%s] serv=[%s], type=[%d]", host, serv, type);
  
  if (type & 0x01) {
    (*sockfd) = socket(AF_INET, SOCK_STREAM, 0);
  } 
  else {
    (*sockfd) = socket(AF_INET, SOCK_DGRAM, 0);
  } 
  
  if ((*sockfd) == -1) {
    return 1;
  } 
  port = atoi(serv);
  
  if (host) {
    hostaddr = gethostbyname(host);
    if (hostaddr == NULL) {
      return 2;
    }
  }
  
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  if (host) {
    memcpy(&servaddr.sin_addr.s_addr, hostaddr->h_addr_list[0], hostaddr->h_length);
  }
  else {
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  }
  servaddr.sin_port = htons(port);

  if (type & 0x01) { /* tcp_listen */
    setsockopt((*sockfd), SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    setsockopt((*sockfd), SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
  }
  
  if (bind((*sockfd), (struct sockaddr*) &servaddr, sizeof(servaddr))){
    printf("bind failed\n");
    return 4;
  } 
  
  if (type & 0x01) { /* tcp_listen */
    if (listen((*sockfd), 5)){
      return 5;
    } 
  }
  
  if (addrlenp) {
    *addrlenp = sizeof(servaddr);  /* return size of protocol address */
  }
#endif
  
  return(0);
}

/*
 * Function name: ip_connect
 * Description: Creates the connected socket.
 * Arguments: sockfd - the connected socket
 *            host - the name of the host
 *            serv - the name of the service (port)
 *            type - the type of the socket
 *            lhost - the name of the local host (used for local bind of the socket)
 *            lserv - the name of the local service (port) (used for local bind of the socket)
 * Returns: 0 - success,
 *          !0 - failure.
 */

int
ip_connect(int* sockfd, const char *host, const char *serv, const char type,
    const char *lhost, const char *lserv)
{
  const int        on = 1;
#if defined(HAVE_GETADDRINFO) && defined(AF_INET6)
  int    n;
  int    bindFailed;
  struct addrinfo  hints, *res, *ressave;
  struct addrinfo  lhints, *lres, *lressave = NULL;

  aflog(LOG_T_INIT, LOG_I_DDEBUG,
      "ip_connect: host=[%s] serv=[%s], type=[%d], lhost=[%s], lserv=[%s]", host, serv, type, lhost, lserv);
  
  bzero(&hints, sizeof(struct addrinfo));
  if (type & 0x02) {
    hints.ai_family = AF_INET;
  }
  else if (type & 0x04) {
    hints.ai_family = AF_INET6;
  }
  else {
    hints.ai_family = AF_UNSPEC;
  }
  if (type & 0x01) {
    hints.ai_socktype = SOCK_STREAM;
  }
  else {
    hints.ai_socktype = SOCK_DGRAM;
  }

  lhints = hints;
  
  if (lhost || lserv) {
    if ( (n = getaddrinfo(lhost, lserv, &lhints, &lres)) != 0) {
      return n;
    }
    lressave = lres;
  }
  
  if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0) {
    return n;
  }
  ressave = res;

  do {
    (*sockfd) = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if ((*sockfd) < 0) {
      continue;  /* ignore this one */
    }
    
    if (type & 0x01) { /* tcp_connect */
      setsockopt((*sockfd), SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
    }

    bindFailed = 0;
    if (lhost || lserv) {
      bindFailed = 1;
      lres = lressave;
      do {
        if (bind((*sockfd), lres->ai_addr, lres->ai_addrlen) == 0) {
          bindFailed = 0;
          break;      /* success */
        }
      } while ( (lres = lres->ai_next) != NULL);
    }

    if (bindFailed == 1) {
      close((*sockfd));  /* ignore this one */
      continue;
    }

    if (connect((*sockfd), res->ai_addr, res->ai_addrlen) == 0) {
      break;    /* success */
    }

    close((*sockfd));  /* ignore this one */
  } while ( (res = res->ai_next) != NULL);

  if (res == NULL) {  /* errno set from final connect() */
    return 1;
  }

  if (lhost || lserv) {
    freeaddrinfo(lressave);
  }
  freeaddrinfo(ressave);
#else
  struct sockaddr_in servaddr, lservaddr;
  struct hostent* hostaddr;
  struct hostent* lhostaddr;
  int port, lport;
  
  aflog(LOG_T_INIT, LOG_I_DDEBUG,
      "ip_connect: host=[%s] serv=[%s], type=[%d], lhost=[%s], lserv=[%s]", host, serv, type, lhost, lserv);

  if (type & 0x01) {
    (*sockfd) = socket(AF_INET, SOCK_STREAM, 0);
  }
  else {
    (*sockfd) = socket(AF_INET, SOCK_DGRAM, 0);
  }

  if ((*sockfd) == -1) {
    return 1;
  }
  port = atoi(serv);

  hostaddr = gethostbyname(host);
  if (hostaddr == NULL) {
    return 2;
  }

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(port);
  memcpy(&servaddr.sin_addr.s_addr, hostaddr->h_addr_list[0], hostaddr->h_length);

  if (type & 0x01) { /* tcp_connect */
    setsockopt((*sockfd), SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
  }
    
  if (lhost || lserv) {
    memset(&lservaddr, 0, sizeof(lservaddr));
    lservaddr.sin_family = AF_INET;
    if (lserv) {
      lport = atoi(lserv);
      lservaddr.sin_port = htons(lport);
    }
    if (lhost) {
      lhostaddr = gethostbyname(lhost);
      if (lhostaddr == NULL) {
        return 3;
      }
      memcpy(&lservaddr.sin_addr.s_addr, lhostaddr->h_addr_list[0], lhostaddr->h_length);
    }
    else {
      lservaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
    if (bind((*sockfd), (struct sockaddr*) &lservaddr, sizeof(lservaddr))){
      return 4;
    }
  }
  
  if (connect((*sockfd), (struct sockaddr*) &servaddr, sizeof(servaddr))){
    return 5;
  }
#endif

  return(0);
}

/*
 * Function name: sock_ntop
 * Description: Returns the string representing given socket address.
 * Arguments: sa - pointer to sockaddr structure
 *            salen - size of the sockaddr structure
 *            namebuf - buffer for string representation of the host name
 *            portbuf - buffer for string representation of the host port
 *            type - if the socket address should be resolved to the the DNS name
 * Returns: The string representing given socket address or NULL, if the address
 *          can't be established.
 */

char *
sock_ntop(const struct sockaddr *sa, socklen_t salen, char* namebuf, char* portbuf, char type)
{
  char        portstr[7];
  static char str[136];    /* Unix domain is largest */

  switch (sa->sa_family) {
    case AF_INET: {
                    struct sockaddr_in  *sin = (struct sockaddr_in *) sa;

                    if (type) {
#ifdef HAVE_GETNAMEINFO
                      if (getnameinfo(sa, salen, str, 128, NULL, 0, 0)) {
                        return NULL;
                      }
#else
                      struct hostent* hostname;
                      if ((hostname = gethostbyaddr((void*) &sin->sin_addr, sizeof(struct in_addr), AF_INET))) {
                        strncpy(str, hostname->h_name, 127);
                        str[127] = 0;
                      }
                      else {
                        if (inet_ntop(AF_INET, (void*) &sin->sin_addr, str, sizeof(str)) == NULL) {
                          return NULL;
                        }
                      }
#endif

                    }
                    else {
                      if (inet_ntop(AF_INET, (void*) &sin->sin_addr, str, sizeof(str)) == NULL) {
                        return NULL;
                      }
                    }
                    if (namebuf) {
                      memcpy(namebuf, str, 128);
                    }
                    if (ntohs(sin->sin_port) != 0) {
                      snprintf(portstr, sizeof(portstr), ".%d", ntohs(sin->sin_port));
                      if (portbuf) {
                        snprintf(portbuf, 7, "%d", ntohs(sin->sin_port));
                      }
                      strcat(str, portstr);
                    }
                    return(str);
                  }
#ifdef AF_INET6
    case AF_INET6: {
                     struct sockaddr_in6  *sin6 = (struct sockaddr_in6 *) sa;

                     if (type) {
#ifdef HAVE_GETNAMEINFO
                       if (getnameinfo(sa, salen, str, 128, NULL, 0, 0)) {
                         return NULL;
                       }
#else
                       struct hostent* hostname;
                       if ((hostname = gethostbyaddr(&sin6->sin6_addr, sizeof(struct in6_addr), AF_INET6))) {
                         strncpy(str, hostname->h_name, 127);
                         str[127] = 0;
                       }
                       else {
                         if (inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)) == NULL) {
                           return NULL;
                         }
                       }
#endif

                     }
                     else {
                       if (inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)) == NULL) {
                         return NULL;
                       }
                     }
                     if (namebuf) {
                       memcpy(namebuf, str, 128);
                     }
                     if (ntohs(sin6->sin6_port) != 0) {
                       snprintf(portstr, sizeof(portstr), ".%d", ntohs(sin6->sin6_port));
                       if (portbuf) {
                         snprintf(portbuf, 7, "%d", ntohs(sin6->sin6_port));
                       }
                       strcat(str, portstr);
                     }
                     return(str);
                   }
#endif
    default: {
               snprintf(str, sizeof(str), "sock_ntop: unknown AF_xxx: %d, len %d", sa->sa_family, salen);
               return(str);
             }
  }
  return NULL;
}

/*
 * Function name: SSL_writen
 * Description: Writes the given amount of data to the SSL connection.
 * Arguments: fd - the SSL connection
 *            buf - buffer with data to write
 *            amount - the size of the data
 * Returns: The amount of bytes written to the SSL connection.
 */

int
SSL_writen(SSL* fd, unsigned char* buf, int amount)
{
  int sent, n;
  sent = 0;
  assert(amount > 0);
  while (sent < amount) {
    n = SSL_write(fd, buf+sent, amount - sent);
    assert(n != 0);
    if (n != -1) {
      sent += n;
    }
    if (n == -1) {
      if (errno != EAGAIN)
        return 0;
    }
  }
  return amount;
}

/*
 * Function name: SSL_readn
 * Description: Reads the given amount of data from the SSL connection.
 * Arguments: fd - the SSL connection
 *            buf - buffer for data
 *            amount - the size of the data to read
 * Returns: The amount of bytes read from the SSL connection.
 */

int
SSL_readn(SSL* fd, unsigned char* buf, int amount)
{
  int sent, n;
  sent = 0;
  assert(amount > 0);
  while (sent < amount) {
    n = SSL_read(fd, buf+sent, amount - sent);
    if (n != -1) {
      sent += n;
    }
    if (n == 0)
      return 0;
    if (n == -1) {
      if (errno != EAGAIN)
        return 0;
    }
  }
  return amount;
} 

/*
 * Function name: writen
 * Description: Writes the given amount of data to the file descriptor.
 * Arguments: fd - the file descriptor
 *            buf - buffer with data to write
 *            amount - the size of the data
 * Returns: The amount of bytes written to the file descriptor
 */

int
writen(int fd, unsigned char* buf, int amount)
{
  int sent, n;
  sent = 0;
  assert(amount > 0);
  while (sent < amount) {
    n = write(fd, buf+sent, amount - sent);
    assert(n != 0);
    if (n != -1) {
      sent += n;
    }
    if (n == -1) {
      if (errno != EAGAIN)
        return 0;
    }
  }
  return amount;
}

/*
 * Function name: readn
 * Description: Reads the given amount of data from the file descriptor.
 * Arguments: fd - the file descriptor
 *            buf - buffer for data
 *            amount - the size of the data to read
 * Returns: The amount of bytes read from the file descriptor.
 */

int
readn(int fd, unsigned char* buf, int amount)
{
  int sent, n;
  sent = 0;
  assert(amount > 0);
  while (sent < amount) {
    n = read(fd, buf+sent, amount - sent);
    if (n != -1) {
      sent += n;
    }
    if (n == 0)
      return 0;
    if (n == -1) {
      if (errno != EAGAIN)
        return 0;
    }
  }
  return amount;

}
