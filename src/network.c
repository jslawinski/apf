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

#include "inet_ntop.h"
#include "network.h"
#include "activefor.h"
#include "stats.h"
#include <string.h>
#include <errno.h>
#include <zlib.h>

int
ip_listen(int* sockfd, const char *host, const char *serv, socklen_t *addrlenp, const char type)
{
#if defined(HAVE_GETADDRINFO) && defined(AF_INET6)
	int			 n;
	const int		on = 1;
	struct addrinfo	hints, *res, *ressave;

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
			continue;		/* error, try next one */
		}

		if (type & 0x01) { /* tcp_listen */
			setsockopt((*sockfd), SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		}
		if (bind((*sockfd), res->ai_addr, res->ai_addrlen) == 0) {
			break;			/* success */
		}

		close((*sockfd));	/* bind error, close and try next one */
	} while ( (res = res->ai_next) != NULL);

	if (res == NULL) {	/* errno from final socket() or bind() */
		return 1;
	}

	if (type & 0x01) { /* tcp_listen */
		listen((*sockfd), 1);
	}

	if (addrlenp) {
		*addrlenp = res->ai_addrlen;	/* return size of protocol address */
	}

	freeaddrinfo(ressave);
#else
  struct sockaddr_in servaddr;
  struct hostent* hostaddr;
  int port;
  
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
  
  if (bind((*sockfd), (struct sockaddr*) &servaddr, sizeof(servaddr))){
    return 4;
  } 
  
  if (listen((*sockfd), 5)){
    return 5;
  } 
#endif
  
  return(0);
}

int
ip_connect(int* sockfd, const char *host, const char *serv, const char type)
{
#if defined(HAVE_GETADDRINFO) && defined(AF_INET6)
	int				n;
	struct addrinfo	hints, *res, *ressave;

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

	if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0) {
		return n;
	}
	ressave = res;

	do {
		(*sockfd) = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if ((*sockfd) < 0) {
			continue;	/* ignore this one */
		}

		if (connect((*sockfd), res->ai_addr, res->ai_addrlen) == 0) {
			break;		/* success */
		}

		close((*sockfd));	/* ignore this one */
	} while ( (res = res->ai_next) != NULL);

	if (res == NULL) {	/* errno set from final connect() */
		return 1;
	}

	freeaddrinfo(ressave);
#else
  struct sockaddr_in servaddr;
  struct hostent* hostaddr;
  int port;

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

  if (connect((*sockfd), (struct sockaddr*) &servaddr, sizeof(servaddr))){
    return 3;
  }
#endif

	return(0);
}

char *
sock_ntop(const struct sockaddr *sa, socklen_t salen, char* namebuf, char* portbuf, char type)
{
    char		portstr[7];
    static char str[136];		/* Unix domain is largest */

    switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in	*sin = (struct sockaddr_in *) sa;

    if (type) {
#ifdef HAVE_GETNAMEINFO
      if (getnameinfo(sa, salen, str, 128, NULL, 0, 0)) {
        return NULL;
      }
#else
      struct hostent* hostname;
      if ((hostname = gethostbyaddr(&sin->sin_addr, sizeof(struct in_addr), AF_INET))) {
        strncpy(str, hostname->h_name, 127);
        str[127] = 0;
      }
      else {
        if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL) {
          return NULL;
        }
      }
#endif

    }
    else {
  		if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL) {
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
		struct sockaddr_in6	*sin6 = (struct sockaddr_in6 *) sa;

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

int
SSL_writen(SSL* fd, unsigned char* buf, int amount)
{
	int sent, n;
	sent = 0;
	while (sent < amount) {
		n = SSL_write(fd, buf+sent, amount - sent);
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

int
SSL_readn(SSL* fd, unsigned char* buf, int amount)
{
	int sent, n;
	sent = 0;
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

int
writen(int fd, unsigned char* buf, int amount)
{
	int sent, n;
	sent = 0;
	while (sent < amount) {
		n = write(fd, buf+sent, amount - sent);
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

int
readn(int fd, unsigned char* buf, int amount)
{
	int sent, n;
	sent = 0;
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

int
send_message(char type, clifd fd, unsigned char* buf, int amount)
{
	unsigned long clen;
	int length;
	static unsigned char bufor[9000];
  aflog(4, "   send_message: ssl:%s zlib:%s length:%d", (TYPE_IS_SSL(type))?"yes":"no",
      (TYPE_IS_ZLIB(type))?"yes":"no", amount);
	clen = 8995;
	length = amount - 5;
	if (TYPE_IS_ZLIB(type)) {
		memcpy(bufor, buf, 5);
		if (amount > 5) {
			compress(&bufor[5], &clen, &buf[5], length);
			if (clen < length) {
				length = clen;
				TYPE_SET_COMP(length);
				bufor[3] = length >> 8; /* high bits of message length */
				bufor[4] = length;	/* low bits of message length */
				addtocg(amount-5 - clen);
			}
		}
		if (TYPE_IS_SSL(type)) {
			if (TYPE_IS_COMP(length)) {
				return SSL_writen(fd.ssl, bufor, clen+5);
			}
			else {
				return SSL_writen(fd.ssl, buf, amount);
			}
		}
		else {
			if (TYPE_IS_COMP(length)) {
				return writen(fd.commfd, bufor, clen+5);
			}
			else {
				return writen(fd.commfd, buf, amount);
			}
		}
	}
	else {
		if (TYPE_IS_SSL(type)) {
			return SSL_writen(fd.ssl, buf, amount);
		}
		else {
			return writen(fd.commfd, buf, amount);
		}
	}
}

int
get_message(char type, clifd fd, unsigned char* buf, int amount)
{
	int length;
	unsigned long elen;
	static unsigned char bufor[9000];
  aflog(4, "   get_message: ssl:%s zlib:%s length:%d", (TYPE_IS_SSL(type))?"yes":"no",
      (TYPE_IS_ZLIB(type))?"yes":"no", amount);
	if (amount == -5) {
		if (TYPE_IS_SSL(type)) {
			return SSL_read(fd.ssl, buf, 5);
		}
		else {
			return read(fd.commfd, buf, 5);
		}
	}
	if (TYPE_IS_ZLIB(type)) {
		if (TYPE_IS_SSL(type)) {
			length = SSL_readn(fd.ssl, bufor, amount&0xBFFF);
		}
		else {
			length = readn(fd.commfd, bufor, amount&0xBFFF);
		}
		if (length <= 0) return length;
		elen = 8096;
		if (TYPE_IS_COMP(amount)) {
			uncompress(buf, &elen, bufor, length);
		}
		else {
			memcpy(buf, bufor, length);
			elen = length;
		}
		return elen;
	}
	else
	{
		if (TYPE_IS_SSL(type)) {
			return SSL_readn(fd.ssl, buf, amount);
		}
		else {
			return readn(fd.commfd, buf, amount);
		}
	}
}