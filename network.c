/*
 * active port forwarder - software for secure forwarding
 * Copyright (C) 2003,2004 jeremian <jeremian [at] poczta.fm>
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

#include "network.h"
#include "activefor.h"
#include "stats.h"
#include <string.h>
#include <errno.h>
#include <zlib.h>

int
ip_listen(int* sockfd, const char *host, const char *serv, socklen_t *addrlenp, const char type)
{
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

	return(0);
}

int
ip_connect(int* sockfd, const char *host, const char *serv, const char type)
{
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

	return(0);
}

char *
sock_ntop(const struct sockaddr *sa, socklen_t salen, char* namebuf, char* portbuf)
{
    char		portstr[7];
    static char str[128];		/* Unix domain is largest */

    switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in	*sin = (struct sockaddr_in *) sa;

		if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL) {
			return(NULL);
		}
		if (namebuf) {
			if (inet_ntop(AF_INET, &sin->sin_addr, namebuf, 128) == NULL) {
				return(NULL);
			}
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

		if (inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)) == NULL) {
			return(NULL);
		}
		if (namebuf) {
			if (inet_ntop(AF_INET6, &sin6->sin6_addr, namebuf, 128) == NULL) {
				return(NULL);
			}
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
    return (NULL);
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
