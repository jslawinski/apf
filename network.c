/*
 * active port forwarder - software for secure forwarding
 * Copyright (C) 2003 jeremian <jeremian@poczta.fm>
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
#include <string.h>
#include <errno.h>
#include <signal.h>

static void
sig_alrm(int signo)
{
	return;
}

int
ip_listen(const char *host, const char *serv, socklen_t *addrlenp, const char *type)
{
	int				listenfd, n, typ;
	const int		on = 1;
	struct addrinfo	hints, *res, *ressave;

	if (strcmp(type, "udp") == 0)
		typ = 0; /* this is udp_listen */
	else
		typ = 1; /* default: tcp_listen */
	
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	
	if (typ)
		hints.ai_socktype = SOCK_STREAM;
	else
		hints.ai_socktype = SOCK_DGRAM;

	if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0) {
		printf("%s_listen error for %s, %s: %s\n",
				 (typ)?"tcp":"udp", host, serv, gai_strerror(n));
		exit(1);
	}
	ressave = res;

	do {
		listenfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (listenfd < 0)
			continue;		/* error, try next one */

		if (typ) /* tcp_listen */
			setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		if (bind(listenfd, res->ai_addr, res->ai_addrlen) == 0)
			break;			/* success */

		close(listenfd);	/* bind error, close and try next one */
	} while ( (res = res->ai_next) != NULL);

	if (res == NULL) {	/* errno from final socket() or bind() */
		printf("%s_listen error for %s, %s\n", (typ)?"tcp":"udp", host, serv);
		exit(1);
	}

	if (typ) /* tcp_listen */
		listen(listenfd, 1);

	if (addrlenp)
		*addrlenp = res->ai_addrlen;	/* return size of protocol address */

	freeaddrinfo(ressave);

	return(listenfd);
}

int
ip_connect(const char *host, const char *serv, const char* type)
{
	int				sockfd, n, typ;
	struct addrinfo	hints, *res, *ressave;

	if (strcmp(type, "udp") == 0)
		typ = 0; /* this is udp_listen */
	else
		typ = 1; /* default: tcp_listen */
	
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	if (typ)
		hints.ai_socktype = SOCK_STREAM;
	else
		hints.ai_socktype = SOCK_DGRAM;

	if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0) {
		printf("%s_connect error for %s, %s: %s\n",
				(typ)?"tcp":"udp", host, serv, gai_strerror(n));
		exit(1);
	}
	ressave = res;

	do {
		sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sockfd < 0)
			continue;	/* ignore this one */

		if (connect(sockfd, res->ai_addr, res->ai_addrlen) == 0)
			break;		/* success */

		close(sockfd);	/* ignore this one */
	} while ( (res = res->ai_next) != NULL);

	if (res == NULL) {	/* errno set from final connect() */
		printf("%s_connect error for %s, %s\n", (typ)?"tcp":"udp", host, serv);
		exit(1);
	}

	freeaddrinfo(ressave);

	return(sockfd);
}

char *
sock_ntop(const struct sockaddr *sa, socklen_t salen)
{
    char		portstr[7];
    static char str[128];		/* Unix domain is largest */

	switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in	*sin = (struct sockaddr_in *) sa;

		if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
			return(NULL);
		if (ntohs(sin->sin_port) != 0) {
			snprintf(portstr, sizeof(portstr), ".%d", ntohs(sin->sin_port));
			strcat(str, portstr);
		}
		return(str);
	}

#ifdef	IPV6
	case AF_INET6: {
		struct sockaddr_in6	*sin6 = (struct sockaddr_in6 *) sa;

		if (inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)) == NULL)
			return(NULL);
		if (ntohs(sin6->sin6_port) != 0) {
			snprintf(portstr, sizeof(portstr), ".%d", ntohs(sin6->sin6_port));
			strcat(str, portstr);
		}
		return(str);
	}
#endif

	default:
		snprintf(str, sizeof(str), "sock_ntop: unknown AF_xxx: %d, len %d",
				 sa->sa_family, salen);
		return(str);
	}
    return (NULL);
}

int
SSL_writen(SSL* fd, unsigned char* buf, int amount)
{
	int sent, n;
	sent = 0;
	while (sent < amount) {
		signal(SIGALRM, sig_alrm);
		alarm(5);
		n = SSL_write(fd, buf+sent, amount - sent);
		alarm(0);
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
		signal(SIGALRM, sig_alrm);
		alarm(5);
		n = write(fd, buf+sent, amount - sent);
		alarm(0);
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
