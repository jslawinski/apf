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

#include "activefor.h"
#include "network.h"
#include "stats.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <signal.h>

static void usage(char* info);

int
main(int argc, char **argv)
{
	int	masterfd, i, n, numofcon, length, buflength, notsent, temp2; /* !!! */
	ConnectuserT* contable = NULL;
	unsigned char				buff[8096];
	char hostname[100];
	struct timeval tv;
	int			maxfdp1, usernum, usercon, merror;
	socklen_t		len, addrlen;
	struct sockaddr* cliaddr;
	fd_set		rset, allset;
	char verbose = 0;
	char logging = 0;
	char* name = NULL;
	char* manage = NULL;
	char* desnam = NULL;
	char* despor = NULL;
	char* keys = NULL;
	char* logfname = NULL;
	char udp = 0;
	char reverse = 0;

	SSL_METHOD* method;
	SSL_CTX* ctx;
	SSL* ssl;

	signal(SIGPIPE, SIG_IGN);

	while ((n = getopt(argc, argv, "huUn:m:d:p:vk:O:o:")) != -1) {
		switch (n) {
		  case 'h': {
				    usage("Active port forwarder (client) v0.5.2");
					  break;
				  }
		  case 'n': {
				    name = optarg;
				    break;
			    }
		  case 'm': {
				    manage = optarg;
				    break;
			    }
		  case 'd': {
				    desnam = optarg;
				    break;
			    }
		  case 'p': {
				    despor = optarg;
				    break;
			    }
		  case 'v': {
				    ++verbose;
				    break;
			    }
		  case 'u': {
				    udp = 1;
				    break;
			    }
		  case 'U': {
				    reverse = 1;
				    break;
			    }
		  case 'k': {
				    keys = optarg;
				    break;
			    }
		  case 'O': {
				    logfname = optarg;
				    logging = 2;
				    break;
			    }
		  case 'o': {
				    logfname = optarg;
				    logging = 1;
				    break;
			    }
		  case '?': {
				    usage("");
				    break;
			    }
		}
	}

	if (name == NULL) {
		usage("Name of the server is required");
	}
	if (manage == NULL) {
		manage = "50126";
		if (reverse)
			usage("Port on the server is required in reverse mode");
	}
	if (desnam == NULL) {
		gethostname(hostname, 100);
		desnam = hostname;
	}
	if (despor == NULL) {
		usage("Destination port number is required");
	}
	if (keys == NULL) {
		keys = "client.rsa";
	}


	masterfd = ip_connect(name, manage, "tcp");

	if (!reverse) {
	SSL_library_init();
	method = SSLv3_client_method();
	ctx = SSL_CTX_new(method);
	if (SSL_CTX_set_cipher_list(ctx, "ALL:@STRENGTH") == 0) {
		printf("Setting cipher list failed... exiting\n");
		exit(1);
	}
	if (SSL_CTX_use_RSAPrivateKey_file(ctx, keys, SSL_FILETYPE_PEM) != 1) {
		printf("Setting rsa key failed (%s)... exiting\n", keys);
		exit(1);
	}
	ssl = SSL_new(ctx);
	if (SSL_set_fd(ssl, masterfd) != 1) {
		printf("Problem with initializing ssl... exiting\n");
		exit(1);
	}
	if (verbose>1)
		printf("Trying SSL_connect\n");
	if ((n = SSL_connect(ssl)) == 1) {
		if (verbose) {
			printf("SSL_connect successfull\n");
		}
	}
	else {
		printf("SSL_connect has failed (%d)... exiting\n", n);
		exit(1);
	}

	
	buff[0] = AF_S_LOGIN;
	buff[1] = 1;
	buff[2] = 3;
	buff[3] = 6;
	buff[4] = 2;
	SSL_write(ssl, buff, 5);
	buff[0] = 0;
	SSL_read(ssl, buff, 5);
	
	if ( buff[0] != AF_S_LOGIN ) {
		printf("Incompatible server type or server full\n");
		exit(1);
	}

	usernum = buff[1];
	usernum = usernum << 8;
	usernum += buff[2];

	} /* !reverse */
	else {
		usernum = 1;
		ssl = NULL;
	}

	contable = calloc( usernum, sizeof(ConnectuserT));
	if (contable == NULL) {
		printf("Calloc error - unable to succesfully comunicate with server\n");
		exit(1);
	}
	
	len = 4;
	if (getsockopt(masterfd, SOL_SOCKET, SO_SNDBUF, &buflength, &len) == -1) {
		printf("Can't get socket send buffor size - exiting...\n");
		exit(1);
	}

	if (loginit(verbose, logging, logfname)) {
		printf("Can't open file to log to... exiting\n");
		exit(1);
	}
	
	if (!verbose)
		daemon(0, 0);
	
	FD_ZERO(&allset);
	
	FD_SET(masterfd, &allset);
	maxfdp1 = masterfd + 1;

	if (reverse) {
		contable[0].connfd=ip_listen(desnam, despor, &addrlen, "udp");
		cliaddr = malloc(addrlen);
		maxfdp1 = (maxfdp1>contable[0].connfd+1) ? maxfdp1 : contable[0].connfd+1;
		FD_SET(contable[0].connfd, &allset);
		aflog(1, "^^Started in udp reverse mode^^");
		for ( ; ; ) {
			len = 4;
			if (getsockopt(masterfd, SOL_SOCKET, SO_SNDBUF, &temp2, &len) != -1) {
				if (temp2 != buflength) {
					buflength = temp2;
					aflog(2, "Send buffor size changed...");
				}
			}
			len = addrlen;
			rset = allset;
			aflog(2, ">select");
			select(maxfdp1, &rset, NULL, NULL, NULL);
			aflog(2, ">>after select...");
			if (FD_ISSET(contable[0].connfd, &rset)) {
				n = recvfrom(contable[0].connfd, &buff[5], 8091, 0, cliaddr, &len);
#ifdef SIOCOUTQ
				if (ioctl(masterfd, SIOCOUTQ, &notsent)) {
					aflog(0, "ioctl error -> exiting...");
					exit(1);
				}
				if (buflength <= notsent + n + 5) { /* when we can't do this */
					aflog(2, "drop: size:%d, buf:%d, w:%d/%d",
								n, buflength, notsent, buflength);
#else
				if (ioctl(masterfd, TIOCOUTQ, &notsent)) {
					aflog(0, "ioctl error -> exiting...");
					exit(1);
				}
				if (notsent <= n + 5) { /* when we can't do this */
					aflog(2, "drop: size:%d, buf:%d, w:%d/%d",
								n, buflength, buflength - notsent, buflength);
#endif
				}
				else {
					if (n > 0) {
							aflog(2, "Sending %d bytes to service (w:%d/%d)",
									n,
#ifdef SIOCOUTQ
									notsent
#else
									buflength - notsent
#endif
									, buflength);
						buff[0] = AF_S_MESSAGE;
						buff[1] = AF_S_LOGIN;
						buff[2] = AF_S_MESSAGE;
						buff[3] = n >> 8;
						buff[4] = n;
						writen(masterfd, buff, n + 5);
					}
				}
			}
			if (FD_ISSET(masterfd, &rset)) {
				n = readn(masterfd, buff, 5);
				if (n == 5) {
					if ((buff[0] != AF_S_MESSAGE) || (buff[1] != AF_S_LOGIN)
							|| (buff[2] != AF_S_MESSAGE)) {
				aflog(0, "Incompatible server type (not udp?) or data corruption -> exiting...");
					exit(1);
					}
					length = buff[3];
					length = length << 8;
					length += buff[4]; /* this is length of message */
					n = readn(masterfd, buff, length);
				}
				else {
					n = 0;
				}
				if (n == 0) { /* server quits -> we do the same... */
					gettimeofday(&tv, 0);
					aflog(0, "premature quit of the server -> exiting...");
					exit(1);
				}
				aflog(2, "Sending %d bytes to user", n);
				sendto(contable[0].connfd, buff, n, 0, cliaddr, addrlen);
			}
		}
		exit(0); /* we shouldn't get here */
	}
	
	aflog(1, "^^Started in normal mode^^ (%s)", (udp)?"udp":"tcp");
	
	for ( ; ; ) {
		rset = allset;
			aflog(2, ">select");
		select(maxfdp1, &rset, NULL, NULL, NULL);
			aflog(2, ">>after select...");

		for (i = 0; i < usernum; ++i) {
			if (contable[i].state == S_STATE_OPEN)
			   if (FD_ISSET(contable[i].connfd, &rset)) {	
				aflog(2, "FD_ISSET(contable[%d].connfd)", i);
				n = read(contable[i].connfd, &buff[5], 8091);
				if (n == -1) {
					aflog(0, "FATAL ERROR! (%d) while reading from user", n);
					n = 0;
				}
#ifdef SIOCOUTQ
				if (ioctl(masterfd, SIOCOUTQ, &notsent)) {
					aflog(0, "ioctl error -> exiting...");
					exit(1);
				}
				if (udp) {
					len = 4;
					if (getsockopt(masterfd, SOL_SOCKET, SO_SNDBUF, &temp2, &len) != -1) {
						if (temp2 != buflength) {
							buflength = temp2;
							aflog(2, "Send buffor size changed...");
						}
					}
					if (buflength <= notsent + n + 5) { /* when we can't send this */
						aflog(2, "drop: size:%d, buf:%d, w:%d/%d",
								n+5, buflength, notsent, buflength);
#else
				if (ioctl(masterfd, TIOCOUTQ, &notsent)) {
					aflog(0, "ioctl error -> exiting...");
					exit(1);
				}
				if (udp) {
					len = 4;
					if (getsockopt(masterfd, SOL_SOCKET, SO_SNDBUF, &temp2, &len) != -1) {
						if (temp2 != buflength) {
							buflength = temp2;
							aflog(2, "Send buffor size changed...");
						}
					}
					if (notsent <= n + 5) { /* when we can't send this */
						aflog(2, "drop: size:%d, buf:%d, w:%d/%d",
								n+5, buflength, buflength-notsent, buflength);
#endif
						continue; /* drop this packet */
					}
				}
				if (n) {
					buff[0] = AF_S_MESSAGE; /* sending message */
					buff[1] = i >> 8;	/* high bits of user number */
					buff[2] = i;		/* low bits of user number */
					buff[3] = n >> 8;	/* high bits of message length */
					buff[4] = n;		/* low bits of message length */
					aflog(2, "Sending %d bytes to user (%d) [%d/%d]",
								n, i,
#ifdef SIOCOUTQ
									notsent
#else
									buflength - notsent
#endif
									, buflength);
					SSL_writen(ssl, buff, n+5);
				}
				else if (!udp) {
					close(contable[i].connfd);
					FD_CLR(contable[i].connfd, &allset);
					contable[i].state = S_STATE_CLOSING;
					buff[0] = AF_S_CONCLOSED; /* closing connection */
					buff[1] = i >> 8;	/* high bits of user number */
					buff[2] = i;		/* low bits of user number */
					SSL_writen(ssl, buff, 5);
				}
			}
		}

		if (FD_ISSET(masterfd, &rset)) {
			aflog(2, "FD_ISSET(masterfd)");
			n = SSL_readn(ssl, buff, 5);
			if (n != 5) {
				aflog(2, "FATAL ERROR! (%d)", n);
				if (n == -1) {
					merror = SSL_get_error(ssl, n);
					switch (merror) {
                                                        case SSL_ERROR_NONE : {
										      aflog(2, "FE: none");
                                                                                      break;
                                                                              }
                                                        case SSL_ERROR_ZERO_RETURN : {
										      aflog(2, "FE: zero");
                                                                                      break;
                                                                              }
                                                        case SSL_ERROR_WANT_READ : {
										      aflog(2, "FE: w_read");
                                                                                      break;
                                                                              }
                                                        case SSL_ERROR_WANT_WRITE : {
										      aflog(2, "FE: w_write");
                                                                                      break;
                                                                              }
                                                        case SSL_ERROR_WANT_CONNECT : {
										     aflog(2, "FE: w_connect");
                                                                                      break;
                                                                              }
                                                        case SSL_ERROR_WANT_X509_LOOKUP : {
									       aflog(2, "FE: w_x509_lookup");
                                                                                      break;
                                                                              }
                                                        case SSL_ERROR_SYSCALL : {
										      aflog(2, "FE: syscall");
                                                                                      break;
                                                                              }
                                                        case SSL_ERROR_SSL : {
                                                                              SSL_load_error_strings();
								      aflog(2, "FE: ssl:%s",
							      ERR_error_string(ERR_get_error(), (char*) buff));
                                                                                      break;
                                                                              }
                                                }
					continue; /* what happened? */
				}
				if (n != 0)
					exit(1);
			}
			if (n == 0) { /* server quits -> we do the same... */
				aflog(0, "premature quit of the server -> exiting...");
				exit(1);
			}
			numofcon = buff[1];
			numofcon = numofcon << 8;
			numofcon += buff[2]; /* this is id of user */
			length = buff[3];
			length = length << 8;
			length += buff[4]; /* this is length of message */
			switch (buff[0]) {
				case AF_S_CONCLOSED : {
						      if ((numofcon>=0) && (numofcon<=usernum)) {
							      usercon--;
							      if (contable[numofcon].state == S_STATE_CLOSING) {
								      contable[numofcon].state = S_STATE_CLEAR;
							      }
							      else if (contable[numofcon].state==S_STATE_OPEN) {
					      close(contable[numofcon].connfd);
					      FD_CLR(contable[numofcon].connfd, &allset);
					      contable[numofcon].state = S_STATE_CLEAR;
					      buff[0] = AF_S_CONCLOSED; /* closing connection */
					      buff[1] = numofcon >> 8;		/* high bits of user number */
					      buff[2] = numofcon;		/* low bits of user number */
					      SSL_writen(ssl, buff, 5);
							      }
						      }
						      break;
						      }
				case AF_S_CONOPEN : {
						if ((numofcon>=0) && (numofcon<=usernum)) {
							usercon++;
 						  if (contable[numofcon].state == S_STATE_CLEAR) {
							  if (udp) {
						    contable[numofcon].connfd=ip_connect(desnam,despor,"udp");
							  }
							  else {
						    contable[numofcon].connfd=ip_connect(desnam,despor,"tcp");
							  }
						    FD_SET(contable[numofcon].connfd, &allset);
						    maxfdp1 = (maxfdp1 > (contable[numofcon].connfd+1)) ? maxfdp1 : (contable[numofcon].connfd+1);
					    buff[0] = AF_S_CONOPEN; /* closing connection */
					    buff[1] = numofcon >> 8;		/* high bits of user number */
					    buff[2] = numofcon; 		/* low bits of user number */
					    SSL_writen(ssl, buff, 5);
					    contable[numofcon].state = S_STATE_OPEN;
						  }
						}
						break;
						    }
				case AF_S_MESSAGE : {
					    aflog(2, "Received msg for con[%d], length=%d", numofcon, length);
							    n = SSL_readn(ssl, buff, length);
							    if (n != length) {
								aflog(2, "n(%d)!=length(%d)", n, length);
							      break;
							    }
						if ((numofcon>=0) && (numofcon<=usernum)) {
							if (contable[numofcon].state == S_STATE_OPEN) {
							aflog(2, "sent msg con[%d], length=%d", numofcon, n);
							  if (writen(contable[numofcon].connfd, buff, n)==-1) {
								  aflog(0, "Sending msg failed!");
							  }
							}
						}
							    break;
						    }
				default : { /* unrecognized type of message -> exiting... */
					  aflog(0, "Server sents unrecognized message -> exiting...");
					  exit(1);
						  
						  break;
					  }
			}
		}
	}
}

static void
usage(char* info)
{
    printf("\n%s\n\n", info);
    printf("  Options:\n");
    printf("  -h                      - prints this help\n");
    printf("  -n [server name]        - where the second part of the active\n");
    printf("                            port forwarder is running (required)\n");
    printf("  -m [portnum]            - the manage port number - server must\n");
    printf("                            listening on it (default: 50126)\n");
    printf("  -d [hostname]           - name of this host/remote host - the final\n");
    printf("                            destination of the packets (default: name\n");
    printf("                            returned by hostname function)\n");
    printf("  -p [portnum]            - port we are forwarding connection to (required)\n");
    printf("  -k [keyfile]            - name of the file with RSA key (default: client.rsa)\n");
    printf("  -u                      - udp mode - client will use udp protocol to\n");
    printf("                            communicate with hostname\n");
    printf("  -U                      - reverse udp forwarding. Udp packets will be forwarded\n");
    printf("                            from hostname:portnum (-p) to server name:portnum (-m)\n");
    printf("  -O [logfile]            - logging everything to a logfile\n");
    printf("  -o [logfile]            - logging some data to a logfile\n");
    printf("  -v                      - to be verbose - program won't enter into\n");
    printf("                            the daemon mode (use twice for greater effect)\n\n");
    exit(0);
}

