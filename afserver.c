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
#include "file.h"
#include "stats.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>

static void usage(char* info);

int
main(int argc, char **argv)
{
	int	i, j, n, flags;
	ConfigurationT config;
	socklen_t	len;
	unsigned char				buff[8096];
	char	hostname[100];
	int			maxfdp1;
	fd_set		rset, allset;
	int manconnecting, numofcon, length;
	char* name    = NULL;
	char* listen  = NULL;
	char* manage  = NULL;
	char* amount  = NULL;
	char* filenam = NULL;
	char* type    = NULL;
	char* znak;
	char verbose = 0;
	RealmT* pointer = NULL;

	SSL_METHOD* method;
	SSL_CTX* ctx;
	
	signal(SIGPIPE, SIG_IGN);

	config.certif = NULL;
	config.keys = NULL;
	config.size = 0;
	config.realmtable = NULL;
	config.logging = 0;
	config.logfnam = NULL;

	while ((n = getopt(argc, argv, "hn:l:m:vu:c:k:f:t:o:O:")) != -1) {
		switch (n) {
		  case 'h': {
				    usage("Active port forwarder (server) v0.5.2");
				  break;
			    }
		  case 'n': {
				    name = optarg;
				    break;
			    }
		  case 'l': {
				    listen = optarg;
				    break;
			    }
		  case 'm': {
				    manage = optarg;
				    break;
			    }
		  case 'v': {
				    ++verbose;
				    break;
			    }
		  case 'u': {
				    amount = optarg;
				    break;
			    }
		  case 'c': {
				    config.certif = optarg;
				    break;
			    }
		  case 'k': {
				    config.keys = optarg;
				    break;
			    }
		  case 't': {
				    type = optarg;
				    break;
			    }
		  case 'f': {
				    filenam = optarg;
				    break;
			    }
		  case 'O': {
				    config.logfnam = optarg;
				    config.logging = 2;
				    break;
			    }
		  case 'o': {
				    config.logfnam = optarg;
				    config.logging = 1;
				    break;
			    }
		  case '?': {
				    usage("");
				    break;
			    }
		}
	}

	if (filenam != NULL) {
		config = parsefile(filenam, &n);
		if (n) {
			printf("parsing failed! line:%d\n", n);
			exit(1);
		}
		else {
			if (verbose) {
				printf("cfg file OK! (readed realms: %d)\n", config.size);
			}
		}
	}
	else {
		if (name == NULL) {
			gethostname(hostname, 100);
			name = hostname;
		}
		if (listen == NULL) {
			listen = "50127";
		}
		if (manage == NULL) {
			manage = "50126";
		}
		if (amount == NULL) {
			amount = "5";
		}
		if (config.certif == NULL) {
			config.certif = "cacert.pem";
		}
		if (config.keys == NULL) {
			config.keys = "server.rsa";
		}
		if (type == NULL) {
			type = "tcp";
		}
		config.size = 1;
		config.realmtable = calloc(config.size, sizeof(RealmT));
		config.realmtable[0].hostname = name;
		config.realmtable[0].lisportnum = listen;
		config.realmtable[0].manportnum = manage;
		config.realmtable[0].users = amount;
		if (strcmp(type, "tcp") == 0) {
			config.realmtable[0].type = 1;
		}
		else if (strcmp(type, "udp") == 0) {
			config.realmtable[0].type = 2;
		}
		else {
			config.realmtable[0].type = 0;
		}
	}

	maxfdp1 = manconnecting = 0;
	
	SSL_library_init();
	method = SSLv3_server_method();
	ctx = SSL_CTX_new(method);
	if (SSL_CTX_set_cipher_list(ctx, "ALL:@STRENGTH") == 0) {
		printf("Setting ciphers list failed... exiting\n");
		exit(1);
	}
	if (SSL_CTX_use_RSAPrivateKey_file(ctx, config.keys, SSL_FILETYPE_PEM) != 1) {
		printf("Setting rsa key failed (%s)... exiting\n", config.keys);
		exit(1);
	}
	if (SSL_CTX_use_certificate_file(ctx, config.certif, SSL_FILETYPE_PEM) != 1) {
		printf("Setting certificate failed (%s)... exiting\n", config.certif);
		exit(1);
	}

	if (config.size == 0) {
		printf("Working without sense is really without sense...\n");
		exit(1);
	}
	
	FD_ZERO(&allset);
	
	for (i = 0; i < config.size; ++i) {
		if ((config.realmtable[i].hostname == NULL) ||
			(config.realmtable[i].lisportnum == NULL) ||
			(config.realmtable[i].manportnum == NULL) ||
			(config.realmtable[i].users == NULL)) {
			printf("Missing some of configurable variables... exiting\n");
			printf("%d) %s, %s, %s, %s\n", i, config.realmtable[i].hostname,
					config.realmtable[i].lisportnum,
					config.realmtable[i].manportnum,
					config.realmtable[i].users);
			exit(1);
		}
		if (config.realmtable[i].type == 0) {
			printf("Unrecognized type of the realm... exiting\n");
			exit(1);
		}
		if ((( config.realmtable[i].usernum = strtol(config.realmtable[i].users, &znak, 10)) == LONG_MAX) || (config.realmtable[i].usernum == LONG_MIN)) {
			printf("Invalid user amount - %s\n", config.realmtable[i].users);
			exit(1);
		}
		if (((*(config.realmtable[i].users)) == '\0') || (*znak != '\0')) {
			printf("Invalid user amount - %s\n", config.realmtable[i].users);
			exit(1);
		}
	
		config.realmtable[i].contable = calloc( config.realmtable[i].usernum, sizeof(ConnectuserT));
		if (config.realmtable[i].contable == NULL) {
			printf("Calloc error - try define smaller amount of users\n");
			exit(1);
		}
	
		config.realmtable[i].listenfd = ip_listen(config.realmtable[i].hostname,
				config.realmtable[i].lisportnum, (&(config.realmtable[i].addrlen)), "tcp");
		config.realmtable[i].managefd = ip_listen(config.realmtable[i].hostname,
				config.realmtable[i].manportnum, (&(config.realmtable[i].addrlen)), "tcp");
		config.realmtable[i].cliaddr = malloc(config.realmtable[i].addrlen);
		
		config.realmtable[i].ssl = SSL_new(ctx);
		if (config.realmtable[i].ssl == NULL) {
			printf("Creating of ssl object failed... exiting\n");
			exit(1);
		}
		
		FD_SET(config.realmtable[i].managefd, &allset);
		maxfdp1 = (maxfdp1 > (config.realmtable[i].managefd+1)) ? maxfdp1 : (config.realmtable[i].managefd+1);
		config.realmtable[i].usercon = 0;
		config.realmtable[i].ready = 0;
		config.realmtable[i].tv.tv_sec = 5;
		config.realmtable[i].tv.tv_usec = 0;
	}

	if (loginit(verbose, config.logging, config.logfnam)) {
		printf("Can't open file to log to... exiting\n");
		exit(1);
	}

	if (!verbose)
		daemon(0, 0);

	aflog(1, "Server started");
	
	for ( ; ; ) {
		rset = allset;
			aflog(2, ">select, maxfdp1: %d", maxfdp1);
		if (manconnecting) {
			/* find out, in what realm client is trying to connect */
			for (i = 0; i < config.size; ++i) {
				if ((config.realmtable[i].ready == 1) || (config.realmtable[i].ready == 2)) {
					break; /* so i points to first good realm */
				}
			}
			if (select(maxfdp1, &rset, NULL, NULL, (&(config.realmtable[i].tv))) == 0) { 
				  close (config.realmtable[i].commfd);
				  FD_CLR(config.realmtable[i].commfd, &allset);
				  FD_CLR(config.realmtable[i].listenfd, &allset);
				  FD_SET(config.realmtable[i].managefd, &allset);
				  config.realmtable[i].ready = 0;
				  manconnecting--;
				  aflog(1, "SSL_accept failed (timeout) in realm[%d]", i);
			}
		}
		else {
			select(maxfdp1, &rset, NULL, NULL, NULL);
		}
		aflog(2, "<<  >>after select...");

	for (j = 0; j < config.size; ++j) {
		pointer = (&(config.realmtable[j]));
		for (i = 0; i <pointer->usernum; ++i) {
		  if (pointer->contable[i].state == S_STATE_OPEN)
			if (FD_ISSET(pointer->contable[i].connfd, &rset)) {
				aflog(2, "FD_ISSET(realm[%d].contable[%d].connfd)", j, i);
				if (pointer->type == 1) { /* forwarding tcp packets */
				n = read(pointer->contable[i].connfd, &buff[5], 8091);
				if (n == -1)
					n = 0;
				if (n) {
					aflog(2, "message from realm[%d].con[%d], length=%d", j, i, n);
					if ((buff[5] == AF_S_MESSAGE) &&
							(buff[6] == AF_S_LOGIN) &&
								(buff[7] == AF_S_MESSAGE)) {
						aflog(2, "WARNING: got packet similiar to udp");
					}
					buff[0] = AF_S_MESSAGE; /* sending message */
					buff[1] = i >> 8;	/* high bits of user number */
					buff[2] = i;		/* low bits of user number */
					buff[3] = n >> 8;	/* high bits of message length */
					buff[4] = n;		/* low bits of message length */
					SSL_writen(pointer->ssl, buff, n+5);
				}
				else {
					aflog(1, "user closed: realm[%d].con[%d]", j, i);
					close(pointer->contable[i].connfd);
					FD_CLR(pointer->contable[i].connfd, &allset);
					pointer->contable[i].state = S_STATE_CLOSING;
					buff[0] = AF_S_CONCLOSED; /* closing connection */
					buff[1] = i >> 8;	/* high bits of user number */
					buff[2] = i;		/* low bits of user number */
					SSL_writen(pointer->ssl, buff, 5);
				}
				}
				else { /* when forwarding udp packets */
				n = readn(pointer->contable[i].connfd, buff, 5 );
				if (n != 5) {
					n = 0;
				}
				if (n) {
				 if ((buff[0] == AF_S_MESSAGE) && (buff[1] == AF_S_LOGIN)
						 && (buff[2] == AF_S_MESSAGE)) {
				      length = buff[3];
				      length = length << 8;
				      length += buff[4]; /* this is length of message */
				   if ((n = readn(pointer->contable[i].connfd, &buff[5], length)) != 0) {
				  	aflog(2, "message from realm[%d].con[%d], length=%d", j, i, n);
					buff[1] = i >> 8;	/* high bits of user number */
					buff[2] = i;		/* low bits of user number */
					SSL_writen(pointer->ssl, buff, n+5);
				   }
				 }
				 else {
					n = 0;
				 }
				}
				
				if (n == 0) {
					aflog(1, "user closed: realm[%d].con[%d]", j, i);
					close(pointer->contable[i].connfd);
					FD_CLR(pointer->contable[i].connfd, &allset);
					pointer->contable[i].state = S_STATE_CLOSING;
					buff[0] = AF_S_CONCLOSED; /* closing connection */
					buff[1] = i >> 8;	/* high bits of user number */
					buff[2] = i;		/* low bits of user number */
					SSL_writen(pointer->ssl, buff, 5);
				}

				}
			}
		}
		if (pointer->ready == 3)
		if (FD_ISSET(pointer->listenfd, &rset)) {
			aflog(2, "FD_ISSET(realm[%d].listenfd)", j);
			len = pointer->addrlen;
			if (pointer->ready == 3) {
				for (i = 0; i < pointer->usernum; ++i) {
					if (pointer->contable[i].state == S_STATE_CLEAR) {
				aflog(2, "realm[%d].contable[%d].connfd = (realm[%d].listenfd)", j, i, j);
						pointer->contable[i].connfd =
							accept(pointer->listenfd, pointer->cliaddr, &len);
						pointer->contable[i].state = S_STATE_OPENING;
						pointer->usercon++;
					aflog(1, "user IP:%s",sock_ntop(pointer->cliaddr, len));
						if (pointer->usercon == pointer->usernum)
							FD_CLR(pointer->listenfd, &allset);
						buff[0] = AF_S_CONOPEN; /* opening connection */
						buff[1] = i >> 8;	/* high bits of user number */
						buff[2] = i;		/* low bits of user number */
						SSL_writen(pointer->ssl, buff, 5);
						break;
					}
				}
			}
		}
		if (pointer->ready != 0)
		if (FD_ISSET(pointer->commfd, &rset)) {	
			if (pointer->ready == 1) {
				if (SSL_set_fd(pointer->ssl, pointer->commfd) != 1) {
					aflog(0, "Problem with initializing ssl... exiting");
					exit(1);
				}
				aflog(2, "Trying SSL_accept in realm[%d]", j);
				if ((n = SSL_accept(pointer->ssl)) != 1) {
						flags = SSL_get_error(pointer->ssl, n);
						switch (flags) {
							case SSL_ERROR_NONE : {
						aflog(2, "SSL_accept has failed(%d)...none", n);
										      break;
									      }
							case SSL_ERROR_ZERO_RETURN : {
						aflog(2, "SSL_accept has failed(%d)...zero", n);
										      break;
									      }
							case SSL_ERROR_WANT_READ : {
						aflog(2, "SSL_accept has failed(%d)...w_read", n);
										      break;
									      }
							case SSL_ERROR_WANT_WRITE : {
						aflog(2, "SSL_accept has failed(%d)...w_write", n);
										      break;
									      }
							case SSL_ERROR_WANT_CONNECT : {
						aflog(2, "SSL_accept has failed(%d)...w_connect", n);
										      break;
									      }
							case SSL_ERROR_WANT_X509_LOOKUP : {
						aflog(2, "SSL_accept has failed(%d)...w_x509_lookup", n);
										      break;
									      }
							case SSL_ERROR_SYSCALL : {
						aflog(2, "SSL_accept has failed(%d)...syscall", n);
										      break;
									      }
							case SSL_ERROR_SSL : {
									      SSL_load_error_strings();
						aflog(2, "SSL_accept has failed(%d)...ssl:%s",
							n, ERR_error_string(ERR_get_error(), (char*) buff));
										      break;
									      }
						}
					if (flags == SSL_ERROR_WANT_READ)
						continue; 
					  close (pointer->commfd);
					  FD_CLR(pointer->commfd, &allset);
					  FD_SET(pointer->managefd, &allset);
					  SSL_clear(pointer->ssl);
					  pointer->ready = 0;
					  manconnecting--;
					  aflog(1, "SSL_accept failed (denied) in realm[%d]", j);
				}
				else {
					  aflog(1, "SSL_accept successfull in realm[%d]", j);
					  pointer->ready = 2;
				}
				  continue; /* in the case this is not our client */
			}
			aflog(2, "FD_ISSET(realm[%d].commfd)", j);
			n = SSL_read(pointer->ssl, buff, 5);
			if (n == -1) {
				if (errno == EAGAIN) {
					continue;
				}
				else {
					n = 0;
				}
			}
			else if (n != 5) {
				n = 0;
			}
			if (n==0) {
				close(pointer->commfd);
				FD_CLR(pointer->commfd, &allset);
				FD_CLR(pointer->listenfd, &allset);
				FD_SET(pointer->managefd, &allset);
				maxfdp1 = (maxfdp1 > (pointer->managefd+1)) ? maxfdp1 : (pointer->managefd+1);
				if (pointer->ready == 3) {
				  for (i = 0; i < pointer->usernum; ++i) {
					  if (pointer->contable[i].state != S_STATE_CLEAR) {
					  pointer->contable[i].state = S_STATE_CLEAR;
					  FD_CLR(pointer->contable[i].connfd, &allset);
					  close(pointer->contable[i].connfd);
					  }
				  }
				}
				pointer->usercon = 0;
			        SSL_clear(pointer->ssl);
				pointer->ready = 0;
				aflog(1, "realm[%d].commfd closed!", j);
				continue;
			}
		      numofcon = buff[1];
		      numofcon = numofcon << 8;
		      numofcon += buff[2]; /* this is id of user */
		      length = buff[3];
		      length = length << 8;
		      length += buff[4]; /* this is length of message */
			switch (buff[0]) {
				case AF_S_CONCLOSED : {
						      if ((numofcon>=0) &&
							(numofcon<=(pointer->usernum)) &&
							  ((pointer->ready)==3)) {
							      (pointer->usercon)--;
								if (pointer->usercon == pointer->usernum-1)
									FD_SET(pointer->listenfd, &allset);
 						        	if (pointer->contable[numofcon].state ==
										S_STATE_CLOSING) {
								     pointer->contable[numofcon].state =
									     S_STATE_CLEAR; 
							      }
							      else if (pointer->contable[numofcon].state ==
									      S_STATE_OPEN) {
					aflog(1, "user kicked: realm[%d].con[%d]", j, numofcon);
					close(pointer->contable[numofcon].connfd);
					FD_CLR(pointer->contable[numofcon].connfd, &allset);
					pointer->contable[numofcon].state = S_STATE_CLEAR;
					buff[0] = AF_S_CONCLOSED; /* closing connection */
					buff[1] = numofcon >> 8;	/* high bits of user number */
					buff[2] = numofcon;		/* low bits of user number */
					SSL_writen(pointer->ssl, buff, 5);
							      }
						      }
							  else {
							  close (pointer->commfd);
							  FD_CLR(pointer->commfd, &allset);
							  FD_CLR(pointer->listenfd, &allset);
							  FD_SET(pointer->managefd, &allset);
							  if (pointer->ready == 2)
								  manconnecting--;
					  		  SSL_clear(pointer->ssl);
							  pointer->ready = 0;
							  }
						      break;
						      }
				case AF_S_CONOPEN : {
						      if ((numofcon>=0) &&
								   (numofcon<=(pointer->usernum)) &&
								      ((pointer->ready)==3)) {
							      if (pointer->contable[numofcon].state ==
									      S_STATE_OPENING) {
							         aflog(2, "realm[%d].con[%d]->ok",j,numofcon);
						        FD_SET(pointer->contable[numofcon].connfd, &allset);
						maxfdp1 = (maxfdp1 > (pointer->contable[numofcon].connfd+1)) ?
							maxfdp1 : (pointer->contable[numofcon].connfd+1);
								pointer->contable[numofcon].state =
									S_STATE_OPEN;
							      }
						      }
							  else {
							  close (pointer->commfd);
							  FD_CLR(pointer->commfd, &allset);
							  FD_CLR(pointer->listenfd, &allset);
							  FD_SET(pointer->managefd, &allset);
							  if (pointer->ready == 2)
								  manconnecting--;
					  		  SSL_clear(pointer->ssl);
							  pointer->ready = 0;
							  }
							      break;
						      }
				case AF_S_MESSAGE : {
							  if ((pointer->ready) != 3) {
							  close (pointer->commfd);
							  FD_CLR(pointer->commfd, &allset);
							  FD_CLR(pointer->listenfd, &allset);
							  FD_SET(pointer->managefd, &allset);
							  manconnecting--;
					  		  SSL_clear(pointer->ssl);
							  pointer->ready = 0;
							  break;
							  }
							  if (pointer->type==2) { /* udp */
							    n = SSL_readn(pointer->ssl, &buff[5], length);
							  }
							  else {
							    n = SSL_readn(pointer->ssl, buff, length);
							  }
							    if (n != length) {
							    aflog(2, "n(%d)!=length(%d)", n, length);
							      break;
							    }
						      if ((numofcon>=0) &&
							      (numofcon<=(pointer->usernum))) {
							      if (pointer->contable[numofcon].state ==
									      S_STATE_OPEN) {
					aflog(2, "message to realm[%d].con[%d], length=%d",j, numofcon, n);
					if (pointer->type==2) { /* udp */
						buff[1] = AF_S_LOGIN;
						buff[2] = AF_S_MESSAGE;
						         writen(pointer->contable[numofcon].connfd, buff, n+5);
					}
					else {
						         writen(pointer->contable[numofcon].connfd, buff, n);
					}
							      }
						      }
							      break;
						    }
				case AF_S_LOGIN : {
						  if ((pointer->ready == 2)&&(numofcon==259)&&(length==1538)) {
								  pointer->ready = 3;
						buff[0] = AF_S_LOGIN; /* sending message */
						buff[1] = pointer->usernum >> 8;/* high bits of user number */
						buff[2] = pointer->usernum;     /* low bits of user number */
							SSL_writen(pointer->ssl, buff, 5);
							FD_SET(pointer->listenfd, &allset);
							manconnecting--;
							  }
							  else {
							  close (pointer->commfd);
							  FD_CLR(pointer->commfd, &allset);
							  FD_CLR(pointer->listenfd, &allset);
							  FD_SET(pointer->managefd, &allset);
							if (pointer->ready == 2)
								manconnecting--;
					  		  SSL_clear(pointer->ssl);
							  pointer->ready = 0;
							  }
							  break;
						  }
				default : {
						  aflog(1, "Unrecognized message - closing realm[%d]", j);
						  close (pointer->commfd);
						  FD_CLR(pointer->commfd, &allset);
					  	  FD_CLR(pointer->listenfd, &allset);
						  FD_SET(pointer->managefd, &allset);
						  if (pointer->ready == 2)
							  manconnecting--;
						  if (pointer->ready == 3) {
							  for (i = 0; i < pointer->usernum; ++i) {
							  if (pointer->contable[i].state != S_STATE_CLEAR) {
								  pointer->contable[i].state = S_STATE_CLEAR;
					  			  FD_CLR(pointer->contable[i].connfd, &allset);
								  close(pointer->contable[i].connfd);
							  }
							  }
						  }
					  	  SSL_clear(pointer->ssl);
						  pointer->ready = 0;
					  }
			}
		}

		if (FD_ISSET(pointer->managefd, &rset)) {
			aflog(2, "FD_ISSET(realm[%d].managefd)", j);
			len = pointer->addrlen;
			if (!(pointer->ready)) {
				aflog(2, "accept(realm[%d].managefd)", j);
				pointer->commfd = accept(pointer->managefd, pointer->cliaddr, &len);
				flags = fcntl(pointer->commfd, F_GETFL, 0);
				fcntl(pointer->commfd, F_SETFL, flags | O_NONBLOCK);
				aflog(1, " >> Client IP:%s", sock_ntop(pointer->cliaddr, len));
				FD_SET(pointer->commfd, &allset);
				maxfdp1 = (maxfdp1 > (pointer->commfd+1)) ? maxfdp1 : (pointer->commfd+1);
				FD_CLR(pointer->managefd, &allset);
				pointer->tv.tv_sec = 5;
				manconnecting++;
				pointer->ready = 1;
			}
		}
	} /* realms loop */
	}
}

static void
usage(char* info)
{	
   printf("\n%s\n\n", info);
   printf("  Options:\n");
   printf("  -h                      - prints this help\n");
   printf("  -n [hostname]           - it's used when creating listening sockets\n");
   printf("                            (default: name returned by hostname function)\n");
   printf("  -l [portnum]            - the listening port number - users connect\n");
   printf("                            to it (default: 50127)\n");
   printf("  -m [portnum]            - the manage port number - second part of active\n");
   printf("                            port forwarder connects to it (default: 50126)\n");
   printf("  -u [#users]             - amount of users allowed to use this server\n");
   printf("                            (default: 5)\n");
   printf("  -c [cerfile]            - name of the file with certificate (default: cacert.pem)\n");
   printf("  -k [keyfile]            - name of the file with RSA key (default: server.rsa)\n");
   printf("  -f [cfgfile]            - name of the file with configuration for active\n");
   printf("                            forwarder (server)\n");
   printf("  -t [type]               - type of the server (tcp|udp) - for which protocol it\n");
   printf("                            would be (default: tcp)\n");
   printf("  -O [logfile]            - logging everything to a logfile\n");
   printf("  -o [logfile]            - logging some data to a logfile\n");
   printf("  -v                      - to be verbose - program won't enter into\n");
   printf("                            the daemon mode (use twice for greater effect)\n\n");
   exit(0);
}

