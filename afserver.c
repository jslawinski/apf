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

#include "activefor.h"
#include "network.h"
#include "file.h"
#include "stats.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>

#include <getopt.h>

static void usage(char* info);
static void sig_int(int);

static struct option long_options[] = {
	{"help", 0, 0, 'h'},
	{"hostname", 1, 0, 'n'},
	{"listenport", 1, 0, 'l'},
	{"manageport", 1, 0, 'm'},
	{"verbose", 0, 0, 'v'},
	{"users", 1, 0, 'u'},
	{"cerfile", 1, 0, 'c'},
	{"keyfile", 1, 0, 'k'},
	{"cfgfile", 1, 0, 'f'},
	{"proto", 1, 0, 'p'},
	{"lightlog", 1, 0, 'o'},
	{"heavylog", 1, 0, 'O'},
	{"nossl", 0, 0, 301},
	{"nozlib", 0, 0, 302},
	{"pass", 1, 0, 303},
	{0, 0, 0, 0}
};

static ConfigurationT config;

int
main(int argc, char **argv)
{
	int	i, j, n, flags;
	socklen_t	len;
	unsigned char				buff[9000];
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
	unsigned char pass[4];
	char verbose = 0;
	char mode = 0;
	RealmT* pointer = NULL;

	SSL_METHOD* method;
	SSL_CTX* ctx;
	
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, sig_int);

	TYPE_SET_SSL(mode);
	TYPE_SET_ZLIB(mode);

	config.certif = NULL;
	config.keys = NULL;
	config.size = 0;
	config.realmtable = NULL;
	config.logging = 0;
	config.logfnam = NULL;

	while ((n = getopt_long(argc, argv, "hn:l:m:vu:c:k:f:p:o:O:", long_options, 0)) != -1) {
		switch (n) {
		  case 'h': {
				    usage(AF_VER("Active port forwarder (server)"));
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
		  case 'p': {
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
		  case 301: {
				    TYPE_UNSET_SSL(mode);
				    break;
			    }
		  case 302: {
				    TYPE_UNSET_ZLIB(mode);
				    break;
			    }
                  case 303: {
                                    n = strlen(optarg);
                                    memset(pass, 0, 4);
                                    for (i = 0; i < n; ++i) {
                                            pass[i%4] += optarg[i];
                                    }
                                    break;
                            }

		  case '?': {
				    usage("");
				    break;
			    }
		}
	}

	if (optind < argc) {
	    usage("Unrecognized non-option elements");
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
		memcpy(config.realmtable[0].pass, pass, 4);
		if (strcmp(type, "tcp") == 0) {
			TYPE_SET_TCP(config.realmtable[0].type);
		}
		else if (strcmp(type, "udp") == 0) {
			TYPE_SET_UDP(config.realmtable[0].type);
		}
		else {
			TYPE_SET_ZERO(config.realmtable[0].type);
		}
		config.realmtable[0].type |= mode;
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
		if (!TYPE_IS_SET(config.realmtable[i].type)) {
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
		
		config.realmtable[i].cliconn.ssl = SSL_new(ctx);
		if (config.realmtable[i].cliconn.ssl == NULL) {
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

	aflog(1, "SERVER STARTED realms: %d", config.size);
	
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
				  close (config.realmtable[i].cliconn.commfd);
				  FD_CLR(config.realmtable[i].cliconn.commfd, &allset);
				  FD_CLR(config.realmtable[i].listenfd, &allset);
				  FD_SET(config.realmtable[i].managefd, &allset);
				  config.realmtable[i].ready = 0;
				  manconnecting--;
				  aflog(1, "  realm[%d]: SSL_accept failed (timeout)", i);
			}
		}
		else {
			select(maxfdp1, &rset, NULL, NULL, NULL);
		}
		aflog(2, " >>after select...");

	for (j = 0; j < config.size; ++j) {
		pointer = (&(config.realmtable[j]));
		for (i = 0; i <pointer->usernum; ++i) {
		  if (pointer->contable[i].state == S_STATE_OPEN)
			if (FD_ISSET(pointer->contable[i].connfd, &rset)) {
				aflog(2, " realm[%d]: user[%d]: FD_ISSET", j, i);
				if (TYPE_IS_TCP(pointer->type)) { /* forwarding tcp packets */
				n = read(pointer->contable[i].connfd, &buff[5], 8091);
				if (n == -1)
					n = 0;
				if (n) {
					aflog(2, "  realm[%d]: FROM user[%d]: MESSAGE length=%d", j, i, n);
					if ((buff[5] == AF_S_MESSAGE) &&
							(buff[6] == AF_S_LOGIN) &&
								(buff[7] == AF_S_MESSAGE)) {
						aflog(2, "  WARNING: got packet similiar to udp");
					}
					buff[0] = AF_S_MESSAGE; /* sending message */
					buff[1] = i >> 8;	/* high bits of user number */
					buff[2] = i;		/* low bits of user number */
					buff[3] = n >> 8;	/* high bits of message length */
					buff[4] = n;		/* low bits of message length */
					send_message(pointer->type, pointer->cliconn, buff, n+5);
				}
				else {
					aflog(1, "  realm[%d]: user[%d]: CLOSED", j, i);
					close(pointer->contable[i].connfd);
					FD_CLR(pointer->contable[i].connfd, &allset);
					pointer->contable[i].state = S_STATE_CLOSING;
					buff[0] = AF_S_CONCLOSED; /* closing connection */
					buff[1] = i >> 8;	/* high bits of user number */
					buff[2] = i;		/* low bits of user number */
					send_message(pointer->type, pointer->cliconn, buff, 5);
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
					aflog(2, "  realm[%d]: FROM user[%d]: MESSAGE length=%d", j, i, n);
					buff[1] = i >> 8;	/* high bits of user number */
					buff[2] = i;		/* low bits of user number */
					send_message(pointer->type, pointer->cliconn, buff, n+5);
				   }
				 }
				 else {
					n = 0;
				 }
				}
				
				if (n == 0) {
					aflog(1, "  realm[%d]: user[%d]: CLOSED", j, i);
					close(pointer->contable[i].connfd);
					FD_CLR(pointer->contable[i].connfd, &allset);
					pointer->contable[i].state = S_STATE_CLOSING;
					buff[0] = AF_S_CONCLOSED; /* closing connection */
					buff[1] = i >> 8;	/* high bits of user number */
					buff[2] = i;		/* low bits of user number */
					send_message(pointer->type, pointer->cliconn, buff, 5);
				}

				}
			}
		}
		if (pointer->ready == 3)
		if (FD_ISSET(pointer->listenfd, &rset)) {
			aflog(2, " realm[%d]: listenfd: FD_ISSET", j);
			len = pointer->addrlen;
			if (pointer->ready == 3) {
				for (i = 0; i < pointer->usernum; ++i) {
					if (pointer->contable[i].state == S_STATE_CLEAR) {
				aflog(2, "  realm[%d]: new user[%d]: CONNECTING", j, i);
						pointer->contable[i].connfd =
							accept(pointer->listenfd, pointer->cliaddr, &len);
						pointer->contable[i].state = S_STATE_OPENING;
						pointer->usercon++;
					aflog(1, "  user IP:%s",sock_ntop(pointer->cliaddr, len));
						if (pointer->usercon == pointer->usernum)
							FD_CLR(pointer->listenfd, &allset);
						buff[0] = AF_S_CONOPEN; /* opening connection */
						buff[1] = i >> 8;	/* high bits of user number */
						buff[2] = i;		/* low bits of user number */
						send_message(pointer->type, pointer->cliconn, buff, 5);
						break;
					}
				}
			}
		}
		if (pointer->ready != 0)
		if (FD_ISSET(pointer->cliconn.commfd, &rset)) {	
			if (pointer->ready == 1) {
				if (SSL_set_fd(pointer->cliconn.ssl, pointer->cliconn.commfd) != 1) {
					aflog(0, "Problem with initializing ssl... exiting");
					exit(1);
				}
				aflog(2, "  realm[%d]: new client: SSL_accept", j);
				if ((n = SSL_accept(pointer->cliconn.ssl)) != 1) {
						flags = SSL_get_error(pointer->cliconn.ssl, n);
						switch (flags) {
							case SSL_ERROR_NONE : {
						aflog(2, "  SSL_accept has failed(%d)...none", n);
										      break;
									      }
							case SSL_ERROR_ZERO_RETURN : {
						aflog(2, "  SSL_accept has failed(%d)...zero", n);
										      break;
									      }
							case SSL_ERROR_WANT_READ : {
						aflog(2, "  SSL_accept has failed(%d)...w_read", n);
										      break;
									      }
							case SSL_ERROR_WANT_WRITE : {
						aflog(2, "  SSL_accept has failed(%d)...w_write", n);
										      break;
									      }
							case SSL_ERROR_WANT_CONNECT : {
						aflog(2, "  SSL_accept has failed(%d)...w_connect", n);
										      break;
									      }
							case SSL_ERROR_WANT_X509_LOOKUP : {
						aflog(2, "  SSL_accept has failed(%d)...w_x509_lookup", n);
										      break;
									      }
							case SSL_ERROR_SYSCALL : {
						aflog(2, "  SSL_accept has failed(%d)...syscall", n);
										      break;
									      }
							case SSL_ERROR_SSL : {
									      SSL_load_error_strings();
						aflog(2, "  SSL_accept has failed(%d)...ssl:%s",
							n, ERR_error_string(ERR_get_error(), (char*) buff));
										      break;
									      }
						}
					if (flags == SSL_ERROR_WANT_READ)
						continue; 
					  close (pointer->cliconn.commfd);
					  FD_CLR(pointer->cliconn.commfd, &allset);
					  FD_SET(pointer->managefd, &allset);
					  SSL_clear(pointer->cliconn.ssl);
					  pointer->ready = 0;
					  manconnecting--;
					  aflog(1, "  realm[%d]: new client: DENIED by SSL_accept", j);
				}
				else {
					  aflog(1, "  realm[%d]: new client: ACCEPTED by SSL_accept", j);
					  pointer->ready = 2;
				}
				  continue; /* in the case this is not our client */
			}
			aflog(2, " realm[%d]: commfd: FD_ISSET", j);
			if (pointer->ready == 2) {
				n = get_message(pointer->type | TYPE_SSL, pointer->cliconn, buff, -5);
			}
			else {
				n = get_message(pointer->type, pointer->cliconn, buff, -5);
			}
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
				close(pointer->cliconn.commfd);
				FD_CLR(pointer->cliconn.commfd, &allset);
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
			        SSL_clear(pointer->cliconn.ssl);
				pointer->ready = 0;
				aflog(1, "  realm[%d]: commfd: CLOSED", j);
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
					aflog(1, "  realm[%d]: user[%d]: KICKED", j, numofcon);
					close(pointer->contable[numofcon].connfd);
					FD_CLR(pointer->contable[numofcon].connfd, &allset);
					pointer->contable[numofcon].state = S_STATE_CLEAR;
					buff[0] = AF_S_CONCLOSED; /* closing connection */
					buff[1] = numofcon >> 8;	/* high bits of user number */
					buff[2] = numofcon;		/* low bits of user number */
					send_message(pointer->type, pointer->cliconn, buff, 5);
							      }
						      }
							  else {
							  close (pointer->cliconn.commfd);
							  FD_CLR(pointer->cliconn.commfd, &allset);
							  FD_CLR(pointer->listenfd, &allset);
							  FD_SET(pointer->managefd, &allset);
							  if (pointer->ready == 2)
								  manconnecting--;
					  		  SSL_clear(pointer->cliconn.ssl);
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
							aflog(2, "  realm[%d]: user[%d]: NEW", j, numofcon);
						        FD_SET(pointer->contable[numofcon].connfd, &allset);
					      maxfdp1 = (maxfdp1 > (pointer->contable[numofcon].connfd+1)) ?
							maxfdp1 : (pointer->contable[numofcon].connfd+1);
								pointer->contable[numofcon].state =
									S_STATE_OPEN;
							      }
						      }
							  else {
							  close (pointer->cliconn.commfd);
							  FD_CLR(pointer->cliconn.commfd, &allset);
							  FD_CLR(pointer->listenfd, &allset);
							  FD_SET(pointer->managefd, &allset);
							  if (pointer->ready == 2)
								  manconnecting--;
					  		  SSL_clear(pointer->cliconn.ssl);
							  pointer->ready = 0;
							  }
							      break;
						      }
				case AF_S_MESSAGE : {
							  if ((pointer->ready) != 3) {
							  close (pointer->cliconn.commfd);
							  FD_CLR(pointer->cliconn.commfd, &allset);
							  FD_CLR(pointer->listenfd, &allset);
							  FD_SET(pointer->managefd, &allset);
							  manconnecting--;
					  		  SSL_clear(pointer->cliconn.ssl);
							  pointer->ready = 0;
							  break;
							  }
							  if (TYPE_IS_UDP(pointer->type)) { /* udp */
				    n = get_message(pointer->type, pointer->cliconn, &buff[5], length);
							  }
							  else {
				    n = get_message(pointer->type, pointer->cliconn, buff, length);
							  }
						      if ((numofcon>=0) &&
							      (numofcon<=(pointer->usernum))) {
							      if (pointer->contable[numofcon].state ==
									      S_STATE_OPEN) {
				aflog(2, "  realm[%d]: TO user[%d]: MESSAGE length=%d", j, numofcon, n);
					if (TYPE_IS_UDP(pointer->type)) { /* udp */
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
						  if ((pointer->ready == 2)&&
							  (numofcon==(pointer->pass[0]*256+pointer->pass[1]))&&
							  (length==(pointer->pass[2]*256+pointer->pass[3]))) {
								  pointer->ready = 3;
						  	aflog(1, "  realm[%d]: pass ok - ACCESS GRANTED", j);
						buff[0] = AF_S_LOGIN; /* sending message */
						buff[1] = pointer->usernum >> 8;/* high bits of user number */
						buff[2] = pointer->usernum;     /* low bits of user number */
						buff[3] = pointer->type;	/* type of connection */
					send_message(pointer->type | TYPE_SSL, pointer->cliconn, buff, 5);
							FD_SET(pointer->listenfd, &allset);
							manconnecting--;
							  }
							  else {
						  	aflog(1, "  realm[%d]: Wrong password - CLOSING", j);
							  close (pointer->cliconn.commfd);
							  FD_CLR(pointer->cliconn.commfd, &allset);
							  FD_CLR(pointer->listenfd, &allset);
							  FD_SET(pointer->managefd, &allset);
							if (pointer->ready == 2)
								manconnecting--;
					  		  SSL_clear(pointer->cliconn.ssl);
							  pointer->ready = 0;
							  }
							  break;
						  }
				default : {
						  aflog(1, "  realm[%d]: Unrecognized message - CLOSING", j);
						  close (pointer->cliconn.commfd);
						  FD_CLR(pointer->cliconn.commfd, &allset);
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
					  	  SSL_clear(pointer->cliconn.ssl);
						  pointer->ready = 0;
					  }
			}
		}

		if (FD_ISSET(pointer->managefd, &rset)) {
			aflog(2, " realm[%d]: managefd: FD_ISSET", j);
			len = pointer->addrlen;
			if (!(pointer->ready)) {
				aflog(2, "  realm[%d]: new client: CONNECTING", j);
				pointer->cliconn.commfd = accept(pointer->managefd, pointer->cliaddr, &len);
				flags = fcntl(pointer->cliconn.commfd, F_GETFL, 0);
				fcntl(pointer->cliconn.commfd, F_SETFL, flags | O_NONBLOCK);
				aflog(1, "  realm[%d]: Client IP:%s", j, sock_ntop(pointer->cliaddr, len));
				FD_SET(pointer->cliconn.commfd, &allset);
		maxfdp1 = (maxfdp1 > (pointer->cliconn.commfd+1)) ? maxfdp1 : (pointer->cliconn.commfd+1);
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
   printf("  -h, --help          - prints this help\n");
   printf("  -n, --hostname      - it's used when creating listening sockets\n");
   printf("                        (default: name returned by hostname function)\n");
   printf("  -l, --listenport    - the listening port number - users connect\n");
   printf("                        to it (default: 50127)\n");
   printf("  -m, --manageport    - the manage port number - second part of active\n");
   printf("                        port forwarder connects to it (default: 50126)\n");
   printf("  -u, --users         - amount of users allowed to use this server\n");
   printf("                        (default: 5)\n");
   printf("  -c, --cerfile       - name of the file with certificate (default: cacert.pem)\n");
   printf("  -k, --keyfile       - name of the file with RSA key (default: server.rsa)\n");
   printf("  -f, --cfgfile       - name of the file with configuration for active\n");
   printf("                        forwarder (server)\n");
   printf("  -p, --proto         - type of the server (tcp|udp) - for which protocol it\n");
   printf("                        would be (default: tcp)\n");
   printf("  -O, --heavylog      - logging everything to a logfile\n");
   printf("  -o, --lightlog      - logging some data to a logfile\n");
   printf("  -v, --verbose       - to be verbose - program won't enter into\n");
   printf("                        the daemon mode (use twice for greater effect)\n");
   printf("  --nossl             - ssl is not used for transfering data (but it's still\n");
   printf("                        used to establish connection) (default: ssl is used)\n");
   printf("  --nozlib            - zlib is not used for compressing data (default:\n");
   printf("                        zlib is used)\n");
   printf("  --pass              - set the password used for client identification\n");
   printf("                        (default: no password)\n\n");
   exit(0);
}

static void
sig_int(int signo)
{
	int j;
	unsigned char buff[5];
	for (j = 0; j < config.size; ++j) {
		buff[0] = AF_S_CLOSING; /* closing */
		send_message(config.realmtable[j].type, config.realmtable[j].cliconn, buff, 5);
	}
        aflog(1, "SERVER CLOSED cg: %ld bytes", getcg());
        exit(0);
}

