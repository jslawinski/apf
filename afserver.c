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
#include <sys/time.h>
#include <getopt.h>

static void usage(char* info);
static void sig_int(int);
static void remove_client(RealmT*, int, fd_set*, fd_set*, int*);
static int find_client(RealmT*, char);
static int eval_numofcon(RealmT*, int, int);
static int eval_usernum(ConnectclientT*, int);
static int find_usernum(ConnectclientT*, int);
static void check_value(int*, char*, char*);

static struct option long_options[] = {
	{"help", 0, 0, 'h'},
	{"hostname", 1, 0, 'n'},
	{"listenport", 1, 0, 'l'},
	{"manageport", 1, 0, 'm'},
	{"timeout", 1, 0, 't'},
	{"verbose", 0, 0, 'v'},
	{"users", 1, 0, 'u'},
	{"clients", 1, 0, 'C'},
	{"usrpcli", 1, 0, 'U'},
	{"climode", 1, 0, 'M'},
	{"cerfile", 1, 0, 'c'},
	{"keyfile", 1, 0, 'k'},
	{"cfgfile", 1, 0, 'f'},
	{"proto", 1, 0, 'p'},
	{"lightlog", 1, 0, 'o'},
	{"heavylog", 1, 0, 'O'},
	{"nossl", 0, 0, 301},
	{"nozlib", 0, 0, 302},
	{"pass", 1, 0, 303},
	{"ipv4", 0, 0, '4'},
	{"ipv6", 0, 0, '6'},
	{0, 0, 0, 0}
};

static ConfigurationT config;

int
main(int argc, char **argv)
{
	int	i, j=0, k, n, flags, sent;
	socklen_t	len;
	unsigned char				buff[9000];
	char	hostname[100];
	int			maxfdp1;
	fd_set		rset, allset, wset, tmpset;
	int manconnecting, numofcon, length;
	char* name    = NULL;
	char* listen  = NULL;
	char* manage  = NULL;
	char* amount  = NULL;
	char* clients = NULL;
	char* usrpcli = NULL;
  char* clim    = NULL;
	char* filenam = NULL;
	char* type    = NULL;
	char* timeout = NULL;
	unsigned char pass[4] = {1, 2, 3, 4};
	char verbose = 0;
	char mode = 0;
	char ipfam = 0;
	RealmT* pointer = NULL;
	struct sigaction act;

	SSL_METHOD* method;
	SSL_CTX* ctx;
	
	sigfillset(&(act.sa_mask));
	act.sa_flags = 0;
	
	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);
	act.sa_handler = sig_int;
	sigaction(SIGINT, &act, NULL);
	
	TYPE_SET_SSL(mode);
	TYPE_SET_ZLIB(mode);

	config.certif = NULL;
	config.keys = NULL;
	config.size = 0;
	config.realmtable = NULL;
	config.logging = 0;
	config.logfnam = NULL;

	while ((n = getopt_long(argc, argv, "hn:l:m:vu:c:k:f:p:o:O:46t:C:U:M:", long_options, 0)) != -1) {
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
		  case 't': {
				    timeout = optarg;
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
		  case 'C': {
				    clients = optarg;
				    break;
			    }
		  case 'U': {
				    usrpcli = optarg;
				    break;
			    }
		  case 'M': {
				    clim = optarg;
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
				    config.logging = 3;
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
		  case '4': {
				    if (ipfam != 0) {
					    ipfam = -1;
				    }
				    else {
					    ipfam = 4;
				    }
				    break;
			    }
		  case '6': {
				    if (ipfam != 0) {
					    ipfam = -1;
				    }
				    else {
					    ipfam = 6;
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
		if (timeout == NULL) {
			timeout = "5";
		}
		if (amount == NULL) {
			amount = "5";
		}
		if (clients == NULL) {
			clients = "1";
		}
		if (usrpcli == NULL) {
			usrpcli = amount;
		}
    if (clim == NULL) {
      clim = "1";
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
		config.realmtable[0].clients = clients;
		config.realmtable[0].timeout = timeout;
		config.realmtable[0].usrpcli = usrpcli;
		config.realmtable[0].clim = clim;
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
		if (ipfam == -1) {
			printf("Conflicting types of ip protocol family... exiting\n");
			exit(1);
		}
		else if (ipfam == 4) {
			TYPE_SET_IPV4(config.realmtable[0].type);
		}
		else if (ipfam == 6) {
			TYPE_SET_IPV6(config.realmtable[0].type);
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
	FD_ZERO(&wset);
	
	for (i = 0; i < config.size; ++i) {
		if ((config.realmtable[i].hostname == NULL) ||
			(config.realmtable[i].lisportnum == NULL) ||
			(config.realmtable[i].manportnum == NULL)) {
			printf("Missing some of the configurable variables...\n");
			printf("\nRealm: %d\nhostname: %s\nlistenport: %s\nmanageport: %s\n",
					i, config.realmtable[i].hostname,
					config.realmtable[i].lisportnum,
					config.realmtable[i].manportnum);
			exit(1);
		}
    /* checking type of the realm */
		if (!TYPE_IS_SET(config.realmtable[i].type)) {
			TYPE_SET_TCP(config.realmtable[i].type);
		}
    /* checking users amount */
    if (config.realmtable[i].users == NULL) {
      config.realmtable[i].users = "5";
    }
    check_value(&(config.realmtable[i].usernum), config.realmtable[i].users, "Invalid users amount");
    /* checking clients amount */
    if (config.realmtable[i].clients == NULL) {
      config.realmtable[i].clients = "1";
    }
    check_value(&(config.realmtable[i].clinum), config.realmtable[i].clients, "Invalid clients amount");
    /* checking usrpcli value */
    if (config.realmtable[i].usrpcli == NULL) {
      config.realmtable[i].usrpcli = config.realmtable[i].users;
    }
    check_value(&(config.realmtable[i].upcnum), config.realmtable[i].usrpcli, "Invalid usrpcli value");
    /* checking timeout value */
    if (config.realmtable[i].timeout == NULL) {
      config.realmtable[i].timeout = "5";
    }
    check_value(&(config.realmtable[i].tmout), config.realmtable[i].timeout, "Invalid timeout value");
    /* checking climode value */
    if (config.realmtable[i].clim == NULL) {
      config.realmtable[i].clim = "1";
    }
    check_value(&(config.realmtable[i].climode), config.realmtable[i].clim, "Invalid climode value");
    /* allocating memory*/
		config.realmtable[i].contable = calloc( config.realmtable[i].usernum, sizeof(ConnectuserT));
		if (config.realmtable[i].contable == NULL) {
			printf("Calloc error - try define smaller amount of users\n");
			exit(1);
		}
		config.realmtable[i].clitable = calloc( config.realmtable[i].clinum, sizeof(ConnectclientT));
		if (config.realmtable[i].clitable == NULL) {
			printf("Calloc error - try define smaller amount of clients\n");
			exit(1);
		}
		ipfam = 0x01;
		if (TYPE_IS_IPV4(config.realmtable[i].type)) {
			ipfam |= 0x02;
		}
		else if (TYPE_IS_IPV6(config.realmtable[i].type)) {
			ipfam |= 0x04;
		}
		if (ip_listen(&(config.realmtable[i].listenfd), config.realmtable[i].hostname,
			config.realmtable[i].lisportnum, (&(config.realmtable[i].addrlen)), ipfam)) {
			printf("tcp_listen_%s error for %s, %s\n",
					(ipfam & 0x02)?"ipv4":(ipfam & 0x04)?"ipv6":"unspec",
					config.realmtable[i].hostname, config.realmtable[i].lisportnum);
			exit(1);
		}
		if (ip_listen(&(config.realmtable[i].managefd), config.realmtable[i].hostname,
			config.realmtable[i].manportnum, (&(config.realmtable[i].addrlen)), ipfam)) {
			printf("tcp_listen_%s error for %s, %s\n",
					(ipfam & 0x02)?"ipv4":(ipfam & 0x04)?"ipv6":"unspec",
					config.realmtable[i].hostname, config.realmtable[i].manportnum);
			exit(1);
		}
		config.realmtable[i].cliaddr = malloc(config.realmtable[i].addrlen);
		
    for (j=0; j<config.realmtable[i].clinum; ++j) {
  		config.realmtable[i].clitable[j].cliconn.ssl = SSL_new(ctx);
  		if (config.realmtable[i].clitable[j].cliconn.ssl == NULL) {
  			printf("Creating of ssl object failed... exiting\n");
  			exit(1);
  		}
    }
		
		FD_SET(config.realmtable[i].managefd, &allset);
		FD_SET(config.realmtable[i].listenfd, &allset);
		maxfdp1 = (maxfdp1 > (config.realmtable[i].managefd+1)) ? maxfdp1 : (config.realmtable[i].managefd+1);
		maxfdp1 = (maxfdp1 > (config.realmtable[i].listenfd+1)) ? maxfdp1 : (config.realmtable[i].listenfd+1);
		config.realmtable[i].usercon = 0;
		config.realmtable[i].clicon = 0;
    for (j=0; j<config.realmtable[i].clinum; ++j) {
		  config.realmtable[i].clitable[j].ready = 0;
      config.realmtable[i].clitable[j].tv.tv_sec = config.realmtable[i].tmout;
      config.realmtable[i].clitable[j].tv.tv_usec = 0;
      config.realmtable[i].clitable[j].usernum = config.realmtable[i].upcnum;
      config.realmtable[i].clitable[j].users = malloc( config.realmtable[i].clitable[j].usernum * sizeof(int));
      if (config.realmtable[i].clitable[j].users == NULL) {
        printf("Calloc error - try define smaller amount of usrpcli (or users)\n");
        exit(1);
      }
      for (k=0; k<config.realmtable[i].clitable[j].usernum; ++k) {
        config.realmtable[i].clitable[j].users[k] = -1;
      }
    }
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
		tmpset = wset;
			aflog(3, ">select, maxfdp1: %d", maxfdp1);
		if (manconnecting) {
			/* find out, in what realm client is trying to connect */
			for (k = 0; k < config.size; ++k) {
        for (j=0; j < config.realmtable[k].clinum; ++j) {
				  if ((config.realmtable[k].clitable[j].ready == 1) || (config.realmtable[k].clitable[j].ready == 2)) {
            i = k;
            k = config.size;
				  	break; /* so i points to first good realm and j to good client */
				  }
        }
			}
			if (select(maxfdp1, &rset, &tmpset, NULL, (&(config.realmtable[i].clitable[j].tv))) == 0) { 
				  close (config.realmtable[i].clitable[j].cliconn.commfd);
				  FD_CLR(config.realmtable[i].clitable[j].cliconn.commfd, &allset);
				  FD_SET(config.realmtable[i].managefd, &allset);
					SSL_clear(config.realmtable[i].clitable[j].cliconn.ssl);
				  config.realmtable[i].clitable[j].ready = 0;
				  manconnecting--;
          config.realmtable[i].clicon--;
				  aflog(1, "  realm[%d]: client[%d]: SSL_accept failed (timeout)", i, j);
			}
		}
		else {
			select(maxfdp1, &rset, &tmpset, NULL, NULL);
		}
		aflog(3, " >>after select...");

	for (j = 0; j < config.size; ++j) {
		pointer = (&(config.realmtable[j]));
		for (i = 0; i <pointer->usernum; ++i) {
		  if ((pointer->contable[i].state == S_STATE_OPEN) || (pointer->contable[i].state == S_STATE_STOPPED))
        if (FD_ISSET(pointer->contable[i].connfd, &rset)) {
          k = eval_usernum(&(pointer->clitable[pointer->contable[i].whatcli]), i);
          aflog(3, " realm[%d]: client[%d]: user[%d]: FD_ISSET", j, pointer->contable[i].whatcli, k);
          if (TYPE_IS_TCP(pointer->type)) { /* forwarding tcp packets */
            n = read(pointer->contable[i].connfd, &buff[5], 8091);
            if (n == -1) {
              aflog(3, "  realm[%d]: client[%d]: user[%d]: READ ERROR (%d)", j,
                  pointer->contable[i].whatcli, k, errno);
              n = 0;
            }
            if (n) {
              aflog(2, "  realm[%d]: client[%d]: FROM user[%d]: MESSAGE length=%d", j,
                  pointer->contable[i].whatcli, k, n);
              if ((buff[5] == AF_S_MESSAGE) && (buff[6] == AF_S_LOGIN) && (buff[7] == AF_S_MESSAGE)) {
                aflog(2, "  WARNING: got packet similiar to udp");
              }
              buff[0] = AF_S_MESSAGE; /* sending message */
              buff[1] = k >> 8;	/* high bits of user number */
              buff[2] = k;		/* low bits of user number */
              buff[3] = n >> 8;	/* high bits of message length */
              buff[4] = n;		/* low bits of message length */
              send_message(pointer->type, pointer->clitable[pointer->contable[i].whatcli].cliconn, buff, n+5);
            }
            else {
              aflog(1, "  realm[%d]: client[%d]: user[%d]: CLOSED", j, pointer->contable[i].whatcli, k);
              aflog(2, "   IP:%s PORT:%s", pointer->contable[i].namebuf,
							pointer->contable[i].portbuf);
              close(pointer->contable[i].connfd);
              FD_CLR(pointer->contable[i].connfd, &allset);
              FD_CLR(pointer->contable[i].connfd, &wset);
              pointer->contable[i].state = S_STATE_CLOSING;
              freebuflist(&pointer->contable[i].head);
              buff[0] = AF_S_CONCLOSED; /* closing connection */
              buff[1] = k >> 8;	/* high bits of user number */
              buff[2] = k;		/* low bits of user number */
              send_message(pointer->type, pointer->clitable[pointer->contable[i].whatcli].cliconn, buff, 5);
            }
          }
          else { /* when forwarding udp packets */
            n = readn(pointer->contable[i].connfd, buff, 5 );
            if (n != 5) {
              n = 0;
            }
            if (n) {
              if ((buff[0] == AF_S_MESSAGE) && (buff[1] == AF_S_LOGIN) && (buff[2] == AF_S_MESSAGE)) {
                length = buff[3];
                length = length << 8;
                length += buff[4]; /* this is length of message */
                if ((n = readn(pointer->contable[i].connfd, &buff[5], length)) != 0) {
                  aflog(2, "  realm[%d]: client[%d]: FROM user[%d]: MESSAGE length=%d", j,
                      pointer->contable[i].whatcli, k, n);
                  buff[1] = k >> 8;	/* high bits of user number */
                  buff[2] = k;		/* low bits of user number */
                  send_message(pointer->type, pointer->clitable[pointer->contable[i].whatcli].cliconn,
                      buff, n+5);
                }
              }
              else {
                n = 0;
              }
            }
            
            if (n == 0) {
              aflog(1, "  realm[%d]: client[%d]: user[%d]: CLOSED (udp mode)", j,
                  pointer->contable[i].whatcli, k);
              aflog(2, "   IP:%s PORT:%s", pointer->contable[i].namebuf,
							pointer->contable[i].portbuf);
              close(pointer->contable[i].connfd);
              FD_CLR(pointer->contable[i].connfd, &allset);
              FD_CLR(pointer->contable[i].connfd, &wset);
              pointer->contable[i].state = S_STATE_CLOSING;
              freebuflist(&pointer->contable[i].head);
              buff[0] = AF_S_CONCLOSED; /* closing connection */
              buff[1] = k >> 8;	/* high bits of user number */
              buff[2] = k;		/* low bits of user number */
              send_message(pointer->type, pointer->clitable[pointer->contable[i].whatcli].cliconn, buff, 5);
            }
            
          }
        }
    }
		/* ------------------------------------ */
		for (i = 0; i <pointer->usernum; ++i) {
      if (pointer->contable[i].state == S_STATE_STOPPED)
        if (FD_ISSET(pointer->contable[i].connfd, &tmpset)) {
          k = eval_usernum(&(pointer->clitable[pointer->contable[i].whatcli]), i);
            aflog(3, " realm[%d]: client[%d]: user[%d]: FD_ISSET - WRITE", j, pointer->contable[i].whatcli,
                k);
          n = pointer->contable[i].head->msglen - pointer->contable[i].head->actptr;
          sent = write(pointer->contable[i].connfd,
              &(pointer->contable[i].head->buff[pointer->contable[i].head->actptr]), n);
          if ((sent > 0) && (sent != n)) {
            pointer->contable[i].head->actptr+=sent;
          }
          else if ((sent == -1) && (errno == EAGAIN)) {
          }
          else if (sent == -1) {
            aflog(1, "  realm[%d]: client[%d]: user[%d]: CLOSED", j, pointer->contable[i].whatcli, k);
            aflog(2, "   IP:%s PORT:%s", pointer->contable[i].namebuf, pointer->contable[i].portbuf);
            close(pointer->contable[i].connfd);
            FD_CLR(pointer->contable[i].connfd, &allset);
            FD_CLR(pointer->contable[i].connfd, &wset);
            pointer->contable[i].state = S_STATE_CLOSING;
            freebuflist(&pointer->contable[i].head);
            buff[0] = AF_S_CONCLOSED; /* closing connection */
            buff[1] = k >> 8;	/* high bits of user number */
            buff[2] = k;		/* low bits of user number */
            send_message(pointer->type, pointer->clitable[pointer->contable[i].whatcli].cliconn, buff, 5);
          }
          else {
            deleteblnode(&pointer->contable[i].head);
            if (pointer->contable[i].head == NULL) {
              pointer->contable[i].state = S_STATE_OPEN;
              FD_CLR(pointer->contable[i].connfd, &wset);
              buff[0] = AF_S_CAN_SEND; /* stopping transfer */
              buff[1] = k >> 8;	/* high bits of user number */
              buff[2] = k;		/* low bits of user number */
              aflog(3, "  realm[%d]: client[%d]: TO user[%d]: BUFFERING MESSAGE ENDED", j,
                  pointer->contable[i].whatcli, k);
              send_message(pointer->type, pointer->clitable[pointer->contable[i].whatcli].cliconn, buff, 5);
            }
          }
        }
    }
		/* ------------------------------------ */
		if (FD_ISSET(pointer->listenfd, &rset)) {
			len = pointer->addrlen;
			sent = accept(pointer->listenfd, pointer->cliaddr, &len);
			flags = fcntl(sent, F_GETFL, 0);
			fcntl(sent, F_SETFL, flags | O_NONBLOCK);
			aflog(3, " realm[%d]: listenfd: FD_ISSET", j);
      k = find_client(pointer, pointer->climode);
			if (pointer->clitable[k].ready == 3) {
				if (pointer->usercon == pointer->usernum) {
					close(sent);
          aflog(3, " realm[%d]: user limit EXCEEDED", j);
        }
        else if(pointer->clitable[k].usercon == pointer->clitable[k].usernum) {
          close(sent);
          aflog(3, " realm[%d]: client[%d]: usrpcli limit EXCEEDED", j, k);
        }
        else {
          for (i = 0; i < pointer->usernum; ++i) {
            if (pointer->contable[i].state == S_STATE_CLEAR) {
              aflog(2, "  realm[%d]: client[%d]: new user: CONNECTING", j, k);
              pointer->contable[i].connfd = sent;
              pointer->contable[i].state = S_STATE_OPENING;
              pointer->contable[i].whatcli = k;
              pointer->usercon++;
              pointer->clitable[k].usercon++;
              aflog(1, "  user IP:%s",sock_ntop(pointer->cliaddr, len,
                    pointer->contable[i].namebuf, pointer->contable[i].portbuf));
              memcpy(&buff[5], pointer->contable[i].namebuf, 128);
              memcpy(&buff[133], pointer->contable[i].portbuf, 7);
              n = 135;
              i = find_usernum(&(pointer->clitable[k]), i);
              buff[0] = AF_S_CONOPEN; /* opening connection */
              buff[1] = i >> 8;	/* high bits of user number */
              buff[2] = i;		/* low bits of user number */
              buff[3] = n >> 8;	/* high bits of message length */
              buff[4] = n;		/* low bits of message length */
              send_message(pointer->type, pointer->clitable[k].cliconn, buff, n+5);
              break;
            }
          }
        }
      }
      else {
        close(sent);
        aflog(3, " realm[%d]: client[%d] is NOT CONNECTED", j, k);
      }
    }
		/* ------------------------------------ */
    for (k = 0; k < pointer->clinum; ++k)
		if (pointer->clitable[k].ready != 0) /* Command file descriptor */
		if (FD_ISSET(pointer->clitable[k].cliconn.commfd, &rset)) {	
			if (pointer->clitable[k].ready == 1) {
				if (SSL_set_fd(pointer->clitable[k].cliconn.ssl, pointer->clitable[k].cliconn.commfd) != 1) {
					aflog(0, "Problem with initializing ssl... exiting");
					exit(1);
				}
				aflog(2, "  realm[%d]: new client: SSL_accept", j);
				if ((n = SSL_accept(pointer->clitable[k].cliconn.ssl)) != 1) {
						flags = SSL_get_error(pointer->clitable[k].cliconn.ssl, n);
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
					  close (pointer->clitable[k].cliconn.commfd);
					  FD_CLR(pointer->clitable[k].cliconn.commfd, &allset);
					  FD_SET(pointer->managefd, &allset);
					  SSL_clear(pointer->clitable[k].cliconn.ssl);
					  pointer->clitable[k].ready = 0;
					  manconnecting--;
            pointer->clicon--;
					  aflog(1, "  realm[%d]: new client[%d]: DENIED by SSL_accept", j, k);
				}
				else {
					  aflog(1, "  realm[%d]: new client[%d]: ACCEPTED by SSL_accept", j, k);
					  pointer->clitable[k].ready = 2;
				}
				  continue; /* in the case this is not our client */
			}
			aflog(3, " realm[%d]: client[%d]: commfd: FD_ISSET", j, k);
			if (pointer->clitable[k].ready == 2) {
				n = get_message(pointer->type | TYPE_SSL, pointer->clitable[k].cliconn, buff, -5);
			}
			else {
				n = get_message(pointer->type, pointer->clitable[k].cliconn, buff, -5);
			}
			if (n == -1) {
				if (errno == EAGAIN) {
				  aflog(4, "     realm[%d]: client[%d]: commfd: EAGAIN", j, k);
					continue;
				}
				else {
				  aflog(4, "     realm[%d]: client[%d]: commfd: ERROR: %d", j, k, errno);
					n = 0;
				}
			}
			else if (n != 5) {
				n = 0;
			}
			if (n==0) { 
        remove_client(pointer, k, &allset, &wset, &manconnecting);
				aflog(1, "  realm[%d]: client[%d]: commfd: CLOSED", j, k);
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
              n = numofcon;
              numofcon = eval_numofcon(pointer, k, numofcon);
              if ((numofcon>=0) && (numofcon<(pointer->usernum)) && ((pointer->clitable[k].ready)==3)) {
                pointer->usercon--;
                pointer->clitable[k].usercon--;
                pointer->clitable[k].users[n] = -1;
                if (pointer->contable[numofcon].state == S_STATE_CLOSING) {
                  pointer->contable[numofcon].state = S_STATE_CLEAR; 
                }
                else if ((pointer->contable[numofcon].state == S_STATE_OPEN) ||
    						      (pointer->contable[numofcon].state == S_STATE_STOPPED)) {
                  aflog(1, "  realm[%d]: user[%d]: KICKED", j, numofcon);
                  aflog(2, "   IP:%s PORT:%s", pointer->contable[numofcon].namebuf,
    							pointer->contable[numofcon].portbuf);
                  close(pointer->contable[numofcon].connfd);
                  FD_CLR(pointer->contable[numofcon].connfd, &allset);
                  FD_CLR(pointer->contable[numofcon].connfd, &wset);
                  pointer->contable[numofcon].state = S_STATE_CLEAR;
                  freebuflist(&pointer->contable[numofcon].head);
                  buff[0] = AF_S_CONCLOSED; /* closing connection */
                  buff[1] = numofcon >> 8;	/* high bits of user number */
                  buff[2] = numofcon;		/* low bits of user number */
                  send_message(pointer->type, pointer->clitable[k].cliconn, buff, 5);
                }
              }
              else {
                remove_client(pointer, k, &allset, &wset, &manconnecting);
              }
              break;
                              }
				case AF_S_CONOPEN : {
              numofcon = eval_numofcon(pointer, k, numofcon);
              if ((numofcon>=0) && (numofcon<(pointer->usernum)) && ((pointer->clitable[k].ready)==3)) {
                if (pointer->contable[numofcon].state == S_STATE_OPENING) {
                  aflog(2, "  realm[%d]: user[%d]: NEW", j, numofcon);
                  FD_SET(pointer->contable[numofcon].connfd, &allset);
                  maxfdp1 = (maxfdp1 > (pointer->contable[numofcon].connfd+1)) ?
                    maxfdp1 : (pointer->contable[numofcon].connfd+1);
                  pointer->contable[numofcon].state = S_STATE_OPEN;
                }
              }
              else {
                remove_client(pointer, k, &allset, &wset, &manconnecting);
              }
              break;
                            }
				case AF_S_CANT_OPEN : {
              n = numofcon;
              numofcon = eval_numofcon(pointer, k, numofcon);
              if ((numofcon>=0) && (numofcon<(pointer->usernum)) && ((pointer->clitable[k].ready)==3)) {
                if (pointer->contable[numofcon].state == S_STATE_OPENING) {
                  aflog(2, "  realm[%d]: user[%d]: DROPPED", j, numofcon);
                  pointer->usercon--;
                  pointer->clitable[k].usercon--;
                  pointer->clitable[k].users[n] = -1;
                  close(pointer->contable[numofcon].connfd);
                  pointer->contable[numofcon].state = S_STATE_CLEAR;
                }
              }
              else {
                remove_client(pointer, k, &allset, &wset, &manconnecting);
              }
              break;
                              }						    
				case AF_S_MESSAGE : {
              if ((pointer->clitable[k].ready) != 3) {
                remove_client(pointer, k, &allset, &wset, &manconnecting);
							  break;
              }
              if (TYPE_IS_UDP(pointer->type)) { /* udp */
                n = get_message(pointer->type, pointer->clitable[k].cliconn, &buff[5], length);
              }
              else {
                n = get_message(pointer->type, pointer->clitable[k].cliconn, buff, length);
              }
              numofcon = eval_numofcon(pointer, k, numofcon);
              if ((numofcon>=0) && (numofcon<(pointer->usernum))) {
                if (pointer->contable[numofcon].state == S_STATE_OPEN) {
                  aflog(2, "  realm[%d]: TO user[%d]: MESSAGE length=%d", j, numofcon, n);
                  if (TYPE_IS_UDP(pointer->type)) { /* udp */
                    buff[1] = AF_S_LOGIN;
                    buff[2] = AF_S_MESSAGE;
                    buff[3] = n >> 8; /* high bits of message length */
                    buff[4] = n;      /* low bits of message length */
                    sent = write(pointer->contable[numofcon].connfd, buff, n+5);
                    if ((sent > 0) && (sent != n)) {
                      insertblnode(&(pointer->contable[numofcon].head), sent, n, buff);
                      pointer->contable[numofcon].state = S_STATE_STOPPED;
                      FD_SET(pointer->contable[numofcon].connfd, &wset);
                      buff[0] = AF_S_DONT_SEND; /* stopping transfer */
                      buff[1] = numofcon >> 8;	/* high bits of user number */
                      buff[2] = numofcon;		/* low bits of user number */
                      aflog(3, "  realm[%d]: TO user[%d]: BUFFERING MESSAGE STARTED (%d/%d)", j, numofcon,
                          sent, n);
                      send_message(pointer->type, pointer->clitable[k].cliconn, buff, 5);
                    }
                    else if ((sent == -1) && (errno == EAGAIN)) {
                      insertblnode(&(pointer->contable[numofcon].head), 0, n, buff);
                      pointer->contable[numofcon].state = S_STATE_STOPPED;
                      FD_SET(pointer->contable[numofcon].connfd, &wset);
                      buff[0] = AF_S_DONT_SEND; /* stopping transfer */
                      buff[1] = numofcon >> 8;	/* high bits of user number */
                      buff[2] = numofcon;		/* low bits of user number */
                      aflog(3, "  realm[%d]: TO user[%d]: BUFFERING MESSAGE STARTED (%d/%d)", j, numofcon,
                          sent, n);
                      send_message(pointer->type, pointer->clitable[k].cliconn, buff, 5);
                    }
                    else if (sent == -1) {
                      aflog(1, "  realm[%d]: user[%d]: CLOSED (write-udp)", j, numofcon);
                      aflog(2, "   IP:%s PORT:%s", pointer->contable[numofcon].namebuf,
                          pointer->contable[numofcon].portbuf);
                      close(pointer->contable[numofcon].connfd);
                      FD_CLR(pointer->contable[numofcon].connfd, &allset);
                      FD_CLR(pointer->contable[numofcon].connfd, &wset);
                      pointer->contable[numofcon].state = S_STATE_CLOSING;
                      freebuflist(&pointer->contable[numofcon].head);
                      buff[0] = AF_S_CONCLOSED; /* closing connection */
                      buff[1] = numofcon >> 8;	/* high bits of user number */
                      buff[2] = numofcon;		/* low bits of user number */
                      send_message(pointer->type, pointer->clitable[k].cliconn, buff, 5);
                    }
                  }
                  else { /* tcp */
                    sent = write(pointer->contable[numofcon].connfd, buff, n);
                    if ((sent > 0) && (sent != n)) {
                      insertblnode(&(pointer->contable[numofcon].head), sent, n, buff);
                      pointer->contable[numofcon].state = S_STATE_STOPPED;
                      FD_SET(pointer->contable[numofcon].connfd, &wset);
                      buff[0] = AF_S_DONT_SEND; /* stopping transfer */
                      buff[1] = numofcon >> 8;	/* high bits of user number */
                      buff[2] = numofcon;		/* low bits of user number */
                      aflog(3, "  realm[%d]: TO user[%d]: BUFFERING MESSAGE STARTED (%d/%d)", j, numofcon,
                          sent, n);
                      send_message(pointer->type, pointer->clitable[k].cliconn, buff, 5);
                    }
                    else if ((sent == -1) && (errno == EAGAIN)) {
                      insertblnode(&(pointer->contable[numofcon].head), 0, n, buff);
                      pointer->contable[numofcon].state = S_STATE_STOPPED;
                      FD_SET(pointer->contable[numofcon].connfd, &wset);
                      buff[0] = AF_S_DONT_SEND; /* stopping transfer */
                      buff[1] = numofcon >> 8;	/* high bits of user number */
                      buff[2] = numofcon;		/* low bits of user number */
                      aflog(3, "  realm[%d]: TO user[%d]: BUFFERING MESSAGE STARTED (%d/%d)", j, numofcon,
                          sent, n);
                      send_message(pointer->type, pointer->clitable[k].cliconn, buff, 5);
                    }
                    else if (sent == -1) {
                      aflog(1, "  realm[%d]: user[%d]: CLOSED (write-tcp)", j, numofcon);
                      aflog(2, "   IP:%s PORT:%s", pointer->contable[numofcon].namebuf,
                          pointer->contable[numofcon].portbuf);
                      close(pointer->contable[numofcon].connfd);
                      FD_CLR(pointer->contable[numofcon].connfd, &allset);
                      FD_CLR(pointer->contable[numofcon].connfd, &wset);
                      pointer->contable[numofcon].state = S_STATE_CLOSING;
                      freebuflist(&pointer->contable[numofcon].head);
                      buff[0] = AF_S_CONCLOSED; /* closing connection */
                      buff[1] = numofcon >> 8;	/* high bits of user number */
                      buff[2] = numofcon;		/* low bits of user number */
                      send_message(pointer->type, pointer->clitable[k].cliconn, buff, 5);
                    }
                  }
                }
                else if (pointer->contable[numofcon].state == S_STATE_STOPPED) {
                  aflog(3, "  realm[%d]: TO user[%d]: BUFFERING MESSAGE (%d)", j, numofcon, n);
                  if (TYPE_IS_UDP(pointer->type)) { /* udp */
                    buff[1] = AF_S_LOGIN;
                    buff[2] = AF_S_MESSAGE;
                    buff[3] = n >> 8; /* high bits of message length */
                    buff[4] = n;      /* low bits of message length */
                    insertblnode(&(pointer->contable[numofcon].head), 0, n+5, buff);
                  }
                  else {
                    insertblnode(&(pointer->contable[numofcon].head), 0, n, buff);
                  }
                }
              }
              break;
                            }
				case AF_S_LOGIN : {
              if ((pointer->clitable[k].ready == 2) && (numofcon==(pointer->pass[0]*256+pointer->pass[1])) &&
                  (length==(pointer->pass[2]*256+pointer->pass[3]))) {
                pointer->clitable[k].ready = 3;
                aflog(1, "  realm[%d]: pass ok - ACCESS GRANTED", j);
                buff[0] = AF_S_LOGIN; /* sending message */
                buff[1] = pointer->clitable[k].usernum >> 8;/* high bits of user number */
                buff[2] = pointer->clitable[k].usernum;     /* low bits of user number */
                buff[3] = pointer->type;	/* type of connection */
                send_message(pointer->type | TYPE_SSL, pointer->clitable[k].cliconn, buff, 5);
                manconnecting--;
              }
              else {
                aflog(1, "  realm[%d]: Wrong password - CLOSING", j);
                remove_client(pointer, k, &allset, &wset, &manconnecting);
              }
              break;
                          }
        case AF_S_DONT_SEND: {
              FD_CLR(pointer->contable[numofcon].connfd, &allset);
              break;
                             }
        case AF_S_CAN_SEND: {
              FD_SET(pointer->contable[numofcon].connfd, &allset);
              break;
                            }
				default : {
              aflog(1, "  realm[%d]: Unrecognized message - CLOSING", j);
              remove_client(pointer, k, &allset, &wset, &manconnecting);
                  }
      }
    }
    if (FD_ISSET(pointer->managefd, &rset)) {
      aflog(3, " realm[%d]: managefd: FD_ISSET", j);
      len = pointer->addrlen;
      for (k = 0; k < pointer->clinum; ++k)
        if (!(pointer->clitable[k].ready)) {
          aflog(2, "  realm[%d]: new client[%d]: CONNECTING", j, k);
          pointer->clitable[k].cliconn.commfd = accept(pointer->managefd, pointer->cliaddr, &len);
          flags = fcntl(pointer->clitable[k].cliconn.commfd, F_GETFL, 0);
          fcntl(pointer->clitable[k].cliconn.commfd, F_SETFL, flags | O_NONBLOCK);
          aflog(1, "  realm[%d]: Client[%d] IP:%s", j, k, sock_ntop(pointer->cliaddr, len, NULL, NULL));
          FD_SET(pointer->clitable[k].cliconn.commfd, &allset);
          maxfdp1 = (maxfdp1 > (pointer->clitable[k].cliconn.commfd+1)) ?
            maxfdp1 : (pointer->clitable[k].cliconn.commfd+1);
          pointer->clicon++;
          if (pointer->clicon == pointer->clinum)
            FD_CLR(pointer->managefd, &allset);
          pointer->clitable[k].tv.tv_sec = pointer->tmout;
          manconnecting++;
          pointer->clitable[k].ready = 1;
          break;
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
   printf("  -n, --hostname      - it's used when creating listening sockets\n");
   printf("                        (default: name returned by hostname function)\n");
   printf("  -l, --listenport    - listening port number - users connect\n");
   printf("                        to it (default: 50127)\n");
   printf("  -m, --manageport    - manage port number - second part of the active\n");
   printf("                        port forwarder connects to it (default: 50126)\n");
   printf("  -t, --timeout       - the timeout value for the client's connection\n");
   printf("                        (default: 5)\n");
   printf("  -u, --users         - the amount of users allowed to use this server\n");
   printf("                        (default: 5)\n");
   printf("  -C, --clients       - the number of allowed clients to use this server\n");
   printf("                        (default: 1)\n");
   printf("  -U, --usrpcli       - the number of allowed users per client (default: $users)\n");
   printf("  -M, --climode       - strategy used for connecting users with clients (default: 1)\n");
   printf("                      Available strategies:\n");
   printf("                        1. fill first client before go to next\n\n");
   printf("  -c, --cerfile       - the name of the file with certificate\n");
   printf("                        (default: cacert.pem)\n");
   printf("  -k, --keyfile       - the name of the file with RSA key (default: server.rsa)\n");
   printf("  -f, --cfgfile       - the name of the file with the configuration for the\n");
   printf("                        active forwarder (server)\n");
   printf("  -p, --proto         - type of server (tcp|udp) - for which protocol it will be\n");
   printf("                        operating (default: tcp)\n");
   printf("  -O, --heavylog      - logging everything to a logfile\n");
   printf("  -o, --lightlog      - logging some data to a logfile\n");
   printf("  -v, --verbose       - to be verbose - program won't enter the daemon mode\n");
   printf("                        (use several times for greater effect)\n\n");
   printf("  --nossl             - ssl is not used for transfering data (but it's still\n");
   printf("                        used to establish a connection) (default: ssl is used)\n");
   printf("  --nozlib            - zlib is not used for compressing data (default:\n");
   printf("                        zlib is used)\n");
   printf("  --pass              - set the password used for client identification\n");
   printf("                        (default: no password)\n\n");
   printf("  -4, --ipv4          - use ipv4 only\n");
   printf("  -6, --ipv6          - use ipv6 only\n\n");
   printf("  -h, --help          - prints this help\n\n");
   exit(0);
}

static void
sig_int(int signo)
{
	int i, j;
	unsigned char buff[5];
	for (j = 0; j < config.size; ++j) {
		buff[0] = AF_S_CLOSING; /* closing */
    for (i = 0; i < config.realmtable[j].clinum; ++i) {
      if (config.realmtable[j].clitable[i].ready == 3) {
        send_message(config.realmtable[j].type, config.realmtable[j].clitable[i].cliconn, buff, 5);
      }
    }
	}
        aflog(1, "SERVER CLOSED cg: %ld bytes", getcg());
        exit(0);
}

static void
remove_client(RealmT* ptr, int client, fd_set* set, fd_set* wset, int* con)
{
  int i;
  if (ptr->clitable[client].ready == 3) {
    for (i = 0; i < ptr->usernum; ++i) {
      if (ptr->contable[i].whatcli == client) {
        if (ptr->contable[i].state != S_STATE_CLEAR) {
          ptr->contable[i].state = S_STATE_CLEAR;
          FD_CLR(ptr->contable[i].connfd, set);
          FD_CLR(ptr->contable[i].connfd, wset);
          close(ptr->contable[i].connfd);
          ptr->usercon--;
        }
      }
    }
  }
  ptr->clitable[client].usercon = 0;
  close(ptr->clitable[client].cliconn.commfd);
	FD_CLR(ptr->clitable[client].cliconn.commfd, set);
	FD_SET(ptr->managefd, set);
	if (ptr->clitable[client].ready == 2)
    (*con)--;
	SSL_clear(ptr->clitable[client].cliconn.ssl);
	ptr->clitable[client].ready = 0;
  ptr->clicon--;
}

static int
find_client(RealmT* ptr, char mode)
{
  int i;
  switch(mode) {
    case 1: { /* fill first client before go to next */
              for (i = 0; i < ptr->clinum; ++i) {
                if (ptr->clitable[i].ready == 3) {
                  if (ptr->clitable[i].usercon < ptr->clitable[i].usernum) {
                    return i;
                  }
                }
              }
              break;
            }
    default: {
               return 0;
             }
  }
  return 0;
}

static int
eval_numofcon(RealmT* ptr, int client, int numofcon)
{
  if ((numofcon >= 0) && (numofcon < ptr->clitable[client].usernum)) {
    numofcon = ptr->clitable[client].users[numofcon];
  }
  else {
    numofcon = -1;
  }
  return numofcon;
}

static int
eval_usernum(ConnectclientT* ptr, int usernum)
{
  int i;
  for (i = 0; i < ptr->usernum; ++i) {
    if (ptr->users[i] == usernum)
      return i;
  }
  return -1;
}

static int
find_usernum(ConnectclientT* ptr, int usernum)
{
  int i;
  for (i = 0; i < ptr->usernum; ++i) {
    if (ptr->users[i] == -1) {
      ptr->users[i] = usernum;
      return i;
    }
  }
  return -1;
}

static void
check_value(int* where, char* what, char* info)
{
  char* znak;
  if ((( (*where) = strtol(what, &znak, 10)) == LONG_MAX) || ((*where) == LONG_MIN)) {
    printf("%s: %s\n", info, what);
    exit(1);
  }
  if (((*what) == '\0') || (*znak != '\0')) {
    printf("%s: %s\n", info, what);
    exit(1);
  }
  if ((*where) <= 0) {
    printf("%s: %d\n", info, *where);
    exit(1);
  }
}
