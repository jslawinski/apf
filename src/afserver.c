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

#include "afserver.h"

static struct option long_options[] = {
	{"help", 0, 0, 'h'},
	{"hostname", 1, 0, 'n'},
	{"listenport", 1, 0, 'l'},
	{"manageport", 1, 0, 'm'},
	{"timeout", 1, 0, 't'},
	{"verbose", 0, 0, 'v'},
	{"users", 1, 0, 'u'},
	{"clients", 1, 0, 'C'},
	{"realm", 1, 0, 'r'},
	{"raclients", 1, 0, 'R'},
	{"usrpcli", 1, 0, 'U'},
	{"climode", 1, 0, 'M'},
	{"cerfile", 1, 0, 'c'},
	{"keyfile", 1, 0, 'k'},
	{"cfgfile", 1, 0, 'f'},
	{"proto", 1, 0, 'p'},
	{"lightlog", 1, 0, 'o'},
	{"heavylog", 1, 0, 'O'},
  {"heavysocklog", 1, 0, 'S'},
  {"lightsocklog", 1, 0, 's'},
	{"nossl", 0, 0, 301},
	{"nozlib", 0, 0, 302},
	{"pass", 1, 0, 303},
#ifdef AF_INET6
	{"ipv4", 0, 0, '4'},
	{"ipv6", 0, 0, '6'},
#endif
	{"baseport", 0, 0, 'b'},
	{"dnslookups", 0, 0, 311},
	{"dateformat", 1, 0, 'D'},
	{0, 0, 0, 0}
};

static ConfigurationT config;

int
main(int argc, char **argv)
{
	int	i, j=0, k, l, n, flags, sent = 0;
	socklen_t	len;
	unsigned char				buff[9000];
	int			maxfdp1;
	fd_set		rset, allset, wset, tmpset;
	int manconnecting, numofcon, length;
	char* name    = NULL;
	char** listen  = NULL;
  int listencount = 0;
	char** manage  = NULL;
  int managecount = 0;
	char* amount  = NULL;
	char* clients = NULL;
	char* raclients = NULL;
	char* usrpcli = NULL;
  char* clim    = NULL;
	char* filenam = NULL;
	char* type    = NULL;
	char* timeout = NULL;
  char* realmname = NULL;
	unsigned char pass[4] = {1, 2, 3, 4};
	char verbose = 0;
	char mode = 0;
	char ipfam = 0;
  char baseport = 0;
  char dnslookups = 0;
	RealmT* pointer = NULL;
	struct sigaction act;

  char* certif = NULL;
  char* keys = NULL;
  char* logfnam = NULL;
  char* logsport = NULL;
  char* dateformat = NULL;
  char logging = 0;
  char socklogging = 0;

	SSL_METHOD* method;
	SSL_CTX* ctx;
  SSL* tmp_ssl;
	
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
  config.socklogging = 0;
	config.logfnam = NULL;
  config.logsport = NULL;
  config.dateformat = NULL;

#ifdef AF_INET6
	while ((n = getopt_long(argc, argv, "hn:l:m:vu:c:k:f:p:o:O:46t:C:U:M:bD:S:s:R:r:", long_options, 0)) != -1) {
#else
	while ((n = getopt_long(argc, argv, "hn:l:m:vu:c:k:f:p:o:O:t:C:U:M:bD:S:s:R:r:", long_options, 0)) != -1) {
#endif
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
            ++listencount;
            listen = realloc(listen, sizeof(char*));
				    listen[listencount-1] = optarg;
				    break;
			    }
		  case 'm': {
            ++managecount;
            manage = realloc(manage, sizeof(char*));
				    manage[managecount-1] = optarg;
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
      case 'r': {
            realmname = optarg;
            break;
          }
		  case 'R': {
				    raclients = optarg;
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
				    certif = optarg;
				    break;
			    }
		  case 'k': {
				    keys = optarg;
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
				    logfnam = optarg;
				    logging = 3;
				    break;
			    }
		  case 'o': {
				    logfnam = optarg;
				    logging = 1;
				    break;
			    }
      case 'S': {
        logsport = optarg;
        socklogging = 3;
        break;
      }
      case 's': {
        logsport = optarg;
        socklogging = 1;
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
            sent = 1;
            break;
          }
#ifdef AF_INET6
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
#endif
      case 'b': {
            baseport = 1;
            break;
          }
      case 311: {
            dnslookups = 1;
            break;
          }
		  case 'D': {
				    dateformat = optarg;
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
      if (certif == NULL) {
        config.certif = "cacert.pem";
      }
      else {
        config.certif = certif;
      }
      if (keys == NULL) {
        config.keys = "server.rsa";
      }
      else {
        config.keys = keys;
      }
      if (logfnam != NULL) {
        config.logfnam = logfnam;
      }
      if (logsport != NULL) {
        config.logsport = logsport;
      }
      if (dateformat != NULL) {
        config.dateformat = dateformat;
      }
      if (logging != 0) {
        config.logging = logging;
      }
      if (socklogging != 0) {
        config.socklogging = socklogging;
      }
      
      if ((k = loginit(verbose, config.logging, config.socklogging,
              config.logfnam, config.logsport, config.dateformat))) {
        switch (k) {
          case 1:
            printf("Can't open file to log to... exiting\n");
            break;
          case 2:
            printf("Can't connect to localhost:%s... exiting\n", logsport);
            break;
          case 3:
            printf("Can't open socket to log to... exiting\n");
            break;
        }
        exit(1);
      }
      
      aflog(1, "cfg file OK! (readed realms: %d)", config.size);
      if (name != NULL)
        aflog(1, "Warning: hostname=%s will be ignored", name);
      if (listen != NULL)
        aflog(1, "Warning: listenport will be ignored");
      if (manage != NULL)
        aflog(1, "Warning: manageport will be ignored");
      if (realmname != NULL)
        aflog(1, "Warning: realmname=%s will be ignored", realmname);
      if (sent == 1)
        aflog(1, "Warning: password from command line will be ignored");
		}
	}
	else {
    config.certif = certif;
    config.keys = keys;
    config.logfnam = logfnam;
    config.logsport = logsport;
    config.dateformat = dateformat;
    config.logging = logging;
    config.socklogging = socklogging;
    
    if ((k = loginit(verbose, config.logging, config.socklogging,
            config.logfnam, config.logsport, config.dateformat))) {
      switch (k) {
        case 1:
          printf("Can't open file to log to... exiting\n");
          break;
        case 2:
          printf("Can't connect to localhost:%s... exiting\n", logsport);
          break;
        case 3:
          printf("Can't open socket to log to... exiting\n");
          break;
      }
      exit(1);
    }

		if (listen == NULL) {
      listencount = 1;
      listen = calloc(1, sizeof(char*));
			listen[0] = "50127";
		}
		if (manage == NULL) {
      managecount = 1;
      manage = calloc(1, sizeof(char*));
			manage[0] = "50126";
		}
    if (managecount != listencount) {
      aflog(0, "Number of listen and manage options are not the same... exiting");
      exit(1);
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
    config.realmtable[0].usrclinum = managecount;
    config.realmtable[0].usrclitable = calloc(managecount, sizeof(UsrCliT));
    for (i = 0; i < config.realmtable[0].usrclinum; ++i) {
      config.realmtable[0].usrclitable[i].lisportnum = listen[i];
      config.realmtable[0].usrclitable[i].manportnum = manage[i];
    }
		config.realmtable[0].users = amount;
		config.realmtable[0].clients = clients;
		config.realmtable[0].raclients = raclients;
		config.realmtable[0].timeout = timeout;
		config.realmtable[0].usrpcli = usrpcli;
		config.realmtable[0].clim = clim;
		config.realmtable[0].baseport = baseport;
		config.realmtable[0].dnslookups = dnslookups;
    config.realmtable[0].realmname = realmname;
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
#ifdef AF_INET6
		if (ipfam == -1) {
			aflog(0, "Conflicting types of ip protocol family... exiting");
			exit(1);
		}
		else if (ipfam == 4) {
			TYPE_SET_IPV4(config.realmtable[0].type);
		}
		else if (ipfam == 6) {
			TYPE_SET_IPV6(config.realmtable[0].type);
		}
#endif
		config.realmtable[0].type |= mode;
	}
  
	maxfdp1 = manconnecting = 0;
	
	SSL_library_init();
	method = SSLv3_server_method();
	ctx = SSL_CTX_new(method);
	if (SSL_CTX_set_cipher_list(ctx, "ALL:@STRENGTH") == 0) {
		aflog(0, "Setting ciphers list failed... exiting");
		exit(1);
	}
  if ((flags = create_apf_dir())) {
    aflog(1, "Warning: Creating ~/.apf directory failed (%d)", flags);
  }
  if ((flags = generate_rsa_key(&config.keys))) {
    aflog(1, "Warning: Something bad happened when generating rsa keys... (%d)", flags);
  }
	if (SSL_CTX_use_RSAPrivateKey_file(ctx, config.keys, SSL_FILETYPE_PEM) != 1) {
    aflog(0, "Setting rsa key failed (%s)... exiting", config.keys);
    exit(1);
  }
  if ((flags = generate_certificate(&config.certif, config.keys))) {
    aflog(1, "Warning: Something bad happened when generating certificate... (%d)", flags);
  }
	if (SSL_CTX_use_certificate_file(ctx, config.certif, SSL_FILETYPE_PEM) != 1) {
		aflog(0, "Setting certificate failed (%s)... exiting", config.certif);
		exit(1);
	}

	if (config.size == 0) {
		aflog(0, "Working without sense is really without sense...");
		exit(1);
	}
	
	FD_ZERO(&allset);
	FD_ZERO(&wset);
	
	for (i = 0; i < config.size; ++i) {
    if (config.realmtable[i].usrclinum == 0) {
      aflog(0, "You have to specify at least one listen port and one manage port in each realm");
      exit(1);
    }
    for (j = 0; j < config.realmtable[i].usrclinum; ++j) {
  		if ((config.realmtable[i].usrclitable[j].lisportnum == NULL) ||
  			(config.realmtable[i].usrclitable[j].manportnum == NULL)) {
  			aflog(0, "Missing some of the variables...\nRealm: %d\nlistenport[%d]: %s\nmanageport[%d]: %s",
  					i, j, config.realmtable[i].usrclitable[j].lisportnum,
  					j, config.realmtable[i].usrclitable[j].manportnum);
  			exit(1);
  		}
    }
    /* checking type of the realm */
    if (!TYPE_IS_SET(config.realmtable[i].type)) {
      if (type != NULL) {
        if (strcmp(type, "tcp") == 0) {
          TYPE_SET_TCP(config.realmtable[i].type);
        }
        else if (strcmp(type, "udp") == 0) {
          TYPE_SET_UDP(config.realmtable[i].type);
        }
        else {
          TYPE_SET_TCP(config.realmtable[i].type);
        }
      }
      else {
        TYPE_SET_TCP(config.realmtable[i].type);
      }
    }
#ifdef AF_INET6
    /* using user's value for ipfam*/
    if (TYPE_IS_UNSPEC(config.realmtable[i].type)) {
      if (ipfam == -1) {
        aflog(0, "Conflicting types of ip protocol family... exiting");
        exit(1);
      }
      else if (ipfam == 4) {
        TYPE_SET_IPV4(config.realmtable[i].type);
      }
      else if (ipfam == 6) {
        TYPE_SET_IPV6(config.realmtable[i].type);
      }
    }
#endif
    /* using user's values for zlib and ssl mode*/
    if (!TYPE_IS_SSL(mode)) {
      TYPE_UNSET_SSL(config.realmtable[i].type);
    }
    if (!TYPE_IS_ZLIB(mode)) {
      TYPE_UNSET_ZLIB(config.realmtable[i].type);
    }
    /* using user's baseport value*/
    if (config.realmtable[i].baseport == 0) {
      config.realmtable[i].baseport = baseport;
    }
    /* using user's dnslookups value*/
    if (config.realmtable[i].dnslookups == 0) {
      config.realmtable[i].dnslookups = dnslookups;
    }
    /* checking users amount */
    set_value(&(config.realmtable[i].users), amount, "5");
    check_value(&(config.realmtable[i].usernum), config.realmtable[i].users, "Invalid users amount");
    /* checking clients amount */
    set_value(&(config.realmtable[i].clients), clients, "1");
    check_value(&(config.realmtable[i].clinum), config.realmtable[i].clients, "Invalid clients amount");
    /* checking raclients amount */
    set_value(&(config.realmtable[i].raclients), raclients, "1");
    check_value(&(config.realmtable[i].raclinum), config.realmtable[i].raclients, "Invalid raclients amount");
    /* checking usrpcli value */
    set_value(&(config.realmtable[i].usrpcli), usrpcli, config.realmtable[i].users);
    check_value(&(config.realmtable[i].upcnum), config.realmtable[i].usrpcli, "Invalid usrpcli value");
    /* checking timeout value */
    set_value(&(config.realmtable[i].timeout), timeout, "5");
    check_value(&(config.realmtable[i].tmout), config.realmtable[i].timeout, "Invalid timeout value");
    /* checking climode value */
    set_value(&(config.realmtable[i].clim), clim, "1");
    check_value(&(config.realmtable[i].climode), config.realmtable[i].clim, "Invalid climode value");
    /* allocating memory*/
		config.realmtable[i].contable = calloc( config.realmtable[i].usernum, sizeof(ConnectuserT));
		if (config.realmtable[i].contable == NULL) {
			aflog(0, "Calloc error - try define smaller amount of users");
			exit(1);
		}
		config.realmtable[i].clitable = calloc( config.realmtable[i].clinum, sizeof(ConnectclientT));
		if (config.realmtable[i].clitable == NULL) {
			aflog(0, "Calloc error - try define smaller amount of clients");
			exit(1);
		}
		config.realmtable[i].raclitable = calloc( config.realmtable[i].raclinum, sizeof(ConnectclientT));
		if (config.realmtable[i].raclitable == NULL) {
			aflog(0, "Calloc error - try define smaller amount of raclients");
			exit(1);
		}
		ipfam = 0x01;
#ifdef AF_INET6
		if (TYPE_IS_IPV4(config.realmtable[i].type)) {
			ipfam |= 0x02;
		}
		else if (TYPE_IS_IPV6(config.realmtable[i].type)) {
			ipfam |= 0x04;
		}
#endif
    if (config.realmtable[i].baseport == 0) {
      for (j = 0; j < config.realmtable[i].usrclinum; ++j) {
    		if (ip_listen(&(config.realmtable[i].usrclitable[j].listenfd), config.realmtable[i].hostname,
    			config.realmtable[i].usrclitable[j].lisportnum, (&(config.realmtable[i].addrlen)), ipfam)) {
          aflog(0,
#ifdef AF_INET6
    			       "tcp_listen_%s error for %s, %s",
    					(ipfam & 0x02)?"ipv4":(ipfam & 0x04)?"ipv6":"unspec",
#else
    			       "tcp_listen error for %s, %s",
#endif
    					config.realmtable[i].hostname, config.realmtable[i].usrclitable[j].lisportnum);
    			exit(1);
    		}
      }
    }
    for (j = 0; j < config.realmtable[i].usrclinum; ++j) {
  		if (ip_listen(&(config.realmtable[i].usrclitable[j].managefd), config.realmtable[i].hostname,
  			config.realmtable[i].usrclitable[j].manportnum, (&(config.realmtable[i].addrlen)), ipfam)) {
          aflog(0,
#ifdef AF_INET6
    			       "tcp_listen_%s error for %s, %s",
    					(ipfam & 0x02)?"ipv4":(ipfam & 0x04)?"ipv6":"unspec",
#else
    			       "tcp_listen error for %s, %s",
#endif
  					config.realmtable[i].hostname, config.realmtable[i].usrclitable[j].manportnum);
  			exit(1);
  		}
    }
		config.realmtable[i].cliaddr = malloc(config.realmtable[i].addrlen);
		
    for (j=0; j<config.realmtable[i].clinum; ++j) {
  		config.realmtable[i].clitable[j].cliconn.ssl = SSL_new(ctx);
  		if (config.realmtable[i].clitable[j].cliconn.ssl == NULL) {
  			aflog(0, "Creating of ssl object failed... exiting");
  			exit(1);
  		}
    }
    
    for (j=0; j<config.realmtable[i].raclinum; ++j) {
  		config.realmtable[i].raclitable[j].cliconn.ssl = SSL_new(ctx);
  		if (config.realmtable[i].raclitable[j].cliconn.ssl == NULL) {
  			aflog(0, "Creating of ssl object failed... exiting");
  			exit(1);
  		}
    }
	
    for (j = 0; j < config.realmtable[i].usrclinum; ++j) {
  		FD_SET(config.realmtable[i].usrclitable[j].managefd, &allset);
  		maxfdp1 = (maxfdp1 > (config.realmtable[i].usrclitable[j].managefd+1)) ?
        maxfdp1 : (config.realmtable[i].usrclitable[j].managefd+1);
    }
    if (config.realmtable[i].baseport == 0) {
      for (j = 0; j < config.realmtable[i].usrclinum; ++j) {
  		  FD_SET(config.realmtable[i].usrclitable[j].listenfd, &allset);
  		  maxfdp1 = (maxfdp1 > (config.realmtable[i].usrclitable[j].listenfd+1)) ?
          maxfdp1 : (config.realmtable[i].usrclitable[j].listenfd+1);
      }
    }
		config.realmtable[i].usercon = 0;
		config.realmtable[i].clicon = 0;
		config.realmtable[i].raclicon = 0;
    for (j=0; j<config.realmtable[i].clinum; ++j) {
      config.realmtable[i].clitable[j].tv.tv_sec = config.realmtable[i].tmout;
      config.realmtable[i].clitable[j].usernum = config.realmtable[i].upcnum;
      config.realmtable[i].clitable[j].users = malloc( config.realmtable[i].clitable[j].usernum * sizeof(int));
      if (config.realmtable[i].clitable[j].users == NULL) {
        aflog(0, "Calloc error - try define smaller amount of usrpcli (or users)");
        exit(1);
      }
      for (k=0; k<config.realmtable[i].clitable[j].usernum; ++k) {
        config.realmtable[i].clitable[j].users[k] = -1;
      }
    }
    for (j=0; j<config.realmtable[i].raclinum; ++j) {
      config.realmtable[i].raclitable[j].tv.tv_sec = config.realmtable[i].tmout;
    }
  }

	if (!verbose)
		daemon(0, 0);

	aflog(1, "SERVER STARTED realms: %d", config.size);
  time(&config.starttime);
	
	for ( ; ; ) {
		rset = allset;
		tmpset = wset;
			aflog(3, ">select, maxfdp1: %d", maxfdp1);
		if (manconnecting) {
			/* find out, in what realm client is trying to connect */
      l = -1;
			for (k = 0; k < config.size; ++k) {
        for (j=0; j < config.realmtable[k].clinum; ++j) {
				  if ((config.realmtable[k].clitable[j].ready == 1) || (config.realmtable[k].clitable[j].ready == 2)) {
            i = k;
            k = config.size;
            l = 0;
				  	break; /* so i points to first good realm and j to good client */
				  }
        }
        if (l == -1) {
          for (j=0; j < config.realmtable[k].raclinum; ++j) {
  				  if ((config.realmtable[k].raclitable[j].ready==1) || (config.realmtable[k].raclitable[j].ready==2)) {
              i = k;
              k = config.size;
              l = 1;
  				  	break; /* so i points to first good realm and j to good client */
  				  }
          }
        }
			}
      if (!l) {
  			if (select(maxfdp1, &rset, &tmpset, NULL, (&(config.realmtable[i].clitable[j].tv))) == 0) { 
  				  close (config.realmtable[i].clitable[j].cliconn.commfd);
  				  FD_CLR(config.realmtable[i].clitable[j].cliconn.commfd, &allset);
  					SSL_clear(config.realmtable[i].clitable[j].cliconn.ssl);
  				  config.realmtable[i].clitable[j].ready = 0;
  				  manconnecting--;
            config.realmtable[i].clicon--;
  				  aflog(1, "  realm[%s]: Client[%s]: SSL_accept failed (timeout)",
                get_realmname(&config, i), get_clientname(pointer, j));
  			}
      }
      else {
  			if (select(maxfdp1, &rset, &tmpset, NULL, (&(config.realmtable[i].raclitable[j].tv))) == 0) { 
  				  close (config.realmtable[i].raclitable[j].cliconn.commfd);
  				  FD_CLR(config.realmtable[i].raclitable[j].cliconn.commfd, &allset);
  					SSL_clear(config.realmtable[i].raclitable[j].cliconn.ssl);
  				  config.realmtable[i].raclitable[j].ready = 0;
  				  manconnecting--;
            config.realmtable[i].clicon--;
  				  aflog(1, "  realm[%s]: Client[%s] (ra): SSL_accept failed (timeout)",
                get_realmname(&config, i), get_raclientname(pointer, j));
  			}
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
          aflog(3, " realm[%s]: Client[%s]: user[%d]: FD_ISSET", get_realmname(&config, j),
              get_clientname(pointer, pointer->contable[i].whatcli), get_username(pointer, k));
          if (TYPE_IS_TCP(pointer->type)) { /* forwarding tcp packets */
            n = read(pointer->contable[i].connfd, &buff[5], 8091);
            if (n == -1) {
              if (errno == EAGAIN) {
                continue;
              }
              aflog(3, "  realm[%s]: Client[%s]: user[%d]: READ ERROR (%d)", get_realmname(&config, j),
                  get_clientname(pointer, pointer->contable[i].whatcli), get_username(pointer, k), errno);
              n = 0;
            }
            if (n) {
              aflog(2, "  realm[%s]: Client[%s]: FROM user[%d]: MESSAGE length=%d", get_realmname(&config, j),
                  get_clientname(pointer, pointer->contable[i].whatcli), get_username(pointer, k), n);
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
              aflog(1, "  realm[%s]: Client[%s]: user[%d]: CLOSED", get_realmname(&config, j),
                  get_clientname(pointer, pointer->contable[i].whatcli), get_username(pointer, k));
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
                  aflog(2, "  realm[%s]: Client[%s]: FROM user[%d]: MESSAGE length=%d",
                      get_realmname(&config, j), get_clientname(pointer, pointer->contable[i].whatcli),
                      get_username(pointer, k), n);
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
              aflog(1, "  realm[%s]: Client[%s]: user[%d]: CLOSED (udp mode)", get_realmname(&config, j),
                  get_clientname(pointer, pointer->contable[i].whatcli), get_username(pointer, k));
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
            aflog(3, " realm[%s]: Client[%s]: user[%d]: FD_ISSET - WRITE", get_realmname(&config, j),
                get_clientname(pointer, pointer->contable[i].whatcli), get_username(pointer, k));
          n = pointer->contable[i].head->msglen - pointer->contable[i].head->actptr;
          sent = write(pointer->contable[i].connfd,
              &(pointer->contable[i].head->buff[pointer->contable[i].head->actptr]), n);
          if ((sent > 0) && (sent != n)) {
            pointer->contable[i].head->actptr+=sent;
            aflog(3, " realm[%s]: Client[%s]: user[%d]: (%d/%d)", get_realmname(&config, j),
                get_clientname(pointer, pointer->contable[i].whatcli), get_username(pointer, k), sent, n);
          }
          else if ((sent == -1) && (errno == EAGAIN)) {
            aflog(3, " realm[%s]: Client[%s]: user[%d]: EAGAIN", get_realmname(&config, j),
                get_clientname(pointer, pointer->contable[i].whatcli), get_username(pointer, k));
          }
          else if (sent == -1) {
            aflog(1, "  realm[%s]: Client[%s]: user[%d]: CLOSED", get_realmname(&config, j),
                get_clientname(pointer, pointer->contable[i].whatcli), get_username(pointer, k));
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
            aflog(3, " realm[%s]: Client[%s]: user[%d]: (%d/%d)", get_realmname(&config, j),
                get_clientname(pointer, pointer->contable[i].whatcli), get_username(pointer, k), sent, n);
            deleteblnode(&pointer->contable[i].head);
            if (pointer->contable[i].head == NULL) {
              pointer->contable[i].state = S_STATE_OPEN;
              FD_CLR(pointer->contable[i].connfd, &wset);
              buff[0] = AF_S_CAN_SEND; /* stopping transfer */
              buff[1] = k >> 8;	/* high bits of user number */
              buff[2] = k;		/* low bits of user number */
              aflog(3, "  realm[%s]: Client[%s]: TO user[%d]: BUFFERING MESSAGE ENDED",
                  get_realmname(&config, j), get_clientname(pointer, pointer->contable[i].whatcli),
                  get_username(pointer, k));
              send_message(pointer->type, pointer->clitable[pointer->contable[i].whatcli].cliconn, buff, 5);
            }
          }
        }
    }
		/* ------------------------------------ */
    if (pointer->baseport == 0) {
      for (l = 0; l < pointer->usrclinum; ++l) {
    		if (FD_ISSET(pointer->usrclitable[l].listenfd, &rset)) {
    			len = pointer->addrlen;
    			sent = accept(pointer->usrclitable[l].listenfd, pointer->cliaddr, &len);
    			flags = fcntl(sent, F_GETFL, 0);
    			fcntl(sent, F_SETFL, flags | O_NONBLOCK);
    			aflog(3, " realm[%s]: listenfd: FD_ISSET", get_realmname(&config, j));
          k = find_client(pointer, pointer->climode, l);
    			if (pointer->clitable[k].ready == 3) {
    				if (pointer->usercon == pointer->usernum) {
    					close(sent);
              aflog(3, " realm[%s]: user limit EXCEEDED", get_realmname(&config, j));
            }
            else if(pointer->clitable[k].usercon == pointer->clitable[k].usernum) {
              close(sent);
              aflog(3, " realm[%s]: Client[%s]: usrpcli limit EXCEEDED",
                  get_realmname(&config, j), get_clientname(pointer, k));
            }
            else {
              for (i = 0; i < pointer->usernum; ++i) {
                if (pointer->contable[i].state == S_STATE_CLEAR) {
                  pointer->contable[i].userid = pointer->usercounter;
                  ++(pointer->usercounter);
                  aflog(1, "  realm[%s]: Client[%s]: new user: CONNECTING from IP: %s",
                      get_realmname(&config, j), get_clientname(pointer, k),
                      sock_ntop(pointer->cliaddr, len, pointer->contable[i].namebuf,
                        pointer->contable[i].portbuf, pointer->dnslookups));
                  pointer->contable[i].connfd = sent;
                  pointer->contable[i].state = S_STATE_OPENING;
                  pointer->contable[i].whatcli = k;
                  time(&pointer->contable[i].connecttime);
                  pointer->usercon++;
                  pointer->clitable[k].usercon++;
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
            aflog(3, " realm[%s]: Client(%d) is NOT CONNECTED",
                get_realmname(&config, j), k);
          }
        }
      }
    }
		/* ------------------------------------ */
    if (pointer->baseport == 1)
    for (k = 0; k < pointer->clinum; ++k)
		if (pointer->clitable[k].ready == 3) /* Command file descriptor */
		if (FD_ISSET(pointer->clitable[k].listenfd, &rset)) {
			len = pointer->addrlen;
			sent = accept(pointer->clitable[k].listenfd, pointer->cliaddr, &len);
			flags = fcntl(sent, F_GETFL, 0);
			fcntl(sent, F_SETFL, flags | O_NONBLOCK);
			aflog(3, " realm[%s]: Client[%s]: listenfd: FD_ISSET",
          get_realmname(&config, j), get_clientname(pointer, k));
			if (pointer->clitable[k].ready == 3) {
				if (pointer->usercon == pointer->usernum) {
					close(sent);
          aflog(3, " realm[%s]: user limit EXCEEDED", get_realmname(&config, j));
        }
        else if(pointer->clitable[k].usercon == pointer->clitable[k].usernum) {
          close(sent);
          aflog(3, " realm[%s]: Client[%s]: usrpcli limit EXCEEDED",
              get_realmname(&config, j), get_clientname(pointer, k));
        }
        else {
          for (i = 0; i < pointer->usernum; ++i) {
            if (pointer->contable[i].state == S_STATE_CLEAR) {
              pointer->contable[i].userid = pointer->usercounter;
              ++(pointer->usercounter);
              aflog(1, "  realm[%s]: Client[%s]: new user: CONNECTING from IP: %s",
                  get_realmname(&config, j), get_clientname(pointer, k),
                  sock_ntop(pointer->cliaddr, len, pointer->contable[i].namebuf, pointer->contable[i].portbuf, pointer->dnslookups));
              pointer->contable[i].connfd = sent;
              pointer->contable[i].state = S_STATE_OPENING;
              pointer->contable[i].whatcli = k;
              time(&pointer->contable[i].connecttime);
              pointer->usercon++;
              pointer->clitable[k].usercon++;
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
    }
		/* ------------------------------------ */
    for (k = 0; k < pointer->clinum; ++k)
		if ((pointer->clitable[k].ready != 0) && (FD_ISSET(pointer->clitable[k].cliconn.commfd, &rset))) {
			if (pointer->clitable[k].ready == 1) {
        make_ssl_initialize(&(pointer->clitable[k].cliconn));
				aflog(2, "  realm[%s]: new Client[%s]: SSL_accept",
            get_realmname(&config, j), get_clientname(pointer, k));
        switch (make_ssl_accept(&(pointer->clitable[k].cliconn))) {
          case 2: {
                    close (pointer->clitable[k].cliconn.commfd);
                    FD_CLR(pointer->clitable[k].cliconn.commfd, &allset);
                    SSL_clear(pointer->clitable[k].cliconn.ssl);
                    pointer->clitable[k].ready = 0;
                    manconnecting--;
                    pointer->clicon--;
                    aflog(1, "  realm[%s]: new Client[%s]: DENIED by SSL_accept",
                        get_realmname(&config, j), get_clientname(pointer, k));
                  }
          case 1: {
                    continue;
                  }
          default: {
                     aflog(1, "  realm[%s]: new Client[%s]: ACCEPTED by SSL_accept",
                         get_realmname(&config, j), get_clientname(pointer, k));
                     pointer->clitable[k].ready = 2;
                     continue;
                   }
        }
			}
			aflog(3, " realm[%s]: Client[%s]: commfd: FD_ISSET",
          get_realmname(&config, j), get_clientname(pointer, k));
      if (pointer->clitable[k].ready == 2) {
				n = get_message(pointer->type | TYPE_SSL | TYPE_ZLIB, pointer->clitable[k].cliconn, buff, -5);
			}
			else {
				n = get_message(pointer->type, pointer->clitable[k].cliconn, buff, -5);
			}
			if (n == -1) {
				if (errno == EAGAIN) {
				  aflog(4, "     realm[%s]: Client[%s]: commfd: EAGAIN",
              get_realmname(&config, j), get_clientname(pointer, k));
					continue;
				}
				else {
				  aflog(4, "     realm[%s]: Client[%s]: commfd: ERROR: %d",
              get_realmname(&config, j), get_clientname(pointer, k), errno);
					n = 0;
				}
			}
			else if (n != 5) {
        if (n != 0) {
          aflog(4, "  realm[%s]: Client[%s]: header length = %d --> closing client",
              get_realmname(&config, j), get_clientname(pointer, k), n);
        }
				n = 0;
			}
			if (n==0) { 
        remove_client(pointer, k, &allset, &wset, &manconnecting);
				aflog(1, "  realm[%s]: Client[%s]: commfd: CLOSED",
            get_realmname(&config, j), get_clientname(pointer, k));
				continue;
			}
      
      numofcon = buff[1];
      numofcon = numofcon << 8;
      numofcon += buff[2]; /* this is id of user */
      length = buff[3];
      length = length << 8;
      length += buff[4]; /* this is length of message */ 
     
      if ((k == pointer->clinum) && (buff[0] != AF_S_LOGIN) &&
          (buff[0] != AF_S_ADMIN_LOGIN) && (buff[0] != AF_S_ADMIN_CMD)) {
        buff[0] = AF_S_WRONG;
      }
      if (pointer->clitable[k].ready<2) {
        aflog(1, "  realm[%s]: Client[%s]: Impossible behaviour --> ignoring",
            get_realmname(&config, j), get_clientname(pointer, k));
        continue;
      }
      if ((pointer->clitable[k].ready == 2) && (buff[0] != AF_S_LOGIN) && (buff[0] != AF_S_ADMIN_LOGIN)) {
        buff[0] = AF_S_WRONG;
      }
      
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
                  aflog(3, "  realm[%s]: user[%d]: CLOSE CONFIRMED",
                      get_realmname(&config, j), get_username(pointer, numofcon));
                }
                else if ((pointer->contable[numofcon].state == S_STATE_OPEN) ||
    						      (pointer->contable[numofcon].state == S_STATE_STOPPED)) {
                  aflog(1, "  realm[%s]: user[%d]: KICKED",
                      get_realmname(&config, j), get_username(pointer, numofcon));
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
                  aflog(2, "  realm[%s]: user[%d]: NEW",
                      get_realmname(&config, j), get_username(pointer, numofcon));
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
                  aflog(2, "  realm[%s]: user[%d]: DROPPED",
                      get_realmname(&config, j), get_username(pointer, numofcon));
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
                  aflog(2, "  realm[%s]: TO user[%d]: MESSAGE length=%d",
                      get_realmname(&config, j), get_username(pointer, numofcon), n);
                  if (TYPE_IS_UDP(pointer->type)) { /* udp */
                    buff[1] = AF_S_LOGIN;
                    buff[2] = AF_S_MESSAGE;
                    buff[3] = n >> 8; /* high bits of message length */
                    buff[4] = n;      /* low bits of message length */
                    sent = write(pointer->contable[numofcon].connfd, buff, n+5);
                    if (sent == -1) {
                      aflog(1, "  realm[%s]: user[%d]: CLOSED (write-udp)",
                          get_realmname(&config, j), get_username(pointer, numofcon));
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
                      aflog(3, "  realm[%s]: TO user[%d]: BUFFERING MESSAGE STARTED (%d/%d)",
                          get_realmname(&config, j), get_username(pointer, numofcon), sent, n);
                      send_message(pointer->type, pointer->clitable[k].cliconn, buff, 5);
                    }
                    else if ((sent == -1) && (errno == EAGAIN)) {
                      insertblnode(&(pointer->contable[numofcon].head), 0, n, buff);
                      pointer->contable[numofcon].state = S_STATE_STOPPED;
                      FD_SET(pointer->contable[numofcon].connfd, &wset);
                      buff[0] = AF_S_DONT_SEND; /* stopping transfer */
                      buff[1] = numofcon >> 8;	/* high bits of user number */
                      buff[2] = numofcon;		/* low bits of user number */
                      aflog(3, "  realm[%s]: TO user[%d]: BUFFERING MESSAGE STARTED (%d/%d)",
                          get_realmname(&config, j), get_username(pointer, numofcon), sent, n);
                      send_message(pointer->type, pointer->clitable[k].cliconn, buff, 5);
                    }
                    else if (sent == -1) {
                      aflog(1, "  realm[%s]: user[%d]: CLOSED (write-tcp)",
                          get_realmname(&config, j), get_username(pointer, numofcon));
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
                  aflog(3, "  realm[%s]: TO user[%d]: BUFFERING MESSAGE (%d)",
                      get_realmname(&config, j), get_username(pointer, numofcon), n);
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
                else if (pointer->contable[numofcon].state == S_STATE_CLOSING) {
                  aflog(3, "  realm[%s]: TO user[%d]: IGNORED message length=%d",
                      get_realmname(&config, j), get_username(pointer, numofcon), n);
                }
              }
              break;
                            }
				case AF_S_LOGIN : {
              if ((pointer->clitable[k].ready == 2) && (numofcon==(pointer->pass[0]*256+pointer->pass[1])) &&
                  (length==(pointer->pass[2]*256+pointer->pass[3]))) {
                if (k != pointer->clinum) {
                  pointer->clitable[k].ready = 3;
                  aflog(1, "  realm[%s]: Client[%s]: pass ok - ACCESS GRANTED",
                      get_realmname(&config, j), get_clientname(pointer, k));
                  buff[0] = AF_S_LOGIN; /* sending message */
                  buff[1] = pointer->clitable[k].usernum >> 8;/* high bits of user number */
                  buff[2] = pointer->clitable[k].usernum;     /* low bits of user number */
                  buff[3] = pointer->type;	/* type of connection */
                  send_message(pointer->type | TYPE_SSL | TYPE_ZLIB, pointer->clitable[k].cliconn, buff, 5);
                  manconnecting--;
                  if (pointer->baseport == 1) {
                    long tmp_val;
                    char tmp_tab[6];
                    if (check_long(pointer->usrclitable[pointer->clitable[k].whatusrcli].lisportnum, &tmp_val)) {
                      aflog(1, "  realm[%s]: INVALID listenport - removing Client[%s]",
                          get_realmname(&config, j), get_clientname(pointer, k));
                      remove_client(pointer, k, &allset, &wset, &manconnecting);
                      break;
                    }
                    tmp_val = tmp_val%65536;
                    memset(tmp_tab, 0, 6);
                    sprintf(tmp_tab, "%d", (int)tmp_val);
  		              ipfam = 0x01;
#ifdef AF_INET6
                    if (TYPE_IS_IPV4(pointer->type)) {
                      ipfam |= 0x02;
                    }
                    else if (TYPE_IS_IPV6(pointer->type)) {
                      ipfam |= 0x04;
                    }
#endif
    		            while (ip_listen(&(pointer->clitable[k].listenfd), pointer->hostname,
    			                 tmp_tab, (&(pointer->addrlen)), ipfam)) {
                      tmp_val = (tmp_val+1)%65536;
                      memset(tmp_tab, 0, 6);
                      sprintf(tmp_tab, "%d", (int)tmp_val);
                    }
                    FD_SET(pointer->clitable[k].listenfd, &allset);
                    maxfdp1 = (maxfdp1 > (pointer->clitable[k].listenfd+1)) ?
                      maxfdp1 : (pointer->clitable[k].listenfd+1);
                    aflog(1, "  realm[%s]: Client[%s]: listenport=%s",
                        get_realmname(&config, j), get_clientname(pointer, k), tmp_tab);
                  }
                }
                else {
                  aflog(3, " realm[%s]: client limit EXCEEDED", get_realmname(&config, j));
                  buff[0] = AF_S_CANT_OPEN; /* sending message */
                  send_message(pointer->type | TYPE_SSL, pointer->clitable[k].cliconn, buff, 5);
                  remove_client(pointer, k, &allset, &wset, &manconnecting);
                }
              }
              else if ((pointer->clitable[k].ready == 3) && (numofcon == 0)) {
                n = get_message(pointer->type, pointer->clitable[k].cliconn, buff, length);
                buff[n] = 0;
                aflog(1, "  realm[%s]: Client[%s]: ID received: %s",
                    get_realmname(&config, j), get_clientname(pointer, k), buff);
                if (pointer->clitable[k].clientid) {
                  free(pointer->clitable[k].clientid);
                }
                pointer->clitable[k].clientid = malloc(n+1);
                if (pointer->clitable[k].clientid) {
                  memcpy(pointer->clitable[k].clientid, buff, n+1);
                }
              }
              else {
                aflog(1, "  realm[%s]: Client[%s]: Wrong password - CLOSING",
                    get_realmname(&config, j), get_clientname(pointer, k));
                remove_client(pointer, k, &allset, &wset, &manconnecting);
              }
              break;
                          }
        case AF_S_DONT_SEND: {
              aflog(3, "  realm[%s]: user[%d]: STOP READING",
                  get_realmname(&config, j), get_username(pointer, numofcon));
              FD_CLR(pointer->contable[numofcon].connfd, &allset);
              break;
                             }
        case AF_S_CAN_SEND: {
              aflog(3, "  realm[%s]: user[%d]: START READING",
                  get_realmname(&config, j), get_username(pointer, numofcon));
              FD_SET(pointer->contable[numofcon].connfd, &allset);
              break;
                            }
        case AF_S_WRONG: {
              aflog(1, "  realm[%s]: Client[%s]: Wrong message - CLOSING",
                  get_realmname(&config, j), get_clientname(pointer, k));
              remove_client(pointer, k, &allset, &wset, &manconnecting);
              break;
                         }
        case AF_S_ADMIN_LOGIN: {
              if ((pointer->clitable[k].ready == 2) && (numofcon==(pointer->pass[0]*256+pointer->pass[1])) &&
                  (length==(pointer->pass[2]*256+pointer->pass[3]))) {
                aflog(1, "  realm[%s]: Client[%s]: NEW remote admin -- pass OK",
                    get_realmname(&config, j), get_clientname(pointer, k));
                for (l = 0; l < pointer->raclinum; ++l) {
                  if (pointer->raclitable[l].ready == 0) {
                    pointer->raclitable[l].cliconn.commfd = pointer->clitable[k].cliconn.commfd;
                    pointer->raclitable[l].connecttime = pointer->clitable[k].connecttime;
                    pointer->raclitable[l].clientnum = pointer->clitable[k].clientnum;
                    memcpy(pointer->raclitable[l].namebuf, pointer->clitable[k].namebuf, 128);
                    memcpy(pointer->raclitable[l].portbuf, pointer->clitable[k].portbuf, 7);
                    tmp_ssl = pointer->raclitable[l].cliconn.ssl;
                    pointer->raclitable[l].cliconn.ssl = pointer->clitable[k].cliconn.ssl;
                    pointer->clitable[k].cliconn.ssl = tmp_ssl;
                    pointer->clitable[k].ready = 0;
                    break;
                  }
                }
                if (l != pointer->raclinum) {
                  pointer->raclitable[l].ready = 3;
                  pointer->raclicon++;
                  manconnecting--;
                  sprintf((char*) &buff[5], AF_VER("AFSERVER"));
                  n = strlen((char*) &buff[5]);
                  buff[0] = AF_S_ADMIN_LOGIN; /* sending message */
                  buff[1] = pointer->type;	/* type of connection */
                  buff[2] = AF_RA_UNDEFINED;
                  buff[3] = n >> 8; /* high bits of message length */
                  buff[4] = n;      /* low bits of message length */
                  send_message(pointer->type | TYPE_SSL, pointer->raclitable[l].cliconn, buff, n+5);
                }
                else {
                  aflog(1, "  realm[%s]: Client[%s]: remote admin -- limit EXCEEDED",
                      get_realmname(&config, j), get_clientname(pointer, k));
                  buff[0] = AF_S_CANT_OPEN; /* sending message */
                  send_message(pointer->type | TYPE_SSL | TYPE_ZLIB, pointer->clitable[k].cliconn, buff, 5);
                  remove_client(pointer, k, &allset, &wset, &manconnecting);
                }
              }
              break;
                         }
				default : {
              aflog(1, "  realm[%s]: Client[%s]: Unrecognized message - CLOSING",
                  get_realmname(&config, j), get_clientname(pointer, k));
              remove_client(pointer, k, &allset, &wset, &manconnecting);
                  }
      }
    }
		/* ------------------------------------ */
    for (k = 0; k < pointer->raclinum; ++k)
		if ((pointer->raclitable[k].ready != 0) && (FD_ISSET(pointer->raclitable[k].cliconn.commfd, &rset))) {
			if (pointer->raclitable[k].ready == 1) {
        make_ssl_initialize(&(pointer->raclitable[k].cliconn));
				aflog(2, "  realm[%s]: new Client[%s] (ra): SSL_accept",
            get_realmname(&config, j), get_raclientname(pointer, k));
        switch (make_ssl_accept(&(pointer->raclitable[k].cliconn))) {
          case 2: {
                    close (pointer->raclitable[k].cliconn.commfd);
                    FD_CLR(pointer->raclitable[k].cliconn.commfd, &allset);
                    SSL_clear(pointer->raclitable[k].cliconn.ssl);
                    pointer->raclitable[k].ready = 0;
                    manconnecting--;
                    pointer->clicon--;
                    aflog(1, "  realm[%s]: new Client[%s] (ra): DENIED by SSL_accept",
                        get_realmname(&config, j), get_raclientname(pointer, k));
                  }
          case 1: {
                    continue;
                  }
          default: {
                     aflog(1, "  realm[%s]: new Client[%s] (ra): ACCEPTED by SSL_accept",
                         get_realmname(&config, j), get_raclientname(pointer, k));
                     pointer->raclitable[k].ready = 2;
                     continue;
                   }
        }
			}
			aflog(3, " realm[%s]: Client[%s] (ra): commfd: FD_ISSET",
          get_realmname(&config, j), get_raclientname(pointer, k));
			n = get_message(pointer->type | TYPE_SSL | TYPE_ZLIB, pointer->raclitable[k].cliconn, buff, -5);
			if (n == -1) {
				if (errno == EAGAIN) {
				  aflog(4, "     realm[%s]: Client[%s] (ra): commfd: EAGAIN",
              get_realmname(&config, j), get_raclientname(pointer, k));
					continue;
				}
				else {
				  aflog(4, "     realm[%s]: Client[%s] (ra): commfd: ERROR: %d",
              get_realmname(&config, j), get_raclientname(pointer, k), errno);
					n = 0;
				}
			}
			else if (n != 5) {
        if (n != 0) {
          aflog(4, "  realm[%s]: Client[%s] (ra): header length = %d --> closing client",
              get_realmname(&config, j), get_raclientname(pointer, k), n);
        }
				n = 0;
			}
			if (n==0) { 
        remove_raclient(pointer, k, &allset, &wset, &manconnecting);
				aflog(1, "  realm[%s]: Client[%s] (ra): commfd: CLOSED",
            get_realmname(&config, j), get_raclientname(pointer, k));
				continue;
			}
      
      numofcon = buff[1];
      numofcon = numofcon << 8;
      numofcon += buff[2]; /* this is id of user */
      length = buff[3];
      length = length << 8;
      length += buff[4]; /* this is length of message */ 
     
      if (pointer->raclitable[k].ready<2) {
        aflog(1, "  realm[%s]: Client[%s] (ra): Impossible behaviour --> ignoring",
            get_realmname(&config, j), get_raclientname(pointer, k));
        continue;
      }
      if ((pointer->raclitable[k].ready == 2) && (buff[0] != AF_S_LOGIN) && (buff[0] != AF_S_ADMIN_LOGIN)) {
        buff[0] = AF_S_WRONG;
      }
      
			switch (buff[0]) {
				case AF_S_LOGIN : {
              if ((pointer->raclitable[k].ready == 2) && (numofcon==(pointer->pass[0]*256+pointer->pass[1])) &&
                  (length==(pointer->pass[2]*256+pointer->pass[3]))) {
                for (l = 0; l < pointer->clinum; ++l) {
                  if (!(pointer->clitable[l].ready)) {
                    aflog(1, "  realm[%s]: Client[%s] (ra) --> Client[%s]",
                        get_realmname(&config, j), get_raclientname(pointer, k), get_clientname(pointer, l));
                    pointer->clitable[l].cliconn.commfd = pointer->raclitable[k].cliconn.commfd;
                    pointer->clitable[l].connecttime = pointer->raclitable[k].connecttime;
                    pointer->clitable[l].clientnum = pointer->raclitable[k].clientnum;
                    memcpy(pointer->clitable[l].namebuf, pointer->raclitable[k].namebuf, 128);
                    memcpy(pointer->clitable[l].portbuf, pointer->raclitable[k].portbuf, 7);
                    tmp_ssl = pointer->clitable[l].cliconn.ssl;
                    pointer->clitable[l].cliconn.ssl = pointer->raclitable[k].cliconn.ssl;
                    pointer->raclitable[k].cliconn.ssl = tmp_ssl;
                    pointer->clitable[l].whatusrcli = pointer->raclitable[k].whatusrcli;
                    pointer->raclitable[k].ready = 0;
                    break;
                  }
                }
                if (l != pointer->clinum) {
                  pointer->clitable[l].ready = 3;
                  aflog(1, "  realm[%s]: Client[%s]: pass ok - ACCESS GRANTED",
                      get_realmname(&config, j), get_clientname(pointer, l));
                  buff[0] = AF_S_LOGIN; /* sending message */
                  buff[1] = pointer->clitable[l].usernum >> 8;/* high bits of user number */
                  buff[2] = pointer->clitable[l].usernum;     /* low bits of user number */
                  buff[3] = pointer->type;	/* type of connection */
                  send_message(pointer->type | TYPE_SSL | TYPE_ZLIB, pointer->clitable[l].cliconn, buff, 5);
                  manconnecting--;
                  if (pointer->baseport == 1) {
                    long tmp_val;
                    char tmp_tab[6];
                    if (check_long(pointer->usrclitable[pointer->clitable[l].whatusrcli].lisportnum, &tmp_val)) {
                      aflog(1, "  realm[%s]: INVALID listenport - removing Client[%s]",
                          get_realmname(&config, j), get_clientname(pointer, l));
                      remove_client(pointer, l, &allset, &wset, &manconnecting);
                      break;
                    }
                    tmp_val = tmp_val%65536;
                    memset(tmp_tab, 0, 6);
                    sprintf(tmp_tab, "%d", (int)tmp_val);
  		              ipfam = 0x01;
#ifdef AF_INET6
                    if (TYPE_IS_IPV4(pointer->type)) {
                      ipfam |= 0x02;
                    }
                    else if (TYPE_IS_IPV6(pointer->type)) {
                      ipfam |= 0x04;
                    }
#endif
    		            while (ip_listen(&(pointer->clitable[l].listenfd), pointer->hostname,
    			                 tmp_tab, (&(pointer->addrlen)), ipfam)) {
                      tmp_val = (tmp_val+1)%65536;
                      memset(tmp_tab, 0, 6);
                      sprintf(tmp_tab, "%d", (int)tmp_val);
                    }
                    FD_SET(pointer->clitable[l].listenfd, &allset);
                    maxfdp1 = (maxfdp1 > (pointer->clitable[l].listenfd+1)) ?
                      maxfdp1 : (pointer->clitable[l].listenfd+1);
                    aflog(1, "  realm[%s]: Client[%s]: listenport=%s",
                        get_realmname(&config, j), get_clientname(pointer, l), tmp_tab);
                  }
                }
                else {
                  aflog(3, " realm[%s]: client limit EXCEEDED", get_realmname(&config, j));
                  buff[0] = AF_S_CANT_OPEN; /* sending message */
                  send_message(pointer->type | TYPE_SSL | TYPE_ZLIB, pointer->raclitable[k].cliconn, buff, 5);
                  remove_raclient(pointer, k, &allset, &wset, &manconnecting);
                }
              }
              else if ((pointer->raclitable[k].ready == 3) && (numofcon == 0)) {
                n = get_message(pointer->type, pointer->raclitable[k].cliconn, buff, length);
                buff[n] = 0;
                aflog(1, "  realm[%s]: Client[%s] (ra): ID received: %s",
                    get_realmname(&config, j), get_raclientname(pointer, k), buff);
                if (pointer->raclitable[k].clientid) {
                  free(pointer->raclitable[k].clientid);
                }
                pointer->raclitable[k].clientid = malloc(n+1);
                if (pointer->raclitable[k].clientid) {
                  memcpy(pointer->raclitable[k].clientid, buff, n+1);
                }
              }
              else {
                aflog(1, "  realm[%s]: Client[%s] (ra): Wrong password - CLOSING",
                    get_realmname(&config, j), get_raclientname(pointer, k));
                remove_raclient(pointer, k, &allset, &wset, &manconnecting);
              }
              break;
                          }
        case AF_S_WRONG: {
              aflog(1, "  realm[%s]: Client[%s] (ra): Wrong message - CLOSING",
                  get_realmname(&config, j), get_raclientname(pointer, k));
              remove_raclient(pointer, k, &allset, &wset, &manconnecting);
              break;
                         }
        case AF_S_ADMIN_LOGIN: {
              if ((pointer->raclitable[k].ready == 2) && (numofcon==(pointer->pass[0]*256+pointer->pass[1])) &&
                  (length==(pointer->pass[2]*256+pointer->pass[3]))) {
                aflog(1, "  realm[%s]: Client[%s] (ra): NEW remote admin -- pass OK",
                    get_realmname(&config, j), get_raclientname(pointer, k));
                pointer->raclitable[k].ready = 3;
                pointer->raclicon++;
                manconnecting--;
                sprintf((char*) &buff[5], AF_VER("AFSERVER"));
                n = strlen((char*) &buff[5]);
                buff[0] = AF_S_ADMIN_LOGIN; /* sending message */
                buff[1] = pointer->type;	/* type of connection */
                buff[2] = AF_RA_UNDEFINED;
                buff[3] = n >> 8; /* high bits of message length */
                buff[4] = n;      /* low bits of message length */
                send_message(pointer->type | TYPE_SSL | TYPE_ZLIB, pointer->raclitable[k].cliconn, buff, n+5);
              }
              break;
                         }
        case AF_S_ADMIN_CMD: {
              if (pointer->raclitable[k].ready == 3) {
                if (serve_admin(&config, j, k, buff)) {
                  remove_raclient(pointer, k, &allset, &wset, &manconnecting);
                }
              }
              else {
                aflog(1, "  realm[%s]: Client[%s] (ra): remote admin -- security VIOLATION",
                    get_realmname(&config, j), get_raclientname(pointer, k));
                remove_raclient(pointer, k, &allset, &wset, &manconnecting);
              }
              break;
                             }
				default : {
              aflog(1, "  realm[%s]: Client[%s] (ra): Unrecognized message - CLOSING",
                  get_realmname(&config, j), get_raclientname(pointer, k));
              remove_raclient(pointer, k, &allset, &wset, &manconnecting);
                  }
      }
    }
		/* ------------------------------------ */    
    for (l = 0; l < pointer->usrclinum; ++l) {
      if (FD_ISSET(pointer->usrclitable[l].managefd, &rset)) {
        aflog(3, " realm[%s]: managefd: FD_ISSET", get_realmname(&config, j));
        len = pointer->addrlen;
        sent = accept(pointer->usrclitable[l].managefd,pointer->cliaddr,&len);
        flags = fcntl(sent, F_GETFL, 0);
        fcntl(sent, F_SETFL, flags | O_NONBLOCK);
        for (k = 0; k < pointer->clinum; ++k) {
          if (!(pointer->clitable[k].ready)) {
            pointer->clitable[k].clientnum = pointer->clientcounter;
            ++(pointer->clientcounter);
            aflog(2, "  realm[%s]: new Client[%s]: CONNECTING",
                get_realmname(&config, j), get_clientname(pointer, k));
            pointer->clitable[k].cliconn.commfd = sent;
            pointer->clitable[k].whatusrcli = l;
            time(&pointer->clitable[k].connecttime);
            aflog(1, "  realm[%s]: new Client[%s] IP:%s", get_realmname(&config, j), get_clientname(pointer, k),
                sock_ntop(pointer->cliaddr, len, pointer->clitable[k].namebuf,
                  pointer->clitable[k].portbuf, pointer->dnslookups));
            FD_SET(pointer->clitable[k].cliconn.commfd, &allset);
            maxfdp1 = (maxfdp1 > (pointer->clitable[k].cliconn.commfd+1)) ?
              maxfdp1 : (pointer->clitable[k].cliconn.commfd+1);
            pointer->clicon++;
            pointer->clitable[k].tv.tv_sec = pointer->tmout;
            manconnecting++;
            pointer->clitable[k].ready = 1;
            break;
          }
        }
        if (k == pointer->clinum) {
          for (k = 0; k < pointer->raclinum; ++k) {
            if ((!pointer->raclitable[k].ready)) {
              pointer->raclitable[k].clientnum = pointer->clientcounter;
              ++(pointer->clientcounter);
              aflog(2, "  realm[%s]: new Client[%s] (ra): CONNECTING",
                  get_realmname(&config, j), get_raclientname(pointer, k));
              pointer->raclitable[k].cliconn.commfd = sent;
              pointer->raclitable[k].whatusrcli = l;
              time(&pointer->raclitable[k].connecttime);
              aflog(1, "  realm[%s]: new Client[%s] (ra) IP:%s",
                  get_realmname(&config, j), get_raclientname(pointer, k),
                  sock_ntop(pointer->cliaddr, len, pointer->raclitable[k].namebuf,
                    pointer->raclitable[k].portbuf, pointer->dnslookups));
              FD_SET(pointer->raclitable[k].cliconn.commfd, &allset);
              maxfdp1 = (maxfdp1 > (pointer->raclitable[k].cliconn.commfd+1)) ?
                maxfdp1 : (pointer->raclitable[k].cliconn.commfd+1);
              pointer->clicon++;
              pointer->raclitable[k].tv.tv_sec = pointer->tmout;
              manconnecting++;
              pointer->raclitable[k].ready = 1;
              break;
            }
          }
          if (k == pointer->raclinum) {
            aflog(3, " realm[%s]: client limit EXCEEDED", get_realmname(&config, j));
            close(sent);
          }
        }
      }
    }
  } /* realms loop */
  }
}

static void
usage(char* info)
{	
   printf("\n%s\n\n\n", info);
   printf(" Basic options:\n\n");
   printf("  -n, --hostname      - it's used when creating listening sockets\n");
   printf("                        (default: '')\n");
   printf("  -l, --listenport    - listening port number - users connect\n");
   printf("                        to it (default: 50127)\n");
   printf("  -m, --manageport    - manage port number - second part of the active\n");
   printf("                        port forwarder connects to it (default: 50126)\n");
   printf("  -h, --help          - prints this help\n\n");
   printf(" Authorization:\n\n");
   printf("  --pass              - set the password used for client identification\n");
   printf("                        (default: no password)\n\n");
   printf(" Configuration:\n\n");
   printf("  -c, --cerfile       - the name of the file with certificate\n");
   printf("                        (default: cacert.pem)\n");
   printf("  -k, --keyfile       - the name of the file with RSA key (default: server.rsa)\n");
   printf("  -f, --cfgfile       - the name of the file with the configuration for the\n");
   printf("                        active forwarder (server)\n");
   printf("  -D, --dateformat    - format of the date printed in logs (see 'man strftime'\n");
   printf("                        for details) (default: %%d.%%m.%%Y %%H:%%M:%%S)\n\n");
   printf("  -t, --timeout       - the timeout value for the client's connection\n");
   printf("                        (default: 5)\n");
   printf("  -u, --users         - the amount of users allowed to use this server\n");
   printf("                        (default: 5)\n");
   printf("  -C, --clients       - the number of allowed clients to use this server\n");
   printf("                        (default: 1)\n");
   printf("  -r, --realm         - set the realm name (default: none)\n");
   printf("  -R, --raclients     - the number of allowed clients in remote administration\n");
   printf("                        mode to use this server (default: 1)\n");
   printf("  -U, --usrpcli       - the number of allowed users per client (default: $users)\n");
   printf("  -M, --climode       - strategy used to connect users with clients (default: 1)\n");
   printf("                      Available strategies:\n");
   printf("                        1. fill first client before go to next\n\n");
   printf("  -p, --proto         - type of server (tcp|udp) - what protocol it will be\n");
   printf("                        operating for (default: tcp)\n");
   printf("  -b, --baseport      - listenports are temporary and differ for each client\n");
   printf("  --nossl             - ssl is not used to transfer data (but it's still used\n");
   printf("                        to establish a connection) (default: ssl is used)\n");
   printf("  --nozlib            - zlib is not used to compress data (default: zlib is\n");
   printf("                        used)\n");
   printf("  --dnslookups        - try to obtain dns names of the computers rather than\n");
   printf("                        their numeric IP\n\n");
   printf(" Logging:\n\n");
   printf("  -O, --heavylog      - logging everything to a logfile\n");
   printf("  -o, --lightlog      - logging some data to a logfile\n");
   printf("  -S, --heavysocklog  - logging everything to a localport\n");
   printf("  -s, --lightsocklog  - logging some data to a localport\n");
   printf("  -v, --verbose       - to be verbose - program won't enter the daemon mode\n");
   printf("                        (use several times for greater effect)\n\n");
#ifdef AF_INET6
   printf(" IP family:\n\n");
   printf("  -4, --ipv4          - use ipv4 only\n");
   printf("  -6, --ipv6          - use ipv6 only\n\n");
#endif
   exit(0);
}

static void
sig_int(int signo)
{
	int i, j;
	unsigned char buff[5];
	for (j = 0; j < config.size; ++j) {
		buff[0] = AF_S_CLOSING; /* closing */
    for (i = 0; i < config.realmtable[j].clinum+1; ++i) {
      if (config.realmtable[j].clitable[i].ready == 3) {
        if (config.realmtable[j].clinum == i) {
          send_message(config.realmtable[j].type | TYPE_SSL, config.realmtable[j].clitable[i].cliconn, buff, 5);
        }
        else {
          send_message(config.realmtable[j].type, config.realmtable[j].clitable[i].cliconn, buff, 5);
        }
      }
    }
	}
        aflog(1, "SERVER CLOSED cg: %ld bytes", getcg());
        exit(0);
}

