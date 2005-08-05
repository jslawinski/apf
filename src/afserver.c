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
	{"log", 1, 0, 'o'},
	{"audit", 0, 0, 'a'},
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
#ifdef HAVE_LIBPTHREAD
	{"enableproxy", 0, 0, 'P'},
  /* FIXME: don't need it now
	{"use-https", 0, 0, 'S'},
  */
#endif
	{"version", 0, 0, 'V'},
	{0, 0, 0, 0}
};

ConfigurationT config;

int
main(int argc, char **argv)
{
	int	i, j=0, k, l, n, flags, sent = 0, temp;
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
#ifdef HAVE_LIBPTHREAD
  char tunneltype = 0;
#endif
	char ipfam = 0;
  char baseport = 0;
  char audit = 0;
  char dnslookups = 0;
	RealmT* pointer = NULL;
	struct sigaction act;
  time_t now;

  char* certif = NULL;
  char* keys = NULL;
  char* dateformat = NULL;

	SSL_METHOD* method;
	SSL_CTX* ctx;
  SSL* tmp_ssl;
	
	sigfillset(&(act.sa_mask));
	act.sa_flags = 0;
	
	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);
	act.sa_handler = server_sig_int;
	sigaction(SIGINT, &act, NULL);
	
	TYPE_SET_SSL(mode);
	TYPE_SET_ZLIB(mode);

  memset(&config, 0, sizeof(config));
  
	config.certif = NULL;
	config.keys = NULL;
	config.size = 0;
	config.realmtable = NULL;
  config.dateformat = NULL;
  
#ifdef HAVE_LIBPTHREAD
  remember_mainthread();
#endif

#ifdef AF_INET6
#define GETOPT_LONG_AF_INET6(x) "46"x
#else
#define GETOPT_LONG_AF_INET6(x) x
#endif
#ifdef HAVE_LIBPTHREAD
/* FIXME: 'S' option is not needed now
#define GETOPT_LONG_LIBPTHREAD(x) "PS"x
*/
#define GETOPT_LONG_LIBPTHREAD(x) "P"x
#else
#define GETOPT_LONG_LIBPTHREAD(x) x
#endif
  
  while ((n = getopt_long(argc, argv,
          GETOPT_LONG_LIBPTHREAD(GETOPT_LONG_AF_INET6("hn:l:m:vu:c:k:f:p:o:t:C:U:M:abD:R:r:V"))
          , long_options, 0)) != -1) {
    switch (n) {
      case 'h': {
                  server_long_usage(AF_VER("Active port forwarder (server)"));
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
      case 'o': {
                  addlogtarget(optarg);
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
      case 'a': {
                  audit = 1;
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
#ifdef HAVE_LIBPTHREAD
      case 'P': {
                  if ((tunneltype < 0) || (tunneltype > 2)) {
                    tunneltype = -1;
                  }
                  else {
                    if (tunneltype != 2) {
                      tunneltype = 1;
                    }
                  }
                  break;
                }
                /* FIXME: don't need it now
      case 'S': {
                  if ((tunneltype < 0) || (tunneltype > 2)) {
                    tunneltype = -1;
                  }
                  else {
                    tunneltype = 2;
                  }
                  break;
                }
                */
#endif
      case 'V': {
                  printf("%s\n", (AF_VER("Active port forwarder (server)")));
                  exit(0);
                  break;
                }
      case '?': {
                  server_short_usage("");
                  break;
                }
    }
  }

	if (optind < argc) {
	    server_short_usage("Unrecognized non-option elements");
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
      if (dateformat != NULL) {
        config.dateformat = dateformat;
      }
     
      initializelogging(verbose, config.dateformat);
      
      aflog(LOG_T_INIT, LOG_I_INFO,
          "cfg file OK! (readed realms: %d)", config.size);
      if (name != NULL)
        aflog(LOG_T_INIT, LOG_I_WARNING,
            "Warning: hostname=%s will be ignored", name);
      if (listen != NULL)
        aflog(LOG_T_INIT, LOG_I_WARNING,
            "Warning: listenport will be ignored");
      if (manage != NULL)
        aflog(LOG_T_INIT, LOG_I_WARNING,
            "Warning: manageport will be ignored");
      if (realmname != NULL)
        aflog(LOG_T_INIT, LOG_I_WARNING,
            "Warning: realmname=%s will be ignored", realmname);
      if (sent == 1)
        aflog(LOG_T_INIT, LOG_I_WARNING,
            "Warning: password from command line will be ignored");
		}
	}
	else {
    config.certif = certif;
    config.keys = keys;
    config.dateformat = dateformat;
    
    initializelogging(verbose, config.dateformat);
    
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
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "Number of listen and manage options are not the same... exiting");
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
    config.realmtable[0].usrclitable = calloc(managecount, sizeof(UsrCli*));
    for (i = 0; i < config.realmtable[0].usrclinum; ++i) {
      config.realmtable[0].usrclitable[i] = UsrCli_new();
      if (config.realmtable[0].usrclitable[i] == NULL) {
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "Problem with allocating memory for UsrCli structure... exiting");
        exit(1);
      }
      UsrCli_set_listenPortName(config.realmtable[0].usrclitable[i], listen[i]);
      UsrCli_set_managePortName(config.realmtable[0].usrclitable[i], manage[i]);
    }
		config.realmtable[0].users = amount;
		config.realmtable[0].clients = clients;
		config.realmtable[0].raclients = raclients;
		config.realmtable[0].timeout = timeout;
		config.realmtable[0].usrpcli = usrpcli;
		config.realmtable[0].clim = clim;
		config.realmtable[0].baseport = baseport;
		config.realmtable[0].audit = audit;
#ifdef HAVE_LIBPTHREAD
		config.realmtable[0].tunneltype = tunneltype;
#endif
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
			aflog(LOG_T_INIT, LOG_I_CRIT,
          "Conflicting types of ip protocol family... exiting");
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
		aflog(LOG_T_INIT, LOG_I_CRIT,
        "Setting ciphers list failed... exiting");
		exit(1);
	}
  if ((flags = create_apf_dir(0))) {
    aflog(LOG_T_INIT, LOG_I_WARNING,
        "Warning: Creating ~/.apf directory failed (%d)", flags);
    if ((flags = create_apf_dir(1))) {
      aflog(LOG_T_INIT, LOG_I_WARNING,
          "Warning: Creating ./apf directory failed (%d)", flags);
    }
  }
  if ((flags = generate_rsa_key(&config.keys))) {
    aflog(LOG_T_INIT, LOG_I_WARNING,
        "Warning: Something bad happened when generating rsa keys... (%d)", flags);
  }
	if (SSL_CTX_use_RSAPrivateKey_file(ctx, config.keys, SSL_FILETYPE_PEM) != 1) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "Setting rsa key failed (%s)... exiting", config.keys);
    exit(1);
  }
  if ((flags = generate_certificate(&config.certif, config.keys))) {
    aflog(LOG_T_INIT, LOG_I_WARNING,
        "Warning: Something bad happened when generating certificate... (%d)", flags);
  }
	if (SSL_CTX_use_certificate_file(ctx, config.certif, SSL_FILETYPE_PEM) != 1) {
		aflog(LOG_T_INIT, LOG_I_CRIT,
        "Setting certificate failed (%s)... exiting", config.certif);
		exit(1);
	}
	if (config.size == 0) {
		aflog(LOG_T_INIT, LOG_I_CRIT,
        "Working without sense is really without sense...");
		exit(1);
	}
	
	FD_ZERO(&allset);
	FD_ZERO(&wset);
	
	if (!verbose)
		daemon(0, 0);

	for (i = 0; i < config.size; ++i) {
    if (config.realmtable[i].usrclinum == 0) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "You have to specify at least one listen port and one manage port in each realm");
      exit(1);
    }
    for (j = 0; j < config.realmtable[i].usrclinum; ++j) {
  		if ((UsrCli_get_listenPortName(config.realmtable[i].usrclitable[j]) == NULL) ||
  			(UsrCli_get_managePortName(config.realmtable[i].usrclitable[j]) == NULL)) {
  			aflog(LOG_T_INIT, LOG_I_CRIT,
            "Missing some of the variables...\nRealm: %d\nlistenport[%d]: %s\nmanageport[%d]: %s",
  					i, j, UsrCli_get_listenPortName(config.realmtable[i].usrclitable[j]),
  					j, UsrCli_get_managePortName(config.realmtable[i].usrclitable[j]));
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
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "Conflicting types of ip protocol family... exiting");
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
    /* using user's audit value*/
    if (config.realmtable[i].audit == 0) {
      config.realmtable[i].audit = audit;
    }
#ifdef HAVE_LIBPTHREAD
    /* using user's tunneltype value*/
    if (config.realmtable[i].tunneltype == 0) {
      if (tunneltype == -1) {
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "Conflicting types of tunnel type... exiting");
        exit(1);
      }
      config.realmtable[i].tunneltype = tunneltype;
    }
#endif
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
		config.realmtable[i].contable = calloc(config.realmtable[i].usernum, sizeof(ConnectUser));
		if (config.realmtable[i].contable == NULL) {
			aflog(LOG_T_INIT, LOG_I_CRIT,
          "Calloc error - try define smaller amount of users");
			exit(1);
		}
    for (j = 0; j < config.realmtable[i].usernum; ++j) {
      config.realmtable[i].contable[j] = ConnectUser_new();
      if (config.realmtable[i].contable[j] == NULL) {
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "Calloc error - try define smaller amount of users");
        exit(1);
      }
    }
		config.realmtable[i].clitable = calloc( config.realmtable[i].clinum, sizeof(ConnectClient));
		if (config.realmtable[i].clitable == NULL) {
			aflog(LOG_T_INIT, LOG_I_CRIT,
          "Calloc error - try define smaller amount of clients");
			exit(1);
		}
    for (j = 0; j < config.realmtable[i].clinum; ++j) {
      config.realmtable[i].clitable[j] = ConnectClient_new();
      if (config.realmtable[i].clitable[j] == NULL) {
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "Calloc error - try define smaller amount of clients");
        exit(1);
      }
    }
		config.realmtable[i].raclitable = calloc( config.realmtable[i].raclinum, sizeof(ConnectClient));
		if (config.realmtable[i].raclitable == NULL) {
			aflog(LOG_T_INIT, LOG_I_CRIT,
          "Calloc error - try define smaller amount of raclients");
			exit(1);
		}
    for (j = 0; j < config.realmtable[i].raclinum; ++j) {
      config.realmtable[i].raclitable[j] = ConnectClient_new();
      if (config.realmtable[i].raclitable[j] == NULL) {
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "Calloc error - try define smaller amount of raclients");
        exit(1);
      }
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
        if (ip_listen(&temp, UsrCli_get_listenHostName(config.realmtable[i].usrclitable[j]) ?
              UsrCli_get_listenHostName(config.realmtable[i].usrclitable[j]) :
              config.realmtable[i].hostname,
              UsrCli_get_listenPortName(config.realmtable[i].usrclitable[j]),
              (&(config.realmtable[i].addrlen)), ipfam)) {
          aflog(LOG_T_INIT, LOG_I_CRIT,
#ifdef AF_INET6
              "tcp_listen_%s error for %s, %s",
              (ipfam & 0x02)?"ipv4":(ipfam & 0x04)?"ipv6":"unspec",
#else
              "tcp_listen error for %s, %s",
#endif
              UsrCli_get_listenHostName(config.realmtable[i].usrclitable[j]) ?
              UsrCli_get_listenHostName(config.realmtable[i].usrclitable[j]) :
              config.realmtable[i].hostname,
              UsrCli_get_listenPortName(config.realmtable[i].usrclitable[j]));
          exit(1);
        }
        UsrCli_set_listenFd(config.realmtable[i].usrclitable[j], temp);
        flags = fcntl(UsrCli_get_listenFd(config.realmtable[i].usrclitable[j]), F_GETFL, 0);
        fcntl(UsrCli_get_listenFd(config.realmtable[i].usrclitable[j]), F_SETFL, flags | O_NONBLOCK);
      }
    }
    for (j = 0; j < config.realmtable[i].usrclinum; ++j) {
      switch (config.realmtable[i].tunneltype) {
        case 0: {
                  if (ip_listen(&temp, UsrCli_get_manageHostName(config.realmtable[i].usrclitable[j]) ?
                        UsrCli_get_manageHostName(config.realmtable[i].usrclitable[j]) :
                        config.realmtable[i].hostname,
                        UsrCli_get_managePortName(config.realmtable[i].usrclitable[j]),
                        (&(config.realmtable[i].addrlen)), ipfam)) {
                    aflog(LOG_T_INIT, LOG_I_CRIT,
#ifdef AF_INET6
                        "tcp_listen_%s error for %s, %s",
                        (ipfam & 0x02)?"ipv4":(ipfam & 0x04)?"ipv6":"unspec",
#else
                        "tcp_listen error for %s, %s",
#endif
                        UsrCli_get_manageHostName(config.realmtable[i].usrclitable[j]) ?
                        UsrCli_get_manageHostName(config.realmtable[i].usrclitable[j]) :
                        config.realmtable[i].hostname,
                        UsrCli_get_managePortName(config.realmtable[i].usrclitable[j]));
                    exit(1);
                  }
                  UsrCli_set_manageFd(config.realmtable[i].usrclitable[j], temp);
                  flags = fcntl(UsrCli_get_manageFd(config.realmtable[i].usrclitable[j]), F_GETFL, 0);
                  fcntl(UsrCli_get_manageFd(config.realmtable[i].usrclitable[j]), F_SETFL, flags | O_NONBLOCK);
                  break;
                }
#ifdef HAVE_LIBPTHREAD
        case 1: case 2: {
                  if (initialize_http_proxy_server(&temp,
                        UsrCli_get_manageHostName(config.realmtable[i].usrclitable[j]) ?
                        UsrCli_get_manageHostName(config.realmtable[i].usrclitable[j]) :
                        config.realmtable[i].hostname,
                        UsrCli_get_managePortName(config.realmtable[i].usrclitable[j]),
                        (&(config.realmtable[i].addrlen)), ipfam,
                        config.realmtable[i].clinum + config.realmtable[i].raclinum,
                        (config.realmtable[i].tunneltype - 1),
                        ctx)) {
                    aflog(LOG_T_INIT, LOG_I_CRIT,
#ifdef AF_INET6
                        "http%s_proxy_listen_%s error for %s, %s",
                        (config.realmtable[i].tunneltype == 2) ? "s" : "",
                        (ipfam & 0x02)?"ipv4":(ipfam & 0x04)?"ipv6":"unspec",
#else
                        "http%s_proxy_listen error for %s, %s",
                        (config.realmtable[i].tunneltype == 2) ? "s" : "",
#endif
                        UsrCli_get_manageHostName(config.realmtable[i].usrclitable[j]) ?
                        UsrCli_get_manageHostName(config.realmtable[i].usrclitable[j]) :
                        config.realmtable[i].hostname,
                        UsrCli_get_managePortName(config.realmtable[i].usrclitable[j]));
                    exit(1);
                  }
                  UsrCli_set_manageFd(config.realmtable[i].usrclitable[j], temp);
                  flags = fcntl(UsrCli_get_manageFd(config.realmtable[i].usrclitable[j]), F_GETFL, 0);
                  fcntl(UsrCli_get_manageFd(config.realmtable[i].usrclitable[j]), F_SETFL, flags | O_NONBLOCK);
                  break;
                }
#endif
        default: {
                   aflog(LOG_T_INIT, LOG_I_CRIT,
                       "Unknown tunnel type");
                   exit(1);
                   break;
                 }
      }
    }
		config.realmtable[i].cliaddr = malloc(config.realmtable[i].addrlen);
		
    for (j=0; j<config.realmtable[i].clinum; ++j) {
      SslFd_set_ssl(ConnectClient_get_sslFd(config.realmtable[i].clitable[j]), SSL_new(ctx));
  		if (SslFd_get_ssl(ConnectClient_get_sslFd(config.realmtable[i].clitable[j])) == NULL) {
  			aflog(LOG_T_INIT, LOG_I_CRIT,
            "Creating of ssl object failed... exiting");
  			exit(1);
  		}
    }
    
    for (j=0; j<config.realmtable[i].raclinum; ++j) {
      SslFd_set_ssl(ConnectClient_get_sslFd(config.realmtable[i].raclitable[j]), SSL_new(ctx));
  		if (SslFd_get_ssl(ConnectClient_get_sslFd(config.realmtable[i].raclitable[j])) == NULL) {
  			aflog(LOG_T_INIT, LOG_I_CRIT,
            "Creating of ssl object failed... exiting");
  			exit(1);
  		}
    }
	
    for (j = 0; j < config.realmtable[i].usrclinum; ++j) {
  		FD_SET(UsrCli_get_manageFd(config.realmtable[i].usrclitable[j]), &allset);
  		maxfdp1 = (maxfdp1 > (UsrCli_get_manageFd(config.realmtable[i].usrclitable[j]) + 1)) ?
        maxfdp1 : (UsrCli_get_manageFd(config.realmtable[i].usrclitable[j]) + 1);
    }
    if (config.realmtable[i].baseport == 0) {
      for (j = 0; j < config.realmtable[i].usrclinum; ++j) {
  		  FD_SET(UsrCli_get_listenFd(config.realmtable[i].usrclitable[j]), &allset);
  		  maxfdp1 = (maxfdp1 > (UsrCli_get_listenFd(config.realmtable[i].usrclitable[j]) + 1)) ?
          maxfdp1 : (UsrCli_get_listenFd(config.realmtable[i].usrclitable[j]) + 1);
      }
    }
		config.realmtable[i].usercon = 0;
		config.realmtable[i].clicon = 0;
		config.realmtable[i].raclicon = 0;
    for (j=0; j<config.realmtable[i].clinum; ++j) {
      ConnectClient_set_timer(config.realmtable[i].clitable[j], timeval_create(config.realmtable[i].tmout, 0));
      ConnectClient_set_limit(config.realmtable[i].clitable[j], config.realmtable[i].upcnum);
      if (ConnectClient_create_users(config.realmtable[i].clitable[j])) {
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "Calloc error - try define smaller amount of usrpcli (or users)");
        exit(1);
      }
    }
    for (j=0; j<config.realmtable[i].raclinum; ++j) {
      ConnectClient_set_timer(config.realmtable[i].raclitable[j], timeval_create(config.realmtable[i].tmout,0));
    }
  }

	aflog(LOG_T_MAIN, LOG_I_INFO,
      "SERVER STARTED realms: %d", config.size);
  time(&config.starttime);
	
	for ( ; ; ) {
		rset = allset;
		tmpset = wset;
			aflog(LOG_T_MAIN, LOG_I_DDEBUG,
          "select, maxfdp1: %d", maxfdp1);
		if (manconnecting) {
			/* find out, in what realm client is trying to connect */
      l = -1;
			for (k = 0; k < config.size; ++k) {
        for (j=0; j < config.realmtable[k].clinum; ++j) {
				  if ((ConnectClient_get_state(config.realmtable[k].clitable[j]) == CONNECTCLIENT_STATE_CONNECTING) ||
              (ConnectClient_get_state(config.realmtable[k].clitable[j]) == CONNECTCLIENT_STATE_AUTHORIZING)) {
            i = k;
            k = config.size;
            l = 0;
				  	break; /* so i points to first good realm and j to good client */
				  }
        }
        if (l == -1) {
          for (j=0; j < config.realmtable[k].raclinum; ++j) {
            if ((ConnectClient_get_state(config.realmtable[k].raclitable[j])==CONNECTCLIENT_STATE_CONNECTING) ||
                (ConnectClient_get_state(config.realmtable[k].raclitable[j])==CONNECTCLIENT_STATE_AUTHORIZING)) {
              i = k;
              k = config.size;
              l = 1;
  				  	break; /* so i points to first good realm and j to good client */
  				  }
          }
        }
			}
      if (!l) {
  			if (select(maxfdp1,&rset,&tmpset,NULL,ConnectClient_get_timerp(config.realmtable[i].clitable[j])) == 0) {
          close(SslFd_get_fd(ConnectClient_get_sslFd(config.realmtable[i].clitable[j])));
          FD_CLR(SslFd_get_fd(ConnectClient_get_sslFd(config.realmtable[i].clitable[j])), &allset);
          SSL_clear(SslFd_get_ssl(ConnectClient_get_sslFd(config.realmtable[i].clitable[j])));
          ConnectClient_set_state(config.realmtable[i].clitable[j], CONNECTCLIENT_STATE_FREE);
          manconnecting--;
          config.realmtable[i].clicon--;
          aflog(LOG_T_CLIENT, LOG_I_WARNING,
              "realm[%s]: Client[%s]: SSL_accept failed (timeout)",
              get_realmname(&config, i), get_clientname(pointer, j));
  			}
      }
      else {
  			if (select(maxfdp1,&rset,&tmpset,NULL,ConnectClient_get_timerp(config.realmtable[i].raclitable[j]))==0) {
          close(SslFd_get_fd(ConnectClient_get_sslFd(config.realmtable[i].raclitable[j])));
          FD_CLR(SslFd_get_fd(ConnectClient_get_sslFd(config.realmtable[i].raclitable[j])), &allset);
          SSL_clear(SslFd_get_ssl(ConnectClient_get_sslFd(config.realmtable[i].raclitable[j])));
          ConnectClient_set_state(config.realmtable[i].raclitable[j], CONNECTCLIENT_STATE_FREE);
				  manconnecting--;
          config.realmtable[i].clicon--;
          aflog(LOG_T_CLIENT, LOG_I_WARNING,
              "realm[%s]: Client[%s] (ra): SSL_accept failed (timeout)",
              get_realmname(&config, i), get_raclientname(pointer, j));
  			}
      }
		}
		else {
			select(maxfdp1, &rset, &tmpset, NULL, NULL);
		}
		aflog(LOG_T_MAIN, LOG_I_DDEBUG,
        "after select...");

    for (j = 0; j < config.size; ++j) {
      pointer = (&(config.realmtable[j]));
      for (i = 0; i <pointer->usernum; ++i) {
        if ((ConnectUser_get_state(pointer->contable[i]) == S_STATE_OPEN) ||
            (ConnectUser_get_state(pointer->contable[i]) == S_STATE_STOPPED))
          if (FD_ISSET(ConnectUser_get_connFd(pointer->contable[i]), &rset)) {
            k = eval_usernum(pointer->clitable[ConnectUser_get_whatClient(pointer->contable[i])], i);
            aflog(LOG_T_USER, LOG_I_DDEBUG,
                "realm[%s]: Client[%s]: user[%d]: FD_ISSET", get_realmname(&config, j),
                get_clientname(pointer, ConnectUser_get_whatClient(pointer->contable[i])),
                get_username(pointer,i));
            if (TYPE_IS_TCP(pointer->type)) { /* forwarding tcp packets */
              n = read(ConnectUser_get_connFd(pointer->contable[i]), &buff[5], 8091);
              if (n == -1) {
                if (errno == EAGAIN) {
                  continue;
                }
                aflog(LOG_T_USER, LOG_I_ERR,
                    "realm[%s]: Client[%s]: user[%d]: READ ERROR (%d)", get_realmname(&config, j),
                    get_clientname(pointer, ConnectUser_get_whatClient(pointer->contable[i])),
                    get_username(pointer, i), errno);
                n = 0;
              }
              if (n) {
                aflog(LOG_T_USER, LOG_I_DEBUG,
                    "realm[%s]: Client[%s]: FROM user[%d]: MESSAGE length=%d", get_realmname(&config, j),
                    get_clientname(pointer, ConnectUser_get_whatClient(pointer->contable[i])),
                    get_username(pointer, i), n);
                UserStats_add_upload(ConnectUser_get_stats(pointer->contable[i]), n);
                if ((buff[5] == AF_S_MESSAGE) && (buff[6] == AF_S_LOGIN) && (buff[7] == AF_S_MESSAGE)) {
                  aflog(LOG_T_USER, LOG_I_WARNING,
                      "WARNING: got packet similiar to udp");
                }
                buff[0] = AF_S_MESSAGE; /* sending message */
                buff[1] = k >> 8;	/* high bits of user number */
                buff[2] = k;		/* low bits of user number */
                buff[3] = n >> 8;	/* high bits of message length */
                buff[4] = n;		/* low bits of message length */
                SslFd_send_message(pointer->type,
                    ConnectClient_get_sslFd(
                      pointer->clitable[ConnectUser_get_whatClient(pointer->contable[i])]),
                    buff, n+5);
              }
              else {
                aflog(LOG_T_USER, LOG_I_INFO,
                    "realm[%s]: Client[%s]: user[%d]: CLOSED", get_realmname(&config, j),
                    get_clientname(pointer, ConnectUser_get_whatClient(pointer->contable[i])),
                    get_username(pointer, i));
                time(&now);
                aflog(LOG_T_USER, LOG_I_NOTICE,
                    "REALM: %s CLIENT: %s USER: %d IP: %s PORT: %s DURATION: %s",
                    get_realmname(&config, j),
                    get_clientname(pointer, ConnectUser_get_whatClient(pointer->contable[i])),
                    get_username(pointer, i),
                    ConnectUser_get_nameBuf(pointer->contable[i]),
                    ConnectUser_get_portBuf(pointer->contable[i]),
                    timeperiod(now - ConnectUser_get_connectTime(pointer->contable[i])));
                if (pointer->audit) {
                  AuditList_insert_back(
                      ConnectClient_get_auditList(
                        pointer->clitable[ConnectUser_get_whatClient(pointer->contable[i])]),
                      AuditListNode_new_entry(
                        get_username(pointer, i),
                        ConnectUser_get_nameBuf(pointer->contable[i]),
                        ConnectUser_get_portBuf(pointer->contable[i]),
                        ConnectUser_get_connectTime(pointer->contable[i]),
                        now - ConnectUser_get_connectTime(pointer->contable[i]))
                      );
                }
                close(ConnectUser_get_connFd(pointer->contable[i]));
                FD_CLR(ConnectUser_get_connFd(pointer->contable[i]), &allset);
                FD_CLR(ConnectUser_get_connFd(pointer->contable[i]), &wset);
                ConnectUser_set_state(pointer->contable[i], S_STATE_CLOSING);
                BufList_clear(ConnectUser_get_bufList(pointer->contable[i]));
                buff[0] = AF_S_CONCLOSED; /* closing connection */
                buff[1] = k >> 8;	/* high bits of user number */
                buff[2] = k;		/* low bits of user number */
                SslFd_send_message(pointer->type,
                    ConnectClient_get_sslFd(
                      pointer->clitable[ConnectUser_get_whatClient(pointer->contable[i])]),
                    buff, 5);
              }
            }
            else { /* when forwarding udp packets */
              n = readn(ConnectUser_get_connFd(pointer->contable[i]), buff, 5 );
              if (n != 5) {
                n = 0;
              }
              if (n) {
                if ((buff[0] == AF_S_MESSAGE) && (buff[1] == AF_S_LOGIN) && (buff[2] == AF_S_MESSAGE)) {
                  length = buff[3];
                  length = length << 8;
                  length += buff[4]; /* this is length of message */
                  if ((n = readn(ConnectUser_get_connFd(pointer->contable[i]), &buff[5], length)) != 0) {
                    aflog(LOG_T_USER, LOG_I_DEBUG,
                        "realm[%s]: Client[%s]: FROM user[%d]: MESSAGE length=%d",
                        get_realmname(&config, j),
                        get_clientname(pointer, ConnectUser_get_whatClient(pointer->contable[i])),
                        get_username(pointer, i), n);
                    buff[1] = k >> 8;	/* high bits of user number */
                    buff[2] = k;		/* low bits of user number */
                    SslFd_send_message(pointer->type,
                        ConnectClient_get_sslFd(
                          pointer->clitable[ConnectUser_get_whatClient(pointer->contable[i])]),
                        buff, n+5);
                  }
                }
                else {
                  n = 0;
                }
              }

              if (n == 0) {
                aflog(LOG_T_USER, LOG_I_INFO,
                    "realm[%s]: Client[%s]: user[%d]: CLOSED (udp mode)", get_realmname(&config, j),
                    get_clientname(pointer,
                      ConnectUser_get_whatClient(pointer->contable[i])), get_username(pointer, i));
                time(&now);
                aflog(LOG_T_USER, LOG_I_NOTICE,
                    "REALM: %s CLIENT: %s USER: %d IP: %s PORT: %s DURATION: %s",
                    get_realmname(&config, j),
                    get_clientname(pointer, ConnectUser_get_whatClient(pointer->contable[i])),
                    get_username(pointer, i),
                    ConnectUser_get_nameBuf(pointer->contable[i]),
                    ConnectUser_get_portBuf(pointer->contable[i]),
                    timeperiod(now - ConnectUser_get_connectTime(pointer->contable[i])));
                close(ConnectUser_get_connFd(pointer->contable[i]));
                FD_CLR(ConnectUser_get_connFd(pointer->contable[i]), &allset);
                FD_CLR(ConnectUser_get_connFd(pointer->contable[i]), &wset);
                ConnectUser_set_state(pointer->contable[i], S_STATE_CLOSING);
                BufList_clear(ConnectUser_get_bufList(pointer->contable[i]));
                buff[0] = AF_S_CONCLOSED; /* closing connection */
                buff[1] = k >> 8;	/* high bits of user number */
                buff[2] = k;		/* low bits of user number */
                SslFd_send_message(pointer->type,
                    ConnectClient_get_sslFd(
                      pointer->clitable[ConnectUser_get_whatClient(pointer->contable[i])]),
                    buff, 5);
              }

            }
          }
      }
      /* ------------------------------------ */
      for (i = 0; i <pointer->usernum; ++i) {
        if (ConnectUser_get_state(pointer->contable[i]) == S_STATE_STOPPED)
          if (FD_ISSET(ConnectUser_get_connFd(pointer->contable[i]), &tmpset)) {
            k = eval_usernum(pointer->clitable[ConnectUser_get_whatClient(pointer->contable[i])], i);
            aflog(LOG_T_USER, LOG_I_DDEBUG,
                "realm[%s]: Client[%s]: user[%d]: FD_ISSET - WRITE", get_realmname(&config, j),
                get_clientname(pointer, ConnectUser_get_whatClient(pointer->contable[i])),
                get_username(pointer, i));
            n = BufListNode_readMessageLength(BufList_get_first(ConnectUser_get_bufList(pointer->contable[i])));
            sent = write(ConnectUser_get_connFd(pointer->contable[i]),
                BufListNode_readMessage(BufList_get_first(ConnectUser_get_bufList(pointer->contable[i]))), n);
            if ((sent > 0) && (sent != n)) {
              BufListNode_set_actPtr(BufList_get_first(ConnectUser_get_bufList(pointer->contable[i])),
                  BufListNode_get_actPtr(BufList_get_first(ConnectUser_get_bufList(pointer->contable[i]))) + sent);
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "realm[%s]: Client[%s]: user[%d]: (%d/%d)", get_realmname(&config, j),
                  get_clientname(pointer, ConnectUser_get_whatClient(pointer->contable[i])),
                  get_username(pointer, i), sent, n);
            }
            else if ((sent == -1) && (errno == EAGAIN)) {
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "realm[%s]: Client[%s]: user[%d]: EAGAIN", get_realmname(&config, j),
                  get_clientname(pointer, ConnectUser_get_whatClient(pointer->contable[i])),
                  get_username(pointer, i));
            }
            else if (sent == -1) {
              aflog(LOG_T_USER, LOG_I_INFO,
                  "realm[%s]: Client[%s]: user[%d]: CLOSED", get_realmname(&config, j),
                  get_clientname(pointer, ConnectUser_get_whatClient(pointer->contable[i])),
                  get_username(pointer, i));
              time(&now);
              aflog(LOG_T_USER, LOG_I_NOTICE,
                  "REALM: %s CLIENT: %s USER: %d IP: %s PORT: %s DURATION: %s",
                  get_realmname(&config, j),
                  get_clientname(pointer, ConnectUser_get_whatClient(pointer->contable[i])),
                  get_username(pointer, i),
                  ConnectUser_get_nameBuf(pointer->contable[i]),
                  ConnectUser_get_portBuf(pointer->contable[i]),
                  timeperiod(now - ConnectUser_get_connectTime(pointer->contable[i])));
              close(ConnectUser_get_connFd(pointer->contable[i]));
              FD_CLR(ConnectUser_get_connFd(pointer->contable[i]), &allset);
              FD_CLR(ConnectUser_get_connFd(pointer->contable[i]), &wset);
              ConnectUser_set_state(pointer->contable[i], S_STATE_CLOSING);
              BufList_clear(ConnectUser_get_bufList(pointer->contable[i]));
              buff[0] = AF_S_CONCLOSED; /* closing connection */
              buff[1] = k >> 8;	/* high bits of user number */
              buff[2] = k;		/* low bits of user number */
              SslFd_send_message(pointer->type,
                  ConnectClient_get_sslFd(
                    pointer->clitable[ConnectUser_get_whatClient(pointer->contable[i])]),
                  buff, 5);
            }
            else {
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "realm[%s]: Client[%s]: user[%d]: (%d/%d)", get_realmname(&config, j),
                  get_clientname(pointer, ConnectUser_get_whatClient(pointer->contable[i])),
                  get_username(pointer, i), sent, n);
              BufList_delete_first(ConnectUser_get_bufList(pointer->contable[i]));
              if (BufList_get_first(ConnectUser_get_bufList(pointer->contable[i])) == NULL) {
                ConnectUser_set_state(pointer->contable[i], S_STATE_OPEN);
                FD_CLR(ConnectUser_get_connFd(pointer->contable[i]), &wset);
                buff[0] = AF_S_CAN_SEND; /* stopping transfer */
                buff[1] = k >> 8;	/* high bits of user number */
                buff[2] = k;		/* low bits of user number */
                aflog(LOG_T_USER, LOG_I_DDEBUG,
                    "realm[%s]: Client[%s]: TO user[%d]: BUFFERING MESSAGE ENDED",
                    get_realmname(&config, j),
                    get_clientname(pointer, ConnectUser_get_whatClient(pointer->contable[i])),
                    get_username(pointer, i));
                SslFd_send_message(pointer->type,
                    ConnectClient_get_sslFd(
                      pointer->clitable[ConnectUser_get_whatClient(pointer->contable[i])]),
                    buff, 5);
              }
            }
          }
      }
      /* ------------------------------------ */
      if (pointer->baseport == 0) {
        for (l = 0; l < pointer->usrclinum; ++l) {
          if (FD_ISSET(UsrCli_get_listenFd(pointer->usrclitable[l]), &rset)) {
            len = pointer->addrlen;
            sent = accept(UsrCli_get_listenFd(pointer->usrclitable[l]), pointer->cliaddr, &len);
            if (sent == -1) {
              if (errno == EAGAIN) {
                aflog(LOG_T_USER, LOG_I_DDEBUG,
                    "realm[%s]: listenfd: FD_ISSET --> EAGAIN", get_realmname(&config, j));
              }
              else {
                aflog(LOG_T_USER, LOG_I_DDEBUG,
                    "realm[%s]: listenfd: FD_ISSET --> errno=%d", get_realmname(&config, j), errno);
              }
              continue;
            }
            flags = fcntl(sent, F_GETFL, 0);
            fcntl(sent, F_SETFL, flags | O_NONBLOCK);
            aflog(LOG_T_USER, LOG_I_DDEBUG,
                "realm[%s]: listenfd: FD_ISSET", get_realmname(&config, j));
            k = find_client(pointer, pointer->climode, l);
            if (ConnectClient_get_state(pointer->clitable[k]) == CONNECTCLIENT_STATE_ACCEPTED) {
              if (pointer->usercon == pointer->usernum) {
                close(sent);
                aflog(LOG_T_USER, LOG_I_WARNING,
                    "realm[%s]: user limit EXCEEDED", get_realmname(&config, j));
              }
              else if (ConnectClient_get_connected(pointer->clitable[k]) ==
                  ConnectClient_get_limit(pointer->clitable[k])) {
                close(sent);
                aflog(LOG_T_USER, LOG_I_WARNING,
                    "realm[%s]: Client[%s]: usrpcli limit EXCEEDED",
                    get_realmname(&config, j), get_clientname(pointer, k));
              }
              else {
                for (i = 0; i < pointer->usernum; ++i) {
                  if (ConnectUser_get_state(pointer->contable[i]) == S_STATE_CLEAR) {
                    ConnectUser_set_userId(pointer->contable[i], pointer->usercounter);
                    ++(pointer->usercounter);
                    aflog(LOG_T_USER, LOG_I_INFO,
                        "realm[%s]: Client[%s]: new user: CONNECTING from IP: %s",
                        get_realmname(&config, j), get_clientname(pointer, k),
                        sock_ntop(pointer->cliaddr, len, ConnectUser_get_nameBuf(pointer->contable[i]),
                          ConnectUser_get_portBuf(pointer->contable[i]), pointer->dnslookups));
                    ConnectUser_set_connFd(pointer->contable[i], sent);
                    ConnectUser_set_state(pointer->contable[i], S_STATE_OPENING);
                    ConnectUser_set_whatClient(pointer->contable[i], k);
                    time(&now);
                    ConnectUser_set_connectTime(pointer->contable[i], now);
                    UserStats_clear(ConnectUser_get_stats(pointer->contable[i]));
                    UserStats_set_lastActivity(ConnectUser_get_stats(pointer->contable[i]), now);
                    pointer->usercon++;
                    ConnectClient_increase_connected(pointer->clitable[k]);
                    memcpy(&buff[5], ConnectUser_get_nameBuf(pointer->contable[i]), 128);
                    memcpy(&buff[133], ConnectUser_get_portBuf(pointer->contable[i]), 7);
                    n = 135;
                    i = find_usernum(pointer->clitable[k], i);
                    buff[0] = AF_S_CONOPEN; /* opening connection */
                    buff[1] = i >> 8;	/* high bits of user number */
                    buff[2] = i;		/* low bits of user number */
                    buff[3] = n >> 8;	/* high bits of message length */
                    buff[4] = n;		/* low bits of message length */
                    SslFd_send_message(pointer->type,
                        ConnectClient_get_sslFd(
                          pointer->clitable[k]),
                        buff, n+5);
                    break;
                  }
                }
              }
            }
            else {
              close(sent);
              aflog(LOG_T_USER, LOG_I_ERR,
                  "realm[%s]: Client(%d) is NOT CONNECTED",
                  get_realmname(&config, j), k);
            }
          }
        }
      }
      /* ------------------------------------ */
      if (pointer->baseport == 1) {
        for (k = 0; k < pointer->clinum; ++k) {
          if (ConnectClient_get_state(pointer->clitable[k]) == CONNECTCLIENT_STATE_ACCEPTED) {
            if (FD_ISSET(ConnectClient_get_listenFd(pointer->clitable[k]), &rset)) {
              len = pointer->addrlen;
              sent = accept(ConnectClient_get_listenFd(pointer->clitable[k]), pointer->cliaddr, &len);
              if (sent == -1) {
                if (errno == EAGAIN) {
                  aflog(LOG_T_USER, LOG_I_DDEBUG,
                      "realm[%s]: listenfd: FD_ISSET --> EAGAIN", get_realmname(&config, j));
                }
                else {
                  aflog(LOG_T_USER, LOG_I_DDEBUG,
                      "realm[%s]: listenfd: FD_ISSET --> errno=%d", get_realmname(&config, j), errno);
                }
                continue;
              }
              flags = fcntl(sent, F_GETFL, 0);
              fcntl(sent, F_SETFL, flags | O_NONBLOCK);
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "realm[%s]: Client[%s]: listenfd: FD_ISSET",
                  get_realmname(&config, j), get_clientname(pointer, k));
              if (pointer->usercon == pointer->usernum) {
                close(sent);
                aflog(LOG_T_USER, LOG_I_WARNING,
                    "realm[%s]: user limit EXCEEDED", get_realmname(&config, j));
              }
              else if(ConnectClient_get_connected(pointer->clitable[k]) ==
                  ConnectClient_get_limit(pointer->clitable[k])) {
                close(sent);
                aflog(LOG_T_USER, LOG_I_WARNING,
                    "realm[%s]: Client[%s]: usrpcli limit EXCEEDED",
                    get_realmname(&config, j), get_clientname(pointer, k));
              }
              else {
                for (i = 0; i < pointer->usernum; ++i) {
                  if (ConnectUser_get_state(pointer->contable[i]) == S_STATE_CLEAR) {
                    ConnectUser_set_userId(pointer->contable[i], pointer->usercounter);
                    ++(pointer->usercounter);
                    aflog(LOG_T_USER, LOG_I_INFO,
                        "realm[%s]: Client[%s]: new user: CONNECTING from IP: %s",
                        get_realmname(&config, j), get_clientname(pointer, k),
                        sock_ntop(pointer->cliaddr, len,
                          ConnectUser_get_nameBuf(pointer->contable[i]),
                          ConnectUser_get_portBuf(pointer->contable[i]), pointer->dnslookups));
                    ConnectUser_set_connFd(pointer->contable[i], sent);
                    ConnectUser_set_state(pointer->contable[i], S_STATE_OPENING);
                    ConnectUser_set_whatClient(pointer->contable[i], k);
                    time(&now);
                    ConnectUser_set_connectTime(pointer->contable[i], now);
                    UserStats_clear(ConnectUser_get_stats(pointer->contable[i]));
                    UserStats_set_lastActivity(ConnectUser_get_stats(pointer->contable[i]), now);
                    pointer->usercon++;
                    ConnectClient_increase_connected(pointer->clitable[k]);
                    memcpy(&buff[5], ConnectUser_get_nameBuf(pointer->contable[i]), 128);
                    memcpy(&buff[133], ConnectUser_get_portBuf(pointer->contable[i]), 7);
                    n = 135;
                    i = find_usernum(pointer->clitable[k], i);
                    buff[0] = AF_S_CONOPEN; /* opening connection */
                    buff[1] = i >> 8;	/* high bits of user number */
                    buff[2] = i;		/* low bits of user number */
                    buff[3] = n >> 8;	/* high bits of message length */
                    buff[4] = n;		/* low bits of message length */
                    SslFd_send_message(pointer->type,
                        ConnectClient_get_sslFd(
                          pointer->clitable[k]),
                        buff, n+5);
                    break;
                  }
                }
              }
            }
          }
        }
      }
      /* ------------------------------------ */
      for (k = 0; k < pointer->clinum; ++k)
        if ((ConnectClient_get_state(pointer->clitable[k]) > CONNECTCLIENT_STATE_FREE) &&
            (FD_ISSET(SslFd_get_fd(ConnectClient_get_sslFd(pointer->clitable[k])), &rset))) {
          if (ConnectClient_get_state(pointer->clitable[k]) == CONNECTCLIENT_STATE_CONNECTING) {
            make_ssl_initialize(ConnectClient_get_sslFd(pointer->clitable[k]));
            aflog(LOG_T_CLIENT, LOG_I_DDEBUG,
                "realm[%s]: new Client[%s]: SSL_accept",
                get_realmname(&config, j), get_clientname(pointer, k));
            switch (make_ssl_accept(ConnectClient_get_sslFd(pointer->clitable[k]))) {
              case 2: {
                        close(SslFd_get_fd(ConnectClient_get_sslFd(pointer->clitable[k])));
                        FD_CLR(SslFd_get_fd(ConnectClient_get_sslFd(pointer->clitable[k])), &allset);
                        SSL_clear(SslFd_get_ssl(ConnectClient_get_sslFd(pointer->clitable[k])));
                        ConnectClient_set_state(pointer->clitable[k], CONNECTCLIENT_STATE_FREE);
                        manconnecting--;
                        pointer->clicon--;
                        aflog(LOG_T_CLIENT, LOG_I_ERR,
                            "realm[%s]: new Client[%s]: DENIED by SSL_accept",
                            get_realmname(&config, j), get_clientname(pointer, k));
                      }
              case 1: {
                        continue;
                      }
              default: {
                         aflog(LOG_T_CLIENT, LOG_I_DEBUG,
                             "realm[%s]: new Client[%s]: ACCEPTED by SSL_accept",
                             get_realmname(&config, j), get_clientname(pointer, k));
                         ConnectClient_set_state(pointer->clitable[k], CONNECTCLIENT_STATE_AUTHORIZING);
                         continue;
                       }
            }
          }
          aflog(LOG_T_CLIENT, LOG_I_DDEBUG,
              "realm[%s]: Client[%s]: commfd: FD_ISSET",
              get_realmname(&config, j), get_clientname(pointer, k));
          if (ConnectClient_get_state(pointer->clitable[k]) == CONNECTCLIENT_STATE_AUTHORIZING) {
            n = SslFd_get_message(pointer->type | TYPE_SSL | TYPE_ZLIB,
                ConnectClient_get_sslFd(
                  pointer->clitable[k]),
                buff, (-1) * HeaderBuffer_to_read(ConnectClient_get_header(pointer->clitable[k])));
          }
          else {
            n = SslFd_get_message(pointer->type,
                ConnectClient_get_sslFd(
                  pointer->clitable[k]),
                buff, (-1) * HeaderBuffer_to_read(ConnectClient_get_header(pointer->clitable[k])));
          }
          if (n == -1) {
            if (errno == EAGAIN) {
              aflog(LOG_T_CLIENT, LOG_I_DDEBUG,
                  "realm[%s]: Client[%s]: commfd: EAGAIN",
                  get_realmname(&config, j), get_clientname(pointer, k));
              continue;
            }
            else {
              aflog(LOG_T_CLIENT, LOG_I_ERR,
                  "realm[%s]: Client[%s]: commfd: ERROR: %d",
                  get_realmname(&config, j), get_clientname(pointer, k), errno);
              n = 0;
            }
          }
          else if (n != 5) {
            if (n != 0) {
              aflog(LOG_T_CLIENT, LOG_I_DEBUG,
                  "realm[%s]: Client[%s]: header length = %d --> buffering",
                  get_realmname(&config, j), get_clientname(pointer, k), n);
              HeaderBuffer_store(ConnectClient_get_header(pointer->clitable[k]), buff, n);
              if (HeaderBuffer_to_read(ConnectClient_get_header(pointer->clitable[k])) == 0) {
                HeaderBuffer_restore(ConnectClient_get_header(pointer->clitable[k]), buff);
                n = 5;
              }
              else {
                continue;
              }
            }
          }
          if (n==0) { 
            aflog(LOG_T_CLIENT, LOG_I_INFO,
                "realm[%s]: Client[%s]: commfd: CLOSED",
                get_realmname(&config, j), get_clientname(pointer, k));
            time(&now);
            aflog(LOG_T_CLIENT, LOG_I_NOTICE,
                "REALM: %s CLIENT: %s IP: %s PORT: %s DURATION: %s",
                get_realmname(&config, j),
                get_clientname(pointer, k),
                ConnectClient_get_nameBuf(pointer->clitable[k]),
                ConnectClient_get_portBuf(pointer->clitable[k]),
                timeperiod(now - ConnectClient_get_connectTime(pointer->clitable[k])));
            if (pointer->audit) {
              while (AuditList_get_first(ConnectClient_get_auditList(pointer->clitable[k]))) {
                aflog(LOG_T_CLIENT, LOG_I_NOTICE,
                    "USERID: %d IP: %s PORT: %s CONNECTED: %s DURATION: %s",
                    AuditListNode_get_userId(
                      AuditList_get_first(
                        ConnectClient_get_auditList(pointer->clitable[k]))),
                    AuditListNode_get_nameBuf(
                      AuditList_get_first(
                        ConnectClient_get_auditList(pointer->clitable[k]))),
                    AuditListNode_get_portBuf(
                      AuditList_get_first(
                        ConnectClient_get_auditList(pointer->clitable[k]))),
                    localdate(AuditListNode_get_connectTimep(
                        AuditList_get_first(
                          ConnectClient_get_auditList(pointer->clitable[k])))),
                    timeperiod(AuditListNode_get_duration(
                        AuditList_get_first(
                          ConnectClient_get_auditList(pointer->clitable[k])))));
                AuditList_delete_first(ConnectClient_get_auditList(pointer->clitable[k]));
              }
            }
            remove_client(pointer, k, &allset, &wset, &manconnecting);
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
          if (ConnectClient_get_state(pointer->clitable[k]) < CONNECTCLIENT_STATE_AUTHORIZING) {
            aflog(LOG_T_CLIENT, LOG_I_WARNING,
                "realm[%s]: Client[%s]: Impossible behaviour --> ignoring",
                get_realmname(&config, j), get_clientname(pointer, k));
            continue;
          }
          if ((ConnectClient_get_state(pointer->clitable[k]) == CONNECTCLIENT_STATE_AUTHORIZING) &&
              (buff[0] != AF_S_LOGIN) && (buff[0] != AF_S_ADMIN_LOGIN)) {
            buff[0] = AF_S_WRONG;
          }

          switch (buff[0]) {
            case AF_S_CONCLOSED : {
                                    n = numofcon;
                                    numofcon = eval_numofcon(pointer, k, numofcon);
                                    if ((numofcon>=0) && (numofcon<(pointer->usernum)) &&
                                        (ConnectClient_get_state(pointer->clitable[k]) ==
                                         CONNECTCLIENT_STATE_ACCEPTED)) {
                                      pointer->usercon--;
                                      ConnectClient_decrease_connected(pointer->clitable[k]);
                                      ConnectClient_get_users(pointer->clitable[k])[n] = -1;
                                      if (ConnectUser_get_state(pointer->contable[numofcon]) == S_STATE_CLOSING) {
                                        ConnectUser_set_state(pointer->contable[numofcon], S_STATE_CLEAR);
                                        aflog(LOG_T_USER, LOG_I_DEBUG,
                                            "realm[%s]: user[%d]: CLOSE CONFIRMED",
                                            get_realmname(&config, j), get_username(pointer, numofcon));
                                      }
                                      else if ((ConnectUser_get_state(pointer->contable[numofcon]) == S_STATE_OPEN) ||
                                          (ConnectUser_get_state(pointer->contable[numofcon]) == S_STATE_STOPPED)) {
                                        aflog(LOG_T_USER, LOG_I_INFO,
                                            "realm[%s]: user[%d]: KICKED",
                                            get_realmname(&config, j), get_username(pointer, numofcon));
                                        time(&now);
                                        aflog(LOG_T_USER, LOG_I_NOTICE,
                                            "REALM: %s USER: %d IP: %s PORT: %s DURATION: %s",
                                            get_realmname(&config, j),
                                            get_username(pointer, numofcon),
                                            ConnectUser_get_nameBuf(pointer->contable[numofcon]),
                                            ConnectUser_get_portBuf(pointer->contable[numofcon]),
                                            timeperiod(now - ConnectUser_get_connectTime(pointer->contable[numofcon])));
                                        close(ConnectUser_get_connFd(pointer->contable[numofcon]));
                                        FD_CLR(ConnectUser_get_connFd(pointer->contable[numofcon]), &allset);
                                        FD_CLR(ConnectUser_get_connFd(pointer->contable[numofcon]), &wset);
                                        ConnectUser_set_state(pointer->contable[numofcon], S_STATE_CLEAR);
                                        BufList_clear(ConnectUser_get_bufList(pointer->contable[numofcon]));
                                        buff[0] = AF_S_CONCLOSED; /* closing connection */
                                        buff[1] = numofcon >> 8;	/* high bits of user number */
                                        buff[2] = numofcon;		/* low bits of user number */
                                        SslFd_send_message(pointer->type,
                                            ConnectClient_get_sslFd(
                                              pointer->clitable[k]),
                                            buff, 5);
                                      }
                                    }
                                    else {
                                      remove_client(pointer, k, &allset, &wset, &manconnecting);
                                    }
                                    break;
                                  }
            case AF_S_CONOPEN : {
                                  numofcon = eval_numofcon(pointer, k, numofcon);
                                  if ((numofcon>=0) && (numofcon<(pointer->usernum)) &&
                                      (ConnectClient_get_state(pointer->clitable[k]) ==
                                       CONNECTCLIENT_STATE_ACCEPTED)) {
                                    if (ConnectUser_get_state(pointer->contable[numofcon]) == S_STATE_OPENING) {
                                      aflog(LOG_T_USER, LOG_I_INFO,
                                          "realm[%s]: user[%d]: NEW",
                                          get_realmname(&config, j), get_username(pointer, numofcon));
                                      FD_SET(ConnectUser_get_connFd(pointer->contable[numofcon]), &allset);
                                      maxfdp1 = (maxfdp1 > (ConnectUser_get_connFd(pointer->contable[numofcon]) + 1)) ?
                                        maxfdp1 : (ConnectUser_get_connFd(pointer->contable[numofcon]) + 1);
                                      ConnectUser_set_state(pointer->contable[numofcon], S_STATE_OPEN);
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
                                    if ((numofcon>=0) && (numofcon<(pointer->usernum)) &&
                                        (ConnectClient_get_state(pointer->clitable[k]) ==
                                         CONNECTCLIENT_STATE_ACCEPTED)) {
                                      if (ConnectUser_get_state(pointer->contable[numofcon]) == S_STATE_OPENING) {
                                        aflog(LOG_T_USER, LOG_I_INFO,
                                            "realm[%s]: user[%d]: DROPPED",
                                            get_realmname(&config, j), get_username(pointer, numofcon));
                                        pointer->usercon--;
                                        ConnectClient_decrease_connected(pointer->clitable[k]);
                                        ConnectClient_get_users(pointer->clitable[k])[n] = -1;
                                        close(ConnectUser_get_connFd(pointer->contable[numofcon]));
                                        ConnectUser_set_state(pointer->contable[numofcon], S_STATE_CLEAR);
                                      }
                                    }
                                    else {
                                      remove_client(pointer, k, &allset, &wset, &manconnecting);
                                    }
                                    break;
                                  }						    
            case AF_S_MESSAGE : {
                                  if (ConnectClient_get_state(pointer->clitable[k]) !=
                                      CONNECTCLIENT_STATE_ACCEPTED) {
                                    remove_client(pointer, k, &allset, &wset, &manconnecting);
                                    break;
                                  }
                                  if (TYPE_IS_UDP(pointer->type)) { /* udp */
                                    n = SslFd_get_message(pointer->type,
                                        ConnectClient_get_sslFd(
                                          pointer->clitable[k]),
                                        &buff[5], length);
                                  }
                                  else {
                                    n = SslFd_get_message(pointer->type,
                                        ConnectClient_get_sslFd(
                                          pointer->clitable[k]),
                                        buff, length);
                                  }
                                  numofcon = eval_numofcon(pointer, k, numofcon);
                                  if ((numofcon>=0) && (numofcon<(pointer->usernum))) {
                                    if (ConnectUser_get_state(pointer->contable[numofcon]) == S_STATE_OPEN) {
                                      aflog(LOG_T_USER, LOG_I_DEBUG,
                                          "realm[%s]: TO user[%d]: MESSAGE length=%d",
                                          get_realmname(&config, j), get_username(pointer, numofcon), n);
                                      UserStats_add_download(ConnectUser_get_stats(pointer->contable[numofcon]), n);
                                      if (TYPE_IS_UDP(pointer->type)) { /* udp */
                                        buff[1] = AF_S_LOGIN;
                                        buff[2] = AF_S_MESSAGE;
                                        buff[3] = n >> 8; /* high bits of message length */
                                        buff[4] = n;      /* low bits of message length */
                                        sent = write(ConnectUser_get_connFd(pointer->contable[numofcon]), buff, n+5);
                                        if (sent == -1) {
                                          aflog(LOG_T_USER, LOG_I_INFO,
                                              "realm[%s]: user[%d]: CLOSED (write-udp)",
                                              get_realmname(&config, j), get_username(pointer, numofcon));
                                          time(&now);
                                          aflog(LOG_T_USER, LOG_I_NOTICE,
                                              "REALM: %s USER: %d IP: %s PORT: %s DURATION: %s",
                                              get_realmname(&config, j),
                                              get_username(pointer, numofcon),
                                              ConnectUser_get_nameBuf(pointer->contable[numofcon]),
                                              ConnectUser_get_portBuf(pointer->contable[numofcon]),
                                              timeperiod(now - ConnectUser_get_connectTime(pointer->contable[numofcon])));
                                          close(ConnectUser_get_connFd(pointer->contable[numofcon]));
                                          FD_CLR(ConnectUser_get_connFd(pointer->contable[numofcon]), &allset);
                                          FD_CLR(ConnectUser_get_connFd(pointer->contable[numofcon]), &wset);
                                          ConnectUser_set_state(pointer->contable[numofcon], S_STATE_CLOSING);
                                          BufList_clear(ConnectUser_get_bufList(pointer->contable[numofcon]));
                                          buff[0] = AF_S_CONCLOSED; /* closing connection */
                                          buff[1] = numofcon >> 8;	/* high bits of user number */
                                          buff[2] = numofcon;		/* low bits of user number */
                                          SslFd_send_message(pointer->type,
                                              ConnectClient_get_sslFd(
                                                pointer->clitable[k]),
                                              buff, 5);
                                        }
                                      }
                                      else { /* tcp */
                                        sent = write(ConnectUser_get_connFd(pointer->contable[numofcon]), buff, n);
                                        if ((sent > 0) && (sent != n)) {
                                          BufList_insert_back(ConnectUser_get_bufList(pointer->contable[numofcon]),
                                              BufListNode_new_message(sent, n, buff));
                                          ConnectUser_set_state(pointer->contable[numofcon], S_STATE_STOPPED);
                                          FD_SET(ConnectUser_get_connFd(pointer->contable[numofcon]), &wset);
                                          buff[0] = AF_S_DONT_SEND; /* stopping transfer */
                                          buff[1] = numofcon >> 8;	/* high bits of user number */
                                          buff[2] = numofcon;		/* low bits of user number */
                                          aflog(LOG_T_USER, LOG_I_DDEBUG,
                                              "realm[%s]: TO user[%d]: BUFFERING MESSAGE STARTED (%d/%d)",
                                              get_realmname(&config, j), get_username(pointer, numofcon), sent, n);
                                          SslFd_send_message(pointer->type,
                                              ConnectClient_get_sslFd(
                                                pointer->clitable[k]),
                                              buff, 5);
                                        }
                                        else if ((sent == -1) && (errno == EAGAIN)) {
                                          BufList_insert_back(ConnectUser_get_bufList(pointer->contable[numofcon]),
                                              BufListNode_new_message(0, n, buff));
                                          ConnectUser_set_state(pointer->contable[numofcon], S_STATE_STOPPED);
                                          FD_SET(ConnectUser_get_connFd(pointer->contable[numofcon]), &wset);
                                          buff[0] = AF_S_DONT_SEND; /* stopping transfer */
                                          buff[1] = numofcon >> 8;	/* high bits of user number */
                                          buff[2] = numofcon;		/* low bits of user number */
                                          aflog(LOG_T_USER, LOG_I_DDEBUG,
                                              "realm[%s]: TO user[%d]: BUFFERING MESSAGE STARTED (%d/%d)",
                                              get_realmname(&config, j), get_username(pointer, numofcon), sent, n);
                                          SslFd_send_message(pointer->type,
                                              ConnectClient_get_sslFd(
                                                pointer->clitable[k]),
                                              buff, 5);
                                        }
                                        else if (sent == -1) {
                                          aflog(LOG_T_USER, LOG_I_INFO,
                                              "realm[%s]: user[%d]: CLOSED (write-tcp)",
                                              get_realmname(&config, j), get_username(pointer, numofcon));
                                          time(&now);
                                          aflog(LOG_T_USER, LOG_I_NOTICE,
                                              "REALM: %s USER: %d IP: %s PORT: %s DURATION: %s",
                                              get_realmname(&config, j),
                                              get_username(pointer, numofcon),
                                              ConnectUser_get_nameBuf(pointer->contable[numofcon]),
                                              ConnectUser_get_portBuf(pointer->contable[numofcon]),
                                              timeperiod(now - ConnectUser_get_connectTime(pointer->contable[numofcon])));
                                          close(ConnectUser_get_connFd(pointer->contable[numofcon]));
                                          FD_CLR(ConnectUser_get_connFd(pointer->contable[numofcon]), &allset);
                                          FD_CLR(ConnectUser_get_connFd(pointer->contable[numofcon]), &wset);
                                          ConnectUser_set_state(pointer->contable[numofcon], S_STATE_CLOSING);
                                          BufList_clear(ConnectUser_get_bufList(pointer->contable[numofcon]));
                                          buff[0] = AF_S_CONCLOSED; /* closing connection */
                                          buff[1] = numofcon >> 8;	/* high bits of user number */
                                          buff[2] = numofcon;		/* low bits of user number */
                                          SslFd_send_message(pointer->type,
                                              ConnectClient_get_sslFd(
                                                pointer->clitable[k]),
                                              buff, 5);
                                        }
                                      }
                                    }
                                    else if (ConnectUser_get_state(pointer->contable[numofcon]) == S_STATE_STOPPED) {
                                      aflog(LOG_T_USER, LOG_I_DDEBUG,
                                          "realm[%s]: TO user[%d]: BUFFERING MESSAGE (%d)",
                                          get_realmname(&config, j), get_username(pointer, numofcon), n);
                                      if (TYPE_IS_UDP(pointer->type)) { /* udp */
                                        buff[1] = AF_S_LOGIN;
                                        buff[2] = AF_S_MESSAGE;
                                        buff[3] = n >> 8; /* high bits of message length */
                                        buff[4] = n;      /* low bits of message length */
                                        BufList_insert_back(ConnectUser_get_bufList(pointer->contable[numofcon]),
                                            BufListNode_new_message(0, n+5, buff));
                                      }
                                      else {
                                        BufList_insert_back(ConnectUser_get_bufList(pointer->contable[numofcon]),
                                            BufListNode_new_message(0, n, buff));
                                      }
                                    }
                                    else if (ConnectUser_get_state(pointer->contable[numofcon]) == S_STATE_CLOSING) {
                                      aflog(LOG_T_USER, LOG_I_WARNING,
                                          "realm[%s]: TO user[%d]: IGNORED message length=%d",
                                          get_realmname(&config, j), get_username(pointer, numofcon), n);
                                    }
                                    else {
                                      aflog(LOG_T_USER, LOG_I_WARNING,
                                          "realm[%s]: TO user[%d]: user in wrong state - IGNORED",
                                          get_realmname(&config, j), get_username(pointer, numofcon));
                                    }
                                  }
                                  else {
                                      aflog(LOG_T_USER, LOG_I_WARNING,
                                          "realm[%s]: message to non-existing user - IGNORED",
                                          get_realmname(&config, j));
                                  }
                                  break;
                                }
            case AF_S_LOGIN : {
                                if ((ConnectClient_get_state(pointer->clitable[k]) ==
                                      CONNECTCLIENT_STATE_AUTHORIZING) &&
                                    (numofcon==(pointer->pass[0]*256+pointer->pass[1])) &&
                                    (length==(pointer->pass[2]*256+pointer->pass[3]))) {
                                  if (k != pointer->clinum) {
                                    ConnectClient_set_state(pointer->clitable[k], CONNECTCLIENT_STATE_ACCEPTED);
                                    aflog(LOG_T_CLIENT, LOG_I_INFO,
                                        "realm[%s]: Client[%s]: pass ok - ACCESS GRANTED",
                                        get_realmname(&config, j), get_clientname(pointer, k));
                                    buff[0] = AF_S_LOGIN; /* sending message */
                                    buff[1] = ConnectClient_get_limit(
                                        pointer->clitable[k]) >> 8;/* high bits of user number */
                                    buff[2] = ConnectClient_get_limit(
                                        pointer->clitable[k]);     /* low bits of user number */
                                    buff[3] = pointer->type;	/* type of connection */
                                    SslFd_send_message(pointer->type | TYPE_SSL | TYPE_ZLIB,
                                        ConnectClient_get_sslFd(
                                          pointer->clitable[k]),
                                        buff, 5);
                                    manconnecting--;
                                    if (pointer->baseport == 1) {
                                      long tmp_val;
                                      char tmp_tab[6];
                                      if (check_long(
                                            UsrCli_get_listenPortName(
                                              pointer->usrclitable[
                                              ConnectClient_get_usrCliPair(pointer->clitable[k])]),
                                            &tmp_val)) {
                                        aflog(LOG_T_CLIENT, LOG_I_ERR,
                                            "realm[%s]: INVALID listenport - removing Client[%s]",
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
                                      while (ip_listen(ConnectClient_get_listenFdp(pointer->clitable[k]),
                                            UsrCli_get_listenHostName(pointer->usrclitable[
                                              ConnectClient_get_usrCliPair(pointer->clitable[k])]) ?
                                            UsrCli_get_listenHostName(pointer->usrclitable[
                                              ConnectClient_get_usrCliPair(pointer->clitable[k])]) :
                                            pointer->hostname,
                                            tmp_tab, (&(pointer->addrlen)), ipfam)) {
                                        tmp_val = (tmp_val+1)%65536;
                                        memset(tmp_tab, 0, 6);
                                        sprintf(tmp_tab, "%d", (int)tmp_val);
                                      }
                                      FD_SET(ConnectClient_get_listenFd(pointer->clitable[k]), &allset);
                                      maxfdp1 = (maxfdp1>(ConnectClient_get_listenFd(pointer->clitable[k])+1)) ?
                                        maxfdp1 : (ConnectClient_get_listenFd(pointer->clitable[k]) + 1);
                                      aflog(LOG_T_CLIENT, LOG_I_INFO,
                                          "realm[%s]: Client[%s]: listenport=%s",
                                          get_realmname(&config, j), get_clientname(pointer, k), tmp_tab);
                                    }
                                  }
                                  else {
                                    aflog(LOG_T_CLIENT, LOG_I_WARNING,
                                        "realm[%s]: client limit EXCEEDED", get_realmname(&config, j));
                                    buff[0] = AF_S_CANT_OPEN; /* sending message */
                                    SslFd_send_message(pointer->type | TYPE_SSL,
                                        ConnectClient_get_sslFd(
                                          pointer->clitable[k]),
                                        buff, 5);
                                    remove_client(pointer, k, &allset, &wset, &manconnecting);
                                  }
                                }
                                else if ((ConnectClient_get_state(pointer->clitable[k]) ==
                                      CONNECTCLIENT_STATE_ACCEPTED) && (numofcon == 0)) {
                                  n = SslFd_get_message(pointer->type,
                                      ConnectClient_get_sslFd(
                                        pointer->clitable[k]),
                                      buff, length);
                                  buff[n] = 0;
                                  aflog(LOG_T_CLIENT, LOG_I_INFO,
                                      "realm[%s]: Client[%s]: ID received: %s",
                                      get_realmname(&config, j), get_clientname(pointer, k), buff);
                                  ConnectClient_set_sClientId(pointer->clitable[k], (char*) buff);
                                }
                                else {
                                  aflog(LOG_T_CLIENT, LOG_I_ERR,
                                      "realm[%s]: Client[%s]: Wrong password - CLOSING",
                                      get_realmname(&config, j), get_clientname(pointer, k));
                                  buff[0] = AF_S_WRONG; /* sending message */
                                  SslFd_send_message(pointer->type | TYPE_SSL,
                                      ConnectClient_get_sslFd(
                                        pointer->clitable[k]),
                                      buff, 5);
                                  remove_client(pointer, k, &allset, &wset, &manconnecting);
                                }
                                break;
                              }
            case AF_S_DONT_SEND: {
                                   aflog(LOG_T_CLIENT, LOG_I_DEBUG,
                                       "realm[%s]: user[%d]: STOP READING",
                                       get_realmname(&config, j), get_username(pointer, numofcon));
                                   FD_CLR(ConnectUser_get_connFd(pointer->contable[numofcon]), &allset);
                                   break;
                                 }
            case AF_S_CAN_SEND: {
                                  aflog(LOG_T_CLIENT, LOG_I_DEBUG,
                                      "realm[%s]: user[%d]: START READING",
                                      get_realmname(&config, j), get_username(pointer, numofcon));
                                  FD_SET(ConnectUser_get_connFd(pointer->contable[numofcon]), &allset);
                                  break;
                                }
            case AF_S_WRONG: {
                               aflog(LOG_T_CLIENT, LOG_I_ERR,
                                   "realm[%s]: Client[%s]: Wrong message - CLOSING",
                                   get_realmname(&config, j), get_clientname(pointer, k));
                               remove_client(pointer, k, &allset, &wset, &manconnecting);
                               break;
                             }
            case AF_S_ADMIN_LOGIN: {
                                     if ((ConnectClient_get_state(pointer->clitable[k]) ==
                                           CONNECTCLIENT_STATE_AUTHORIZING) &&
                                         (numofcon == (pointer->pass[0]*256 + pointer->pass[1])) &&
                                         (length == (pointer->pass[2]*256 + pointer->pass[3]))) {
                                       aflog(LOG_T_MANAGE, LOG_I_INFO,
                                           "realm[%s]: Client[%s]: NEW remote admin -- pass OK",
                                           get_realmname(&config, j), get_clientname(pointer, k));
                                       for (l = 0; l < pointer->raclinum; ++l) {
                                         if (ConnectClient_get_state(pointer->raclitable[l]) ==
                                             CONNECTCLIENT_STATE_FREE) {
                                           SslFd_set_fd(
                                               ConnectClient_get_sslFd(pointer->raclitable[l]),
                                               SslFd_get_fd(
                                                 ConnectClient_get_sslFd(pointer->clitable[k])));
                                           ConnectClient_set_connectTime(
                                               pointer->raclitable[l],
                                               ConnectClient_get_connectTime(pointer->clitable[k]));
#ifdef HAVE_LIBPTHREAD
                                           ConnectClient_set_tunnelType(
                                               pointer->raclitable[l],
                                               ConnectClient_get_tunnelType(pointer->clitable[k]));
#endif
                                           ConnectClient_set_clientId(
                                               pointer->raclitable[l],
                                               ConnectClient_get_clientId(pointer->clitable[k]));
                                           ConnectClient_set_nameBuf(
                                               pointer->raclitable[l],
                                               ConnectClient_get_nameBuf(pointer->clitable[k]));
                                           ConnectClient_set_portBuf(
                                               pointer->raclitable[l],
                                               ConnectClient_get_portBuf(pointer->clitable[k]));
                                           tmp_ssl = SslFd_get_ssl(
                                               ConnectClient_get_sslFd(pointer->raclitable[l]));
                                           SslFd_set_ssl_nf(
                                               ConnectClient_get_sslFd(pointer->raclitable[l]),
                                               SslFd_get_ssl(
                                                 ConnectClient_get_sslFd(pointer->clitable[k])));
                                           SslFd_set_ssl_nf(
                                               ConnectClient_get_sslFd(pointer->clitable[k]),
                                               tmp_ssl);
                                           ConnectClient_set_state(
                                               pointer->clitable[k],
                                               CONNECTCLIENT_STATE_FREE);
                                           break;
                                         }
                                       }
                                       if (l != pointer->raclinum) {
                                         ConnectClient_set_state(
                                             pointer->raclitable[l],
                                             CONNECTCLIENT_STATE_ACCEPTED);
                                         pointer->raclicon++;
                                         manconnecting--;
                                         sprintf((char*) &buff[5], AF_VER("AFSERVER"));
                                         n = strlen((char*) &buff[5]);
                                         buff[0] = AF_S_ADMIN_LOGIN; /* sending message */
                                         buff[1] = pointer->type;	/* type of connection */
                                         buff[2] = AF_RA_UNDEFINED;
                                         buff[3] = n >> 8; /* high bits of message length */
                                         buff[4] = n;      /* low bits of message length */
                                         SslFd_send_message(pointer->type | TYPE_SSL,
                                             ConnectClient_get_sslFd(
                                               pointer->raclitable[l]),
                                             buff, n+5);
                                       }
                                       else {
                                         aflog(LOG_T_MANAGE, LOG_I_WARNING,
                                             "realm[%s]: Client[%s]: remote admin -- limit EXCEEDED",
                                             get_realmname(&config, j), get_clientname(pointer, k));
                                         buff[0] = AF_S_CANT_OPEN; /* sending message */
                                         SslFd_send_message(pointer->type | TYPE_SSL | TYPE_ZLIB,
                                             ConnectClient_get_sslFd(
                                               pointer->clitable[k]),
                                             buff, 5);
                                         remove_client(pointer, k, &allset, &wset, &manconnecting);
                                       }
                                     }
                                     break;
                                   }
            case AF_S_KEEP_ALIVE: {
                                    aflog(LOG_T_CLIENT, LOG_I_DEBUG,
                                        "realm[%s]: Client[%s]: Keep alive packet",
                                        get_realmname(&config, j), get_clientname(pointer, k));
                                    break;
                                  }
            default : {
                        aflog(LOG_T_CLIENT, LOG_I_ERR,
                            "realm[%s]: Client[%s]: Unrecognized message - CLOSING",
                            get_realmname(&config, j), get_clientname(pointer, k));
                        remove_client(pointer, k, &allset, &wset, &manconnecting);
                      }
          }
        }
      /* ------------------------------------ */
      for (k = 0; k < pointer->raclinum; ++k)
        if ((ConnectClient_get_state(pointer->raclitable[k]) > CONNECTCLIENT_STATE_FREE) &&
            (FD_ISSET(SslFd_get_fd(ConnectClient_get_sslFd(pointer->raclitable[k])), &rset))) {
          if (ConnectClient_get_state(pointer->raclitable[k]) == CONNECTCLIENT_STATE_CONNECTING) {
            make_ssl_initialize(ConnectClient_get_sslFd(pointer->raclitable[k]));
            aflog(LOG_T_MANAGE, LOG_I_DDEBUG,
                "realm[%s]: new Client[%s] (ra): SSL_accept",
                get_realmname(&config, j), get_raclientname(pointer, k));
            switch (make_ssl_accept(ConnectClient_get_sslFd(pointer->raclitable[k]))) {
              case 2: {
                        close (SslFd_get_fd(ConnectClient_get_sslFd(pointer->raclitable[k])));
                        FD_CLR(SslFd_get_fd(ConnectClient_get_sslFd(pointer->raclitable[k])), &allset);
                        SSL_clear(SslFd_get_ssl(ConnectClient_get_sslFd(pointer->raclitable[k])));
                        ConnectClient_set_state(pointer->raclitable[k], CONNECTCLIENT_STATE_FREE);
                        manconnecting--;
                        pointer->clicon--;
                        aflog(LOG_T_MANAGE, LOG_I_ERR,
                            "realm[%s]: new Client[%s] (ra): DENIED by SSL_accept",
                            get_realmname(&config, j), get_raclientname(pointer, k));
                      }
              case 1: {
                        continue;
                      }
              default: {
                         aflog(LOG_T_MANAGE, LOG_I_DEBUG,
                             "realm[%s]: new Client[%s] (ra): ACCEPTED by SSL_accept",
                             get_realmname(&config, j), get_raclientname(pointer, k));
                         ConnectClient_set_state(pointer->raclitable[k], CONNECTCLIENT_STATE_AUTHORIZING);
                         continue;
                       }
            }
          }
          aflog(LOG_T_MANAGE, LOG_I_DDEBUG,
              "realm[%s]: Client[%s] (ra): commfd: FD_ISSET",
              get_realmname(&config, j), get_raclientname(pointer, k));
          n = SslFd_get_message(pointer->type | TYPE_SSL | TYPE_ZLIB,
              ConnectClient_get_sslFd(
                pointer->raclitable[k]),
              buff, (-1) * HeaderBuffer_to_read(ConnectClient_get_header(pointer->raclitable[k])));
          if (n == -1) {
            if (errno == EAGAIN) {
              aflog(LOG_T_MANAGE, LOG_I_DDEBUG,
                  "realm[%s]: Client[%s] (ra): commfd: EAGAIN",
                  get_realmname(&config, j), get_raclientname(pointer, k));
              continue;
            }
            else {
              aflog(LOG_T_MANAGE, LOG_I_ERR,
                  "realm[%s]: Client[%s] (ra): commfd: ERROR: %d",
                  get_realmname(&config, j), get_raclientname(pointer, k), errno);
              n = 0;
            }
          }
          else if (n != 5) {
            if (n != 0) {
              aflog(LOG_T_MANAGE, LOG_I_WARNING,
                  "realm[%s]: Client[%s] (ra): header length = %d --> buffering",
                  get_realmname(&config, j), get_raclientname(pointer, k), n);
              HeaderBuffer_store(ConnectClient_get_header(pointer->raclitable[k]), buff, n);
              if (HeaderBuffer_to_read(ConnectClient_get_header(pointer->raclitable[k])) == 0) {
                HeaderBuffer_restore(ConnectClient_get_header(pointer->raclitable[k]), buff);
                n = 5;
              }
              else {
                continue;
              }
            }
          }
          if (n==0) { 
            remove_raclient(pointer, k, &allset, &wset, &manconnecting);
            aflog(LOG_T_MANAGE, LOG_I_INFO,
                "realm[%s]: Client[%s] (ra): commfd: CLOSED",
                get_realmname(&config, j), get_raclientname(pointer, k));
            continue;
          }

          numofcon = buff[1];
          numofcon = numofcon << 8;
          numofcon += buff[2]; /* this is id of user */
          length = buff[3];
          length = length << 8;
          length += buff[4]; /* this is length of message */ 

          if (ConnectClient_get_state(pointer->raclitable[k]) < CONNECTCLIENT_STATE_AUTHORIZING) {
            aflog(LOG_T_MANAGE, LOG_I_WARNING,
                "realm[%s]: Client[%s] (ra): Impossible behaviour --> ignoring",
                get_realmname(&config, j), get_raclientname(pointer, k));
            continue;
          }
          if ((ConnectClient_get_state(pointer->raclitable[k]) == CONNECTCLIENT_STATE_AUTHORIZING) &&
              (buff[0] != AF_S_LOGIN) && (buff[0] != AF_S_ADMIN_LOGIN)) {
            buff[0] = AF_S_WRONG;
          }

          switch (buff[0]) {
            case AF_S_LOGIN : {
                                if ((ConnectClient_get_state(pointer->raclitable[k]) == 
                                      CONNECTCLIENT_STATE_AUTHORIZING) &&
                                    (numofcon==(pointer->pass[0]*256+pointer->pass[1])) &&
                                    (length==(pointer->pass[2]*256+pointer->pass[3]))) {
                                  for (l = 0; l < pointer->clinum; ++l) {
                                    if (ConnectClient_get_state(pointer->clitable[l]) ==
                                        CONNECTCLIENT_STATE_FREE) {
                                      aflog(LOG_T_MANAGE | LOG_T_CLIENT, LOG_I_INFO,
                                          "realm[%s]: Client[%s] (ra) --> Client[%s]",
                                          get_realmname(&config, j),
                                          get_raclientname(pointer, k), get_clientname(pointer, l));
                                      SslFd_set_fd(
                                          ConnectClient_get_sslFd(pointer->clitable[l]),
                                          SslFd_get_fd(
                                            ConnectClient_get_sslFd(pointer->raclitable[k])));
                                      ConnectClient_set_connectTime(
                                          pointer->clitable[l],
                                          ConnectClient_get_connectTime(pointer->raclitable[k]));
#ifdef HAVE_LIBPTHREAD
                                      ConnectClient_set_tunnelType(
                                          pointer->clitable[l],
                                          ConnectClient_get_tunnelType(pointer->raclitable[k]));
#endif
                                      ConnectClient_set_clientId(
                                          pointer->clitable[l],
                                          ConnectClient_get_clientId(pointer->raclitable[k]));
                                      ConnectClient_set_nameBuf(
                                          pointer->clitable[l],
                                          ConnectClient_get_nameBuf(pointer->raclitable[k]));
                                      ConnectClient_set_portBuf(
                                          pointer->clitable[l],
                                          ConnectClient_get_portBuf(pointer->raclitable[k]));
                                      tmp_ssl = SslFd_get_ssl(
                                          ConnectClient_get_sslFd(pointer->clitable[l]));
                                      SslFd_set_ssl_nf(
                                          ConnectClient_get_sslFd(pointer->clitable[l]),
                                          SslFd_get_ssl(
                                            ConnectClient_get_sslFd(pointer->raclitable[k])));
                                      SslFd_set_ssl_nf(
                                          ConnectClient_get_sslFd(pointer->raclitable[k]),
                                          tmp_ssl);
                                      ConnectClient_set_usrCliPair(
                                          pointer->clitable[l],
                                          ConnectClient_get_usrCliPair(pointer->raclitable[k]));
                                      ConnectClient_set_state(pointer->raclitable[k], CONNECTCLIENT_STATE_FREE);
                                      break;
                                    }
                                  }
                                  if (l != pointer->clinum) {
                                    ConnectClient_set_state(pointer->clitable[l], CONNECTCLIENT_STATE_ACCEPTED);
                                    aflog(LOG_T_CLIENT, LOG_I_INFO,
                                        "realm[%s]: Client[%s]: pass ok - ACCESS GRANTED",
                                        get_realmname(&config, j), get_clientname(pointer, l));
                                    buff[0] = AF_S_LOGIN; /* sending message */
                                    buff[1] = ConnectClient_get_limit(
                                        pointer->clitable[l]) >> 8;/* high bits of user number */
                                    buff[2] = ConnectClient_get_limit(
                                        pointer->clitable[l]);     /* low bits of user number */
                                    buff[3] = pointer->type;	/* type of connection */
                                    SslFd_send_message(pointer->type | TYPE_SSL | TYPE_ZLIB,
                                        ConnectClient_get_sslFd(
                                          pointer->clitable[l]),
                                        buff, 5);
                                    manconnecting--;
                                    if (pointer->baseport == 1) {
                                      long tmp_val;
                                      char tmp_tab[6];
                                      if (check_long(
                                            UsrCli_get_listenPortName(
                                              pointer->usrclitable[
                                              ConnectClient_get_usrCliPair(pointer->clitable[l])]),
                                            &tmp_val)) {
                                        aflog(LOG_T_CLIENT, LOG_I_ERR,
                                            "realm[%s]: INVALID listenport - removing Client[%s]",
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
                                      while (ip_listen(ConnectClient_get_listenFdp(pointer->clitable[l]),
                                            UsrCli_get_listenHostName(pointer->usrclitable[
                                              ConnectClient_get_usrCliPair(pointer->clitable[l])]) ?
                                            UsrCli_get_listenHostName(pointer->usrclitable[
                                              ConnectClient_get_usrCliPair(pointer->clitable[l])]) :
                                            pointer->hostname,
                                            tmp_tab, (&(pointer->addrlen)), ipfam)) {
                                        tmp_val = (tmp_val+1)%65536;
                                        memset(tmp_tab, 0, 6);
                                        sprintf(tmp_tab, "%d", (int)tmp_val);
                                      }
                                      FD_SET(ConnectClient_get_listenFd(pointer->clitable[l]), &allset);
                                      maxfdp1 = (maxfdp1>(ConnectClient_get_listenFd(pointer->clitable[l])+1)) ?
                                        maxfdp1 : (ConnectClient_get_listenFd(pointer->clitable[l])+1);
                                      aflog(LOG_T_CLIENT, LOG_I_INFO,
                                          "realm[%s]: Client[%s]: listenport=%s",
                                          get_realmname(&config, j), get_clientname(pointer, l), tmp_tab);
                                    }
                                  }
                                  else {
                                    aflog(LOG_T_CLIENT, LOG_I_WARNING,
                                        "realm[%s]: client limit EXCEEDED", get_realmname(&config, j));
                                    buff[0] = AF_S_CANT_OPEN; /* sending message */
                                    SslFd_send_message(pointer->type | TYPE_SSL | TYPE_ZLIB,
                                        ConnectClient_get_sslFd(
                                          pointer->raclitable[k]),
                                        buff, 5);
                                    remove_raclient(pointer, k, &allset, &wset, &manconnecting);
                                  }
                                }
                                else if ((ConnectClient_get_state(pointer->raclitable[k]) ==
                                      CONNECTCLIENT_STATE_ACCEPTED) && (numofcon == 0)) {
                                  n = SslFd_get_message(pointer->type,
                                      ConnectClient_get_sslFd(
                                        pointer->raclitable[k]),
                                      buff, length);
                                  buff[n] = 0;
                                  aflog(LOG_T_MANAGE, LOG_I_INFO,
                                      "realm[%s]: Client[%s] (ra): ID received: %s",
                                      get_realmname(&config, j), get_raclientname(pointer, k), buff);
                                  ConnectClient_set_sClientId(pointer->raclitable[k], (char*) buff);
                                }
                                else {
                                  aflog(LOG_T_MANAGE, LOG_I_ERR,
                                      "realm[%s]: Client[%s] (ra): Wrong password - CLOSING",
                                      get_realmname(&config, j), get_raclientname(pointer, k));
                                  remove_raclient(pointer, k, &allset, &wset, &manconnecting);
                                }
                                break;
                              }
            case AF_S_WRONG: {
                               aflog(LOG_T_MANAGE, LOG_I_ERR,
                                   "realm[%s]: Client[%s] (ra): Wrong message - CLOSING",
                                   get_realmname(&config, j), get_raclientname(pointer, k));
                               remove_raclient(pointer, k, &allset, &wset, &manconnecting);
                               break;
                             }
            case AF_S_ADMIN_LOGIN: {
                                     if ((ConnectClient_get_state(pointer->raclitable[k]) ==
                                           CONNECTCLIENT_STATE_AUTHORIZING) &&
                                         (numofcon==(pointer->pass[0]*256+pointer->pass[1])) &&
                                         (length==(pointer->pass[2]*256+pointer->pass[3]))) {
                                       aflog(LOG_T_MANAGE, LOG_I_INFO,
                                           "realm[%s]: Client[%s] (ra): NEW remote admin -- pass OK",
                                           get_realmname(&config, j), get_raclientname(pointer, k));
                                       ConnectClient_set_state(
                                           pointer->raclitable[k],
                                           CONNECTCLIENT_STATE_ACCEPTED);
                                       pointer->raclicon++;
                                       manconnecting--;
                                       sprintf((char*) &buff[5], AF_VER("AFSERVER"));
                                       n = strlen((char*) &buff[5]);
                                       buff[0] = AF_S_ADMIN_LOGIN; /* sending message */
                                       buff[1] = pointer->type;	/* type of connection */
                                       buff[2] = AF_RA_UNDEFINED;
                                       buff[3] = n >> 8; /* high bits of message length */
                                       buff[4] = n;      /* low bits of message length */
                                       SslFd_send_message(pointer->type | TYPE_SSL | TYPE_ZLIB,
                                           ConnectClient_get_sslFd(
                                             pointer->raclitable[k]),
                                           buff, n+5);
                                     }
                                     break;
                                   }
            case AF_S_ADMIN_CMD: {
                                   if (ConnectClient_get_state(pointer->raclitable[k]) ==
                                       CONNECTCLIENT_STATE_ACCEPTED) {
                                     if ((n = serve_admin(&config, j, k, buff))) {
                                       if (n == 1) {
                                         aflog(LOG_T_MANAGE, LOG_I_NOTICE,
                                             "realm[%s]: Client[%s] (ra): remote admin -- closing",
                                             get_realmname(&config, j), get_raclientname(pointer, k));
                                         remove_raclient(pointer, k, &allset, &wset, &manconnecting);
                                       }
                                       else {
                                         for (i = 0; i < config.size; ++i) {
                                           l = get_clientnumber(&(config.realmtable[i]), n-2);
                                           if (l != -1) {
                                             aflog(LOG_T_MANAGE, LOG_I_NOTICE,
                                                 "realm[%s]: Client[%s] (ra): remote admin: KICKING realm[%s]: Client[%s]",
                                                 get_realmname(&config, j), get_raclientname(pointer, k),
                                                 get_realmname(&config, i),
                                                 get_clientname(&(config.realmtable[i]), l));
                                             buff[0] = AF_S_CLOSING; /* closing */
                                             SslFd_send_message(config.realmtable[i].type,
                                                 ConnectClient_get_sslFd(
                                                   config.realmtable[i].clitable[l]),
                                                 buff, 5);
                                             time(&now);
                                             aflog(LOG_T_CLIENT, LOG_I_NOTICE,
                                                 "REALM: %s CLIENT: %s IP: %s PORT: %s DURATION: %s",
                                                 get_realmname(&config, j),
                                                 get_clientname(&(config.realmtable[i]), l),
                                                 ConnectClient_get_nameBuf(config.realmtable[i].clitable[l]),
                                                 ConnectClient_get_portBuf(config.realmtable[i].clitable[l]),
                                                 timeperiod(now - ConnectClient_get_connectTime(
                                                     config.realmtable[i].clitable[l])));
                                             if (config.realmtable[i].audit) {
                                               while (AuditList_get_first(
                                                     ConnectClient_get_auditList(
                                                       config.realmtable[i].clitable[l]))) {
                                                 aflog(LOG_T_CLIENT, LOG_I_NOTICE,
                                                     "USERID: %d IP: %s PORT: %s CONNECTED: %s DURATION: %s",
                                                     AuditListNode_get_userId(
                                                       AuditList_get_first(
                                                         ConnectClient_get_auditList(
                                                           config.realmtable[i].clitable[l]))),
                                                     AuditListNode_get_nameBuf(
                                                       AuditList_get_first(
                                                         ConnectClient_get_auditList(
                                                           config.realmtable[i].clitable[l]))),
                                                     AuditListNode_get_portBuf(
                                                       AuditList_get_first(
                                                         ConnectClient_get_auditList(
                                                           config.realmtable[i].clitable[l]))),
                                                     localdate(
                                                       AuditListNode_get_connectTimep(
                                                         AuditList_get_first(
                                                           ConnectClient_get_auditList(
                                                             config.realmtable[i].clitable[l])))),
                                                     timeperiod(
                                                       AuditListNode_get_duration(
                                                         AuditList_get_first(
                                                           ConnectClient_get_auditList(
                                                             config.realmtable[i].clitable[l])))));
                                                     AuditList_delete_first(
                                                         ConnectClient_get_auditList(
                                                           config.realmtable[i].clitable[l]));
                                               }
                                             }
                                             remove_client(&(config.realmtable[i]), l,
                                                 &allset, &wset, &manconnecting);
                                             break;
                                           }
                                         }
                                       }
                                     }
                                   }
                                   else {
                                     aflog(LOG_T_MANAGE, LOG_I_ERR,
                                         "realm[%s]: Client[%s] (ra): remote admin -- security VIOLATION",
                                         get_realmname(&config, j), get_raclientname(pointer, k));
                                     remove_raclient(pointer, k, &allset, &wset, &manconnecting);
                                   }
                                   break;
                                 }
            case AF_S_KEEP_ALIVE: {
                                    aflog(LOG_T_MANAGE, LOG_I_DEBUG,
                                        "realm[%s]: Client[%s] (ra): Keep alive packet",
                                        get_realmname(&config, j), get_raclientname(pointer, k));
                                    break;
                                  }
            default : {
                        aflog(LOG_T_MANAGE, LOG_I_ERR,
                            "realm[%s]: Client[%s] (ra): Unrecognized message - CLOSING",
                            get_realmname(&config, j), get_raclientname(pointer, k));
                        remove_raclient(pointer, k, &allset, &wset, &manconnecting);
                      }
          }
        }
      /* ------------------------------------ */    
      for (l = 0; l < pointer->usrclinum; ++l) {
        if (FD_ISSET(UsrCli_get_manageFd(pointer->usrclitable[l]), &rset)) {
          aflog(LOG_T_CLIENT, LOG_I_DDEBUG,
              "realm[%s]: managefd: FD_ISSET", get_realmname(&config, j));
          len = pointer->addrlen;
#ifdef HAVE_LIBPTHREAD
          sent = get_new_socket(UsrCli_get_manageFd(pointer->usrclitable[l]),
              pointer->tunneltype,pointer->cliaddr, &len, &tunneltype); 
#else
          sent = accept(UsrCli_get_manageFd(pointer->usrclitable[l]), pointer->cliaddr, &len);
#endif
          if (sent == -1) {
            if (errno == EAGAIN) {
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "realm[%s]: managefd: FD_ISSET --> EAGAIN", get_realmname(&config, j));
            }
            else {
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "realm[%s]: managefd: FD_ISSET --> errno=%d", get_realmname(&config, j), errno);
            }
            continue;
          }
          flags = fcntl(sent, F_GETFL, 0);
          fcntl(sent, F_SETFL, flags | O_NONBLOCK);
          for (k = 0; k < pointer->clinum; ++k) {
            if (ConnectClient_get_state(pointer->clitable[k]) == CONNECTCLIENT_STATE_FREE) {
              ConnectClient_set_clientId(pointer->clitable[k], pointer->clientcounter);
              ++(pointer->clientcounter);
              aflog(LOG_T_CLIENT, LOG_I_INFO,
                  "realm[%s]: new Client[%s]: CONNECTING",
                  get_realmname(&config, j), get_clientname(pointer, k));
              SslFd_set_fd(ConnectClient_get_sslFd(pointer->clitable[k]), sent);
              ConnectClient_set_usrCliPair(pointer->clitable[k], l);
              time(&now);
              ConnectClient_set_connectTime(pointer->clitable[k], now);
#ifdef HAVE_LIBPTHREAD
              ConnectClient_set_tunnelType(pointer->clitable[k], tunneltype);
#endif
              aflog(LOG_T_CLIENT, LOG_I_INFO,
                  "realm[%s]: new Client[%s] IP:%s", get_realmname(&config, j), get_clientname(pointer, k),
                  sock_ntop(pointer->cliaddr, len, ConnectClient_get_nameBuf(pointer->clitable[k]),
                    ConnectClient_get_portBuf(pointer->clitable[k]), pointer->dnslookups));
              FD_SET(SslFd_get_fd(ConnectClient_get_sslFd(pointer->clitable[k])), &allset);
              maxfdp1 = (maxfdp1 > (SslFd_get_fd(ConnectClient_get_sslFd(pointer->clitable[k])) + 1)) ?
                maxfdp1 : (SslFd_get_fd(ConnectClient_get_sslFd(pointer->clitable[k])) + 1);
              pointer->clicon++;
              ConnectClient_set_timer(pointer->clitable[k], timeval_create(pointer->tmout, 0));
              manconnecting++;
              ConnectClient_set_state(pointer->clitable[k], CONNECTCLIENT_STATE_CONNECTING);
              break;
            }
          }
          if (k == pointer->clinum) {
            for (k = 0; k < pointer->raclinum; ++k) {
              if (ConnectClient_get_state(pointer->raclitable[k]) ==
                  CONNECTCLIENT_STATE_FREE) {
                ConnectClient_set_clientId(pointer->raclitable[k], pointer->clientcounter);
                ++(pointer->clientcounter);
                aflog(LOG_T_MANAGE, LOG_I_INFO,
                    "realm[%s]: new Client[%s] (ra): CONNECTING",
                    get_realmname(&config, j), get_raclientname(pointer, k));
                SslFd_set_fd(ConnectClient_get_sslFd(pointer->raclitable[k]), sent);
                ConnectClient_set_usrCliPair(pointer->raclitable[k], l);
                time(&now);
                ConnectClient_set_connectTime(pointer->raclitable[k], now);
#ifdef HAVE_LIBPTHREAD
                ConnectClient_set_tunnelType(pointer->raclitable[k], tunneltype);
#endif
                aflog(LOG_T_MANAGE, LOG_I_INFO,
                    "realm[%s]: new Client[%s] (ra) IP:%s",
                    get_realmname(&config, j), get_raclientname(pointer, k),
                    sock_ntop(pointer->cliaddr, len, ConnectClient_get_nameBuf(pointer->raclitable[k]),
                      ConnectClient_get_portBuf(pointer->raclitable[k]), pointer->dnslookups));
                FD_SET(SslFd_get_fd(ConnectClient_get_sslFd(pointer->raclitable[k])), &allset);
                maxfdp1 = (maxfdp1 > (SslFd_get_fd(ConnectClient_get_sslFd(pointer->raclitable[k])) + 1)) ?
                  maxfdp1 : (SslFd_get_fd(ConnectClient_get_sslFd(pointer->raclitable[k])) + 1);
                pointer->clicon++;
                ConnectClient_set_timer(pointer->raclitable[k], timeval_create(pointer->tmout, 0));
                manconnecting++;
                ConnectClient_set_state(pointer->raclitable[k], CONNECTCLIENT_STATE_CONNECTING);
                break;
              }
            }
            if (k == pointer->raclinum) {
              aflog(LOG_T_CLIENT | LOG_T_MANAGE, LOG_I_WARNING,
                  "realm[%s]: client limit EXCEEDED", get_realmname(&config, j));
              close(sent);
            }
          }
        }
      }
    } /* realms loop */
  }
}
