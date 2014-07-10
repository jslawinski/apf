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

#include "afserver.h"

static struct option long_options[] = {
	{"help", 0, 0, 'h'},
	{"hostname", 1, 0, 'n'},
	{"listenport", 1, 0, 'l'},
	{"manageport", 1, 0, 'm'},
	{"timeout", 1, 0, 't'},
	{"maxidle", 1, 0, 321},
	{"verbose", 0, 0, 'v'},
	{"users", 1, 0, 'u'},
	{"clients", 1, 0, 'C'},
	{"realm", 1, 0, 'r'},
	{"raclients", 1, 0, 'R'},
	{"usrpcli", 1, 0, 'U'},
	{"climode", 1, 0, 'M'},
	{"cerfile", 1, 0, 'c'},
	{"cacerfile", 1, 0, 'A'},
	{"cerdepth", 1, 0, 'd'},
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

ServerConfiguration* config;

int
main(int argc, char **argv)
{
	int	i, j=0, k, l, n, flags, sent = 0, temp;
	socklen_t	len;
	unsigned char				buff[9000];
	int			maxfdp1;
	fd_set		rset, allset, wset, tmpset;
	int numofcon, length;
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
	char* maxidle = NULL;
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
	ServerRealm* pointer = NULL;
  TaskScheduler* scheduler;
  Task* task;
	struct sigaction act;
  time_t now;
  ServerRealm** scRealmsTable;
  UsrCli** srUsersClientsTable;
  ConnectUser** srUsersTable;
  ConnectClient** srClientsTable;
  ConnectClient** srRaClientsTable;

  char* certif = NULL;
  char* cacertif = NULL;
  char* cerdepth = NULL;
  char* keys = NULL;
  char* dateformat = NULL;
  static char* stemp = NULL;

	SSL_METHOD* method;
	SSL_CTX* ctx;
  SSL* tmp_ssl;
	
	sigfillset(&(act.sa_mask));
	act.sa_flags = 0;
	
	act.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &act, NULL);
	act.sa_handler = server_sig_int;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	
	TYPE_SET_SSL(mode);
	TYPE_SET_ZLIB(mode);
  TYPE_SET_SUPPORTED_MULTI(mode);
  
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
          GETOPT_LONG_LIBPTHREAD(GETOPT_LONG_AF_INET6("hn:l:m:vu:c:A:d:k:f:p:o:t:C:U:M:abD:R:r:V"))
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
      case 321: {
                  maxidle = optarg;
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
      case 'A': {
                  cacertif = optarg;
                  break;
                }
      case 'd': {
                  cerdepth = optarg;
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
        if (ServerConfiguration_get_certificateFile(config) == NULL) {
          ServerConfiguration_set_certificateFile(config, "server-cert.pem");
        }
      }
      else {
        ServerConfiguration_set_certificateFile(config, certif);
      }
      if (cacertif != NULL) {
        ServerConfiguration_set_cacertificateFile(config, cacertif);
      }
      if (cerdepth != NULL) {
          ServerConfiguration_set_sCertificateDepth(config, cerdepth);
      }
      if (keys == NULL) {
        if (ServerConfiguration_get_keysFile(config) == NULL) {
          ServerConfiguration_set_keysFile(config, "server.rsa");
        }
      }
      else {
        ServerConfiguration_set_keysFile(config, keys);
      }
      if (dateformat != NULL) {
        ServerConfiguration_set_dateFormat(config, dateformat);
      }
     
      initializelogging(verbose, ServerConfiguration_get_dateFormat(config));
      
      aflog(LOG_T_INIT, LOG_I_INFO,
          "cfg file OK! (readed realms: %d)", ServerConfiguration_get_realmsNumber(config));
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
    config = ServerConfiguration_new();
    if (config == NULL) {
      printf("Can't allocate memory for server configuration... exiting\n");
      exit(1);
    }
    ServerConfiguration_set_certificateFile(config, certif);
    ServerConfiguration_set_cacertificateFile(config, cacertif);
    ServerConfiguration_set_sCertificateDepth(config, cerdepth);
    ServerConfiguration_set_keysFile(config, keys);
    ServerConfiguration_set_dateFormat(config, dateformat);

    initializelogging(verbose, ServerConfiguration_get_dateFormat(config));
    
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
    if (ServerConfiguration_get_certificateFile(config) == NULL) {
      ServerConfiguration_set_certificateFile(config, "server-cert.pem");
    }
    if (ServerConfiguration_get_keysFile(config) == NULL) {
      ServerConfiguration_set_keysFile(config, "server.rsa");
    }
		if (type == NULL) {
			type = "tcp";
		}
    ServerConfiguration_set_realmsNumber(config, 1);
    scRealmsTable = calloc(1, sizeof(ServerRealm*));
    if (scRealmsTable == NULL) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "Problem with allocating memory for ServerRealm* table... exiting");
      exit(1);
    }
    ServerConfiguration_set_realmsTable(config, scRealmsTable);
    pointer = ServerRealm_new();
    if (pointer == NULL) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "Problem with allocating memory for ServerRealm structure... exiting");
      exit(1);
    }
    scRealmsTable[0] = pointer;
    ServerRealm_set_hostName(pointer, name);
    ServerRealm_set_userClientPairs(pointer, managecount);
    srUsersClientsTable = calloc(managecount, sizeof(UsrCli*));
    if (srUsersClientsTable == NULL) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "Problem with allocating memory for UsrCli* table... exiting");
      exit(1);
    }
    ServerRealm_set_usersClientsTable(pointer, srUsersClientsTable);
    for (i = 0; i < managecount; ++i) {
      srUsersClientsTable[i] = UsrCli_new();
      if (srUsersClientsTable[i] == NULL) {
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "Problem with allocating memory for UsrCli structure... exiting");
        exit(1);
      }
      UsrCli_set_listenPortName(srUsersClientsTable[i], listen[i]);
      UsrCli_set_managePortName(srUsersClientsTable[i], manage[i]);
    }
    ServerRealm_set_sUsersLimit(pointer, amount);
    ServerRealm_set_sClientsLimit(pointer, clients);
    ServerRealm_set_sRaClientsLimit(pointer, raclients);
    ServerRealm_set_sTimeout(pointer, timeout);
    ServerRealm_set_sMaxIdle(pointer, maxidle);
    ServerRealm_set_sUsersPerClient(pointer, usrpcli);
    ServerRealm_set_sClientMode(pointer, clim);
    ServerRealm_set_basePortOn(pointer, baseport);
    ServerRealm_set_auditOn(pointer, audit);
#ifdef HAVE_LIBPTHREAD
    ServerRealm_set_tunnelType(pointer, tunneltype);
#endif
    ServerRealm_set_dnsLookupsOn(pointer, dnslookups);
    ServerRealm_set_realmName(pointer, realmname);
    ServerRealm_set_password(pointer, pass);
		if (strcmp(type, "tcp") == 0) {
      temp = ServerRealm_get_realmType(pointer);
			TYPE_SET_TCP(temp);
      ServerRealm_set_realmType(pointer, temp);
		}
		else if (strcmp(type, "udp") == 0) {
      temp = ServerRealm_get_realmType(pointer);
			TYPE_SET_UDP(temp);
      ServerRealm_set_realmType(pointer, temp);
		}
		else {
      temp = ServerRealm_get_realmType(pointer);
			TYPE_SET_ZERO(temp);
      ServerRealm_set_realmType(pointer, temp);
		}
#ifdef AF_INET6
		if (ipfam == -1) {
			aflog(LOG_T_INIT, LOG_I_CRIT,
          "Conflicting types of ip protocol family... exiting");
			exit(1);
		}
		else if (ipfam == 4) {
      temp = ServerRealm_get_realmType(pointer);
			TYPE_SET_IPV4(temp);
      ServerRealm_set_realmType(pointer, temp);
		}
		else if (ipfam == 6) {
      temp = ServerRealm_get_realmType(pointer);
			TYPE_SET_IPV6(temp);
      ServerRealm_set_realmType(pointer, temp);
		}
#endif
    temp = ServerRealm_get_realmType(pointer);
		temp |= mode;
    ServerRealm_set_realmType(pointer, temp);
	}
  
	maxfdp1 = 0;
	
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
  keys = ServerConfiguration_get_keysFile(config);
  if ((flags = generate_rsa_key(&keys))) {
    aflog(LOG_T_INIT, LOG_I_WARNING,
        "Warning: Something bad happened when generating rsa keys... (%d)", flags);
  }
  ServerConfiguration_set_keysFile(config, keys);
	if (SSL_CTX_use_RSAPrivateKey_file(ctx, ServerConfiguration_get_keysFile(config), SSL_FILETYPE_PEM) != 1) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "Setting rsa key failed (%s)... exiting", ServerConfiguration_get_keysFile(config));
    exit(1);
  }
  certif = ServerConfiguration_get_certificateFile(config);
  if ((flags = generate_certificate(&certif, ServerConfiguration_get_keysFile(config)))) {
    aflog(LOG_T_INIT, LOG_I_WARNING,
        "Warning: Something bad happened when generating certificate... (%d)", flags);
  }
  ServerConfiguration_set_certificateFile(config, certif);
	if (SSL_CTX_use_certificate_file(ctx,
        ServerConfiguration_get_certificateFile(config), SSL_FILETYPE_PEM) != 1) {
		aflog(LOG_T_INIT, LOG_I_CRIT,
        "Setting certificate failed (%s)... exiting", ServerConfiguration_get_certificateFile(config));
		exit(1);
	}

        cacertif = ServerConfiguration_get_cacertificateFile(config);
        if (cacertif) {
          if (SSL_CTX_load_verify_locations(ctx,
                                            cacertif,
                                            NULL)
              != 1)
          {
            aflog(LOG_T_INIT, LOG_I_CRIT,
                  "Setting CA certificate failed (%s)... exiting", cacertif);
            exit(1);
          }

          SSL_CTX_set_verify (ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                              NULL);

          cerdepth = ServerConfiguration_get_sCertificateDepth (config);
          if (cerdepth == NULL) {
              cerdepth = "9";
          }
          SSL_CTX_set_verify_depth(ctx, check_value_liberal (cerdepth, "Invalid max certificate-depth"));
        }

	if (ServerConfiguration_get_realmsNumber(config) == 0) {
		aflog(LOG_T_INIT, LOG_I_CRIT,
        "Working without sense is really without sense...");
		exit(1);
	}
	
	FD_ZERO(&allset);
	FD_ZERO(&wset);
	
	if (!verbose)
		daemon(0, 0);

  scheduler = TaskScheduler_new();
  if (scheduler == NULL) {
		aflog(LOG_T_INIT, LOG_I_CRIT,
        "Problems with creating task scheduler... exiting");
		exit(1);
  }
  
  scRealmsTable = ServerConfiguration_get_realmsTable(config);
	for (i = 0; i < ServerConfiguration_get_realmsNumber(config); ++i) {
    if (ServerRealm_get_userClientPairs(scRealmsTable[i]) == 0) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "You have to specify at least one listen port and one manage port in each realm");
      exit(1);
    }
    srUsersClientsTable = ServerRealm_get_usersClientsTable(scRealmsTable[i]);
    for (j = 0; j < ServerRealm_get_userClientPairs(scRealmsTable[i]); ++j) {
  		if ((UsrCli_get_listenPortName(srUsersClientsTable[j]) == NULL) ||
  			(UsrCli_get_managePortName(srUsersClientsTable[j]) == NULL)) {
  			aflog(LOG_T_INIT, LOG_I_CRIT,
            "Missing some of the variables...\nRealm: %d\nlistenport[%d]: %s\nmanageport[%d]: %s",
  					i, j, UsrCli_get_listenPortName(srUsersClientsTable[j]),
  					j, UsrCli_get_managePortName(srUsersClientsTable[j]));
  			exit(1);
  		}
    }
    /* checking type of the realm */
    if (!TYPE_IS_SET(ServerRealm_get_realmType(scRealmsTable[i]))) {
      if (type != NULL) {
        if (strcmp(type, "tcp") == 0) {
          temp = ServerRealm_get_realmType(scRealmsTable[i]);
          TYPE_SET_TCP(temp);
          ServerRealm_set_realmType(scRealmsTable[i], temp);
        }
        else if (strcmp(type, "udp") == 0) {
          temp = ServerRealm_get_realmType(scRealmsTable[i]);
          TYPE_SET_UDP(temp);
          ServerRealm_set_realmType(scRealmsTable[i], temp);
        }
        else {
          temp = ServerRealm_get_realmType(scRealmsTable[i]);
          TYPE_SET_TCP(temp);
          ServerRealm_set_realmType(scRealmsTable[i], temp);
        }
      }
      else {
        temp = ServerRealm_get_realmType(scRealmsTable[i]);
        TYPE_SET_TCP(temp);
        ServerRealm_set_realmType(scRealmsTable[i], temp);
      }
    }
#ifdef AF_INET6
    /* using user's value for ipfam*/
    if (TYPE_IS_UNSPEC(ServerRealm_get_realmType(scRealmsTable[i]))) {
      if (ipfam == -1) {
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "Conflicting types of ip protocol family... exiting");
        exit(1);
      }
      else if (ipfam == 4) {
        temp = ServerRealm_get_realmType(scRealmsTable[i]);
        TYPE_SET_IPV4(temp);
        ServerRealm_set_realmType(scRealmsTable[i], temp);
      }
      else if (ipfam == 6) {
        temp = ServerRealm_get_realmType(scRealmsTable[i]);
        TYPE_SET_IPV6(temp);
        ServerRealm_set_realmType(scRealmsTable[i], temp);
      }
    }
#endif
    /* using user's values for zlib and ssl mode*/
    if (!TYPE_IS_SSL(mode)) {
      temp = ServerRealm_get_realmType(scRealmsTable[i]);
      TYPE_UNSET_SSL(temp);
      ServerRealm_set_realmType(scRealmsTable[i], temp);
    }
    if (!TYPE_IS_ZLIB(mode)) {
      temp = ServerRealm_get_realmType(scRealmsTable[i]);
      TYPE_UNSET_ZLIB(temp);
      ServerRealm_set_realmType(scRealmsTable[i], temp);
    }
    /* using user's baseport value*/
    if (ServerRealm_get_basePortOn(scRealmsTable[i]) == 0) {
      ServerRealm_set_basePortOn(scRealmsTable[i], baseport);
    }
    /* using user's audit value*/
    if (ServerRealm_get_auditOn(scRealmsTable[i]) == 0) {
      ServerRealm_set_auditOn(scRealmsTable[i], audit);
    }
#ifdef HAVE_LIBPTHREAD
    /* using user's tunneltype value*/
    if (ServerRealm_get_tunnelType(scRealmsTable[i]) == 0) {
      if (tunneltype == -1) {
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "Conflicting types of tunnel type... exiting");
        exit(1);
      }
      ServerRealm_set_tunnelType(scRealmsTable[i], tunneltype);
    }
#endif
    /* using user's dnslookups value*/
    if (ServerRealm_get_dnsLookupsOn(scRealmsTable[i]) == 0) {
      ServerRealm_set_dnsLookupsOn(scRealmsTable[i], dnslookups);
    }
    /* checking users amount */
    stemp = ServerRealm_get_sUsersLimit(scRealmsTable[i]);
    set_value(&stemp, amount, "5");
    ServerRealm_set_sUsersLimit(scRealmsTable[i], stemp);
    ServerRealm_set_usersLimit(scRealmsTable[i],
        check_value(ServerRealm_get_sUsersLimit(scRealmsTable[i]), "Invalid users amount"));
    /* checking clients amount */
    stemp = ServerRealm_get_sClientsLimit(scRealmsTable[i]);
    set_value(&stemp, clients, "1");
    ServerRealm_set_sClientsLimit(scRealmsTable[i], stemp);
    ServerRealm_set_clientsLimit(scRealmsTable[i],
        check_value(ServerRealm_get_sClientsLimit(scRealmsTable[i]), "Invalid clients amount"));
    /* checking raclients amount */
    stemp = ServerRealm_get_sRaClientsLimit(scRealmsTable[i]);
    set_value(&stemp, raclients, "1");
    ServerRealm_set_sRaClientsLimit(scRealmsTable[i], stemp);
    ServerRealm_set_raClientsLimit(scRealmsTable[i],
        check_value(ServerRealm_get_sRaClientsLimit(scRealmsTable[i]), "Invalid raclients amount"));
    /* checking usrpcli value */
    stemp = ServerRealm_get_sUsersPerClient(scRealmsTable[i]);
    set_value(&stemp, usrpcli, ServerRealm_get_sUsersLimit(scRealmsTable[i]));
    ServerRealm_set_sUsersPerClient(scRealmsTable[i], stemp);
    ServerRealm_set_usersPerClient(scRealmsTable[i],
        check_value(ServerRealm_get_sUsersPerClient(scRealmsTable[i]), "Invalid usrpcli value"));
    /* checking timeout value */
    stemp = ServerRealm_get_sTimeout(scRealmsTable[i]);
    set_value(&stemp, timeout, "5");
    ServerRealm_set_sTimeout(scRealmsTable[i], stemp);
    ServerRealm_set_timeout(scRealmsTable[i],
        check_value(ServerRealm_get_sTimeout(scRealmsTable[i]), "Invalid timeout value"));
    /* checking maxidle value */
    stemp = ServerRealm_get_sMaxIdle(scRealmsTable[i]);
    set_value(&stemp, maxidle, "0");
    ServerRealm_set_sMaxIdle(scRealmsTable[i], stemp);
    temp = check_value_liberal(ServerRealm_get_sMaxIdle(scRealmsTable[i]), "Invalid maxidle value");
    if (temp < 0) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "Invalid maxidle value: %d\n", temp);
      exit(1);
    }
    ServerRealm_set_maxIdle(scRealmsTable[i], temp);
    /* checking climode value */
    stemp = ServerRealm_get_sClientMode(scRealmsTable[i]);
    set_value(&stemp, clim, "1");
    ServerRealm_set_sClientMode(scRealmsTable[i], stemp);
    ServerRealm_set_clientMode(scRealmsTable[i],
        check_value(ServerRealm_get_sClientMode(scRealmsTable[i]), "Invalid climode value"));
    /* allocating memory*/
    srUsersTable = calloc(ServerRealm_get_usersLimit(scRealmsTable[i]), sizeof(ConnectUser*));
		if (srUsersTable == NULL) {
			aflog(LOG_T_INIT, LOG_I_CRIT,
          "Calloc error - try define smaller amount of users");
			exit(1);
		}
    ServerRealm_set_usersTable(scRealmsTable[i], srUsersTable);
    for (j = 0; j < ServerRealm_get_usersLimit(scRealmsTable[i]); ++j) {
      srUsersTable[j] = ConnectUser_new();
      if (srUsersTable[j] == NULL) {
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "Calloc error - try define smaller amount of users");
        exit(1);
      }
    }
    srClientsTable = calloc(ServerRealm_get_clientsLimit(scRealmsTable[i]), sizeof(ConnectClient*));
		if (srClientsTable == NULL) {
			aflog(LOG_T_INIT, LOG_I_CRIT,
          "Calloc error - try define smaller amount of clients");
			exit(1);
		}
    ServerRealm_set_clientsTable(scRealmsTable[i], srClientsTable);
    for (j = 0; j < ServerRealm_get_clientsLimit(scRealmsTable[i]); ++j) {
      srClientsTable[j] = ConnectClient_new();
      if (srClientsTable[j] == NULL) {
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "Calloc error - try define smaller amount of clients");
        exit(1);
      }
    }
    srRaClientsTable = calloc(ServerRealm_get_raClientsLimit(scRealmsTable[i]), sizeof(ConnectClient*));
		if (srRaClientsTable == NULL) {
			aflog(LOG_T_INIT, LOG_I_CRIT,
          "Calloc error - try define smaller amount of raclients");
			exit(1);
		}
    ServerRealm_set_raClientsTable(scRealmsTable[i], srRaClientsTable);
    for (j = 0; j < ServerRealm_get_raClientsLimit(scRealmsTable[i]); ++j) {
      srRaClientsTable[j] = ConnectClient_new();
      if (srRaClientsTable[j] == NULL) {
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "Calloc error - try define smaller amount of raclients");
        exit(1);
      }
    }
		ipfam = 0x01;
#ifdef AF_INET6
		if (TYPE_IS_IPV4(ServerRealm_get_realmType(scRealmsTable[i]))) {
			ipfam |= 0x02;
		}
		else if (TYPE_IS_IPV6(ServerRealm_get_realmType(scRealmsTable[i]))) {
			ipfam |= 0x04;
		}
#endif
    if (ServerRealm_get_basePortOn(scRealmsTable[i]) == 0) {
      for (j = 0; j < ServerRealm_get_userClientPairs(scRealmsTable[i]); ++j) {
        if (ip_listen(&temp, UsrCli_get_listenHostName(srUsersClientsTable[j]) ?
              UsrCli_get_listenHostName(srUsersClientsTable[j]) :
              ServerRealm_get_hostName(scRealmsTable[i]),
              UsrCli_get_listenPortName(srUsersClientsTable[j]),
              (&len), ipfam)) {
          aflog(LOG_T_INIT, LOG_I_CRIT,
#ifdef AF_INET6
              "tcp_listen_%s error for %s, %s",
              (ipfam & 0x02)?"ipv4":(ipfam & 0x04)?"ipv6":"unspec",
#else
              "tcp_listen error for %s, %s",
#endif
              UsrCli_get_listenHostName(srUsersClientsTable[j]) ?
              UsrCli_get_listenHostName(srUsersClientsTable[j]) :
              ServerRealm_get_hostName(scRealmsTable[i]),
              UsrCli_get_listenPortName(srUsersClientsTable[j]));
          exit(1);
        }
        ServerRealm_set_addressLength(scRealmsTable[i], len);
        UsrCli_set_listenFd(srUsersClientsTable[j], temp);
        flags = fcntl(UsrCli_get_listenFd(srUsersClientsTable[j]), F_GETFL, 0);
        fcntl(UsrCli_get_listenFd(srUsersClientsTable[j]), F_SETFL, flags | O_NONBLOCK);
      }
    }
    
    for (j = 0; j < ServerRealm_get_userClientPairs(scRealmsTable[i]); ++j) {
      switch (ServerRealm_get_tunnelType(scRealmsTable[i])) {
        case 0: {
                  temp = find_previousFd(srUsersClientsTable, j,
                      UsrCli_get_manageHostName(srUsersClientsTable[j]),
                      UsrCli_get_managePortName(srUsersClientsTable[j]));
                  if (temp == -1) {
                    if (ip_listen(&temp, UsrCli_get_manageHostName(srUsersClientsTable[j]) ?
                          UsrCli_get_manageHostName(srUsersClientsTable[j]) :
                          ServerRealm_get_hostName(scRealmsTable[i]),
                          UsrCli_get_managePortName(srUsersClientsTable[j]),
                          (&len), ipfam)) {
                      aflog(LOG_T_INIT, LOG_I_CRIT,
#ifdef AF_INET6
                          "tcp_listen_%s error for %s, %s",
                          (ipfam & 0x02)?"ipv4":(ipfam & 0x04)?"ipv6":"unspec",
#else
                          "tcp_listen error for %s, %s",
#endif
                          UsrCli_get_manageHostName(srUsersClientsTable[j]) ?
                          UsrCli_get_manageHostName(srUsersClientsTable[j]) :
                          ServerRealm_get_hostName(scRealmsTable[i]),
                          UsrCli_get_managePortName(srUsersClientsTable[j]));
                      exit(1);
                    }
                  }
                  ServerRealm_set_addressLength(scRealmsTable[i], len);
                  UsrCli_set_manageFd(srUsersClientsTable[j], temp);
                  flags = fcntl(UsrCli_get_manageFd(srUsersClientsTable[j]), F_GETFL, 0);
                  fcntl(UsrCli_get_manageFd(srUsersClientsTable[j]), F_SETFL, flags | O_NONBLOCK);
                  UsrCli_set_number(srUsersClientsTable[j], eval_UsrCliPair(srUsersClientsTable, j,
                        UsrCli_get_manageHostName(srUsersClientsTable[j]),
                        UsrCli_get_managePortName(srUsersClientsTable[j])));
                  break;
                }
#ifdef HAVE_LIBPTHREAD
        case 1:
        case 2: {
                  temp = find_previousFd(srUsersClientsTable, j,
                      UsrCli_get_manageHostName(srUsersClientsTable[j]),
                      UsrCli_get_managePortName(srUsersClientsTable[j]));
                  if (temp == -1) {
                    if (initialize_http_proxy_server(&temp,
                          UsrCli_get_manageHostName(srUsersClientsTable[j]) ?
                          UsrCli_get_manageHostName(srUsersClientsTable[j]) :
                          ServerRealm_get_hostName(scRealmsTable[i]),
                          UsrCli_get_managePortName(srUsersClientsTable[j]),
                          (&len), ipfam,
                          ServerRealm_get_clientsLimit(scRealmsTable[i]) +
                          ServerRealm_get_raClientsLimit(scRealmsTable[i]),
                          (ServerRealm_get_tunnelType(scRealmsTable[i]) - 1),
                          ctx)) {
                      aflog(LOG_T_INIT, LOG_I_CRIT,
#ifdef AF_INET6
                          "http%s_proxy_listen_%s error for %s, %s",
                          (ServerRealm_get_tunnelType(scRealmsTable[i]) == 2) ? "s" : "",
                          (ipfam & 0x02)?"ipv4":(ipfam & 0x04)?"ipv6":"unspec",
#else
                          "http%s_proxy_listen error for %s, %s",
                          (ServerRealm_get_tunnelType(scRealmsTable[i]) == 2) ? "s" : "",
#endif
                          UsrCli_get_manageHostName(srUsersClientsTable[j]) ?
                          UsrCli_get_manageHostName(srUsersClientsTable[j]) :
                          ServerRealm_get_hostName(scRealmsTable[i]),
                          UsrCli_get_managePortName(srUsersClientsTable[j]));
                      exit(1);
                    }
                  }
                  ServerRealm_set_addressLength(scRealmsTable[i], len);
                  UsrCli_set_manageFd(srUsersClientsTable[j], temp);
                  flags = fcntl(UsrCli_get_manageFd(srUsersClientsTable[j]), F_GETFL, 0);
                  fcntl(UsrCli_get_manageFd(srUsersClientsTable[j]), F_SETFL, flags | O_NONBLOCK);
                  UsrCli_set_number(srUsersClientsTable[j], eval_UsrCliPair(srUsersClientsTable, j,
                        UsrCli_get_manageHostName(srUsersClientsTable[j]),
                        UsrCli_get_managePortName(srUsersClientsTable[j])));
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

    ServerRealm_set_clientAddress(scRealmsTable[i], malloc(ServerRealm_get_addressLength(scRealmsTable[i])));
    if (ServerRealm_get_clientAddress(scRealmsTable[i]) == NULL) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "Allocating memory for client addresses failed... exiting");
      exit(1);
    }
		
    for (j = 0; j < ServerRealm_get_clientsLimit(scRealmsTable[i]); ++j) {
      SslFd_set_ssl(ConnectClient_get_sslFd(srClientsTable[j]), SSL_new(ctx));
  		if (SslFd_get_ssl(ConnectClient_get_sslFd(srClientsTable[j])) == NULL) {
  			aflog(LOG_T_INIT, LOG_I_CRIT,
            "Creation of ssl object failed... exiting");
  			exit(1);
  		}
    }
    
    for (j = 0; j < ServerRealm_get_raClientsLimit(scRealmsTable[i]); ++j) {
      SslFd_set_ssl(ConnectClient_get_sslFd(srRaClientsTable[j]), SSL_new(ctx));
  		if (SslFd_get_ssl(ConnectClient_get_sslFd(srRaClientsTable[j])) == NULL) {
  			aflog(LOG_T_INIT, LOG_I_CRIT,
            "Creation of ssl object failed... exiting");
  			exit(1);
  		}
    }
	
    for (j = 0; j < ServerRealm_get_userClientPairs(scRealmsTable[i]); ++j) {
  		FD_SET(UsrCli_get_manageFd(srUsersClientsTable[j]), &allset);
  		maxfdp1 = (maxfdp1 > (UsrCli_get_manageFd(srUsersClientsTable[j]) + 1)) ?
        maxfdp1 : (UsrCli_get_manageFd(srUsersClientsTable[j]) + 1);
    }
    if (ServerRealm_get_basePortOn(scRealmsTable[i]) == 0) {
      for (j = 0; j < ServerRealm_get_userClientPairs(scRealmsTable[i]); ++j) {
  		  FD_SET(UsrCli_get_listenFd(srUsersClientsTable[j]), &allset);
  		  maxfdp1 = (maxfdp1 > (UsrCli_get_listenFd(srUsersClientsTable[j]) + 1)) ?
          maxfdp1 : (UsrCli_get_listenFd(srUsersClientsTable[j]) + 1);
      }
    }
    ServerRealm_set_connectedUsers(scRealmsTable[i], 0);
    ServerRealm_set_connectedClients(scRealmsTable[i], 0);
    ServerRealm_set_connectedRaClients(scRealmsTable[i], 0);
    for (j = 0; j < ServerRealm_get_clientsLimit(scRealmsTable[i]); ++j) {
      ConnectClient_set_timer(srClientsTable[j], timeval_create(ServerRealm_get_timeout(scRealmsTable[i]), 0));
      ConnectClient_set_limit(srClientsTable[j], ServerRealm_get_usersPerClient(scRealmsTable[i]));
      if (ConnectClient_create_users(srClientsTable[j])) {
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "Calloc error - try define smaller amount of usrpcli (or users)");
        exit(1);
      }
    }
    for (j = 0; j < ServerRealm_get_raClientsLimit(scRealmsTable[i]); ++j) {
      ConnectClient_set_timer(srRaClientsTable[j],
          timeval_create(ServerRealm_get_timeout(scRealmsTable[i]), 0));
    }
  }

	aflog(LOG_T_MAIN, LOG_I_INFO,
      "SERVER STARTED realms: %d", ServerConfiguration_get_realmsNumber(config));
  time(&now);
  ServerConfiguration_set_startTime(config, now);
	
	for ( ; ; ) {
    rset = allset;
    tmpset = wset;
    aflog(LOG_T_MAIN, LOG_I_DDEBUG,
        "select, maxfdp1: %d", maxfdp1);
    if (TaskScheduler_hasMoreTasks(scheduler)) {
      TaskScheduler_startWatching(scheduler);
      select(maxfdp1, &rset, &tmpset, NULL, TaskScheduler_get_actualTimer(scheduler));
      TaskScheduler_stopWatching(scheduler);
    }
    else {
      select(maxfdp1, &rset, &tmpset, NULL, NULL);
    }
    aflog(LOG_T_MAIN, LOG_I_DDEBUG,
        "after select...");

    for (j = 0; j < ServerConfiguration_get_realmsNumber(config); ++j) {
      pointer = scRealmsTable[j];
      srUsersTable = ServerRealm_get_usersTable(pointer);
      srClientsTable = ServerRealm_get_clientsTable(pointer);
      srRaClientsTable = ServerRealm_get_raClientsTable(pointer);
      srUsersClientsTable = ServerRealm_get_usersClientsTable(pointer);
      for (i = 0; i < ServerRealm_get_usersLimit(pointer); ++i) {
        if ((ConnectUser_get_state(srUsersTable[i]) == S_STATE_OPEN) ||
            (ConnectUser_get_state(srUsersTable[i]) == S_STATE_STOPPED) ||
            (ConnectUser_get_state(srUsersTable[i]) == S_STATE_KICKING)) {
          if (FD_ISSET(ConnectUser_get_connFd(srUsersTable[i]), &rset)) {
            k = eval_usernum(srClientsTable[ConnectUser_get_whatClient(srUsersTable[i])], i);
            aflog(LOG_T_USER, LOG_I_DDEBUG,
                "realm[%s]: Client[%s]: user[%d]: FD_ISSET", get_realmname(config, j),
                get_clientname(pointer, ConnectUser_get_whatClient(srUsersTable[i])),
                get_username(pointer,i));
            if (TYPE_IS_TCP(ServerRealm_get_realmType(pointer))) { /* forwarding tcp packets */
              n = read(ConnectUser_get_connFd(srUsersTable[i]), &buff[5], 8091);
              if (n == -1) {
                if (errno == EAGAIN) {
                  continue;
                }
                aflog(LOG_T_USER, LOG_I_ERR,
                    "realm[%s]: Client[%s]: user[%d]: READ ERROR (%d)", get_realmname(config, j),
                    get_clientname(pointer, ConnectUser_get_whatClient(srUsersTable[i])),
                    get_username(pointer, i), errno);
                n = 0;
              }
              if (n) {
                aflog(LOG_T_USER, LOG_I_DEBUG,
                    "realm[%s]: Client[%s]: FROM user[%d]: MESSAGE length=%d", get_realmname(config, j),
                    get_clientname(pointer, ConnectUser_get_whatClient(srUsersTable[i])),
                    get_username(pointer, i), n);
                UserStats_add_upload(ConnectUser_get_stats(srUsersTable[i]), n);
                if ((buff[5] == AF_S_MESSAGE) && (buff[6] == AF_S_LOGIN) && (buff[7] == AF_S_MESSAGE)) {
                  aflog(LOG_T_USER, LOG_I_WARNING,
                      "WARNING: got packet similiar to udp");
                }
                buff[0] = AF_S_MESSAGE; /* sending message */
                buff[1] = k >> 8;	/* high bits of user number */
                buff[2] = k;		/* low bits of user number */
                buff[3] = n >> 8;	/* high bits of message length */
                buff[4] = n;		/* low bits of message length */
                SslFd_send_message(ServerRealm_get_realmType(pointer),
                    ConnectClient_get_sslFd(
                      srClientsTable[ConnectUser_get_whatClient(srUsersTable[i])]),
                    buff, n+5);
              }
              else {
                aflog(LOG_T_USER, LOG_I_INFO,
                    "realm[%s]: Client[%s]: user[%d]: CLOSED", get_realmname(config, j),
                    get_clientname(pointer, ConnectUser_get_whatClient(srUsersTable[i])),
                    get_username(pointer, i));
                time(&now);
                aflog(LOG_T_USER, LOG_I_NOTICE,
                    "REALM: %s CLIENT: %s USER: %d IP: %s PORT: %s DURATION: %s",
                    get_realmname(config, j),
                    get_clientname(pointer, ConnectUser_get_whatClient(srUsersTable[i])),
                    get_username(pointer, i),
                    ConnectUser_get_nameBuf(srUsersTable[i]),
                    ConnectUser_get_portBuf(srUsersTable[i]),
                    timeperiod(now - ConnectUser_get_connectTime(srUsersTable[i])));
                if (ServerRealm_get_auditOn(pointer)) {
                  AuditList_insert_back(
                      ConnectClient_get_auditList(
                        srClientsTable[ConnectUser_get_whatClient(srUsersTable[i])]),
                      AuditListNode_new_entry(
                        get_username(pointer, i),
                        ConnectUser_get_nameBuf(srUsersTable[i]),
                        ConnectUser_get_portBuf(srUsersTable[i]),
                        ConnectUser_get_connectTime(srUsersTable[i]),
                        now - ConnectUser_get_connectTime(srUsersTable[i]))
                      );
                }
                close(ConnectUser_get_connFd(srUsersTable[i]));
                FD_CLR(ConnectUser_get_connFd(srUsersTable[i]), &allset);
                FD_CLR(ConnectUser_get_connFd(srUsersTable[i]), &wset);
                if (ConnectUser_get_state(srUsersTable[i]) == S_STATE_KICKING) {
                  ConnectUser_set_state(srUsersTable[i], S_STATE_CLEAR);
                  ServerRealm_decrease_connectedUsers(pointer);
                  ConnectClient_decrease_connected(srClientsTable[ConnectUser_get_whatClient(srUsersTable[i])]);
                  ConnectClient_get_users(srClientsTable[ConnectUser_get_whatClient(srUsersTable[i])])[k] = -1;
                }
                else {
                  ConnectUser_set_state(srUsersTable[i], S_STATE_CLOSING);
                }
                BufList_clear(ConnectUser_get_bufList(srUsersTable[i]));
                buff[0] = AF_S_CONCLOSED; /* closing connection */
                buff[1] = k >> 8;	/* high bits of user number */
                buff[2] = k;		/* low bits of user number */
                SslFd_send_message(ServerRealm_get_realmType(pointer),
                    ConnectClient_get_sslFd(
                      srClientsTable[ConnectUser_get_whatClient(srUsersTable[i])]),
                    buff, 5);
              }
            }
            else { /* when forwarding udp packets */
              n = readn(ConnectUser_get_connFd(srUsersTable[i]), buff, 5 );
              if (n != 5) {
                n = 0;
              }
              if (n) {
                if ((buff[0] == AF_S_MESSAGE) && (buff[1] == AF_S_LOGIN) && (buff[2] == AF_S_MESSAGE)) {
                  length = buff[3];
                  length = length << 8;
                  length += buff[4]; /* this is length of message */
                  if ((n = readn(ConnectUser_get_connFd(srUsersTable[i]), &buff[5], length)) != 0) {
                    aflog(LOG_T_USER, LOG_I_DEBUG,
                        "realm[%s]: Client[%s]: FROM user[%d]: MESSAGE length=%d",
                        get_realmname(config, j),
                        get_clientname(pointer, ConnectUser_get_whatClient(srUsersTable[i])),
                        get_username(pointer, i), n);
                    buff[1] = k >> 8;	/* high bits of user number */
                    buff[2] = k;		/* low bits of user number */
                    SslFd_send_message(ServerRealm_get_realmType(pointer),
                        ConnectClient_get_sslFd(
                          srClientsTable[ConnectUser_get_whatClient(srUsersTable[i])]),
                        buff, n+5);
                  }
                }
                else {
                  n = 0;
                }
              }

              if (n == 0) {
                aflog(LOG_T_USER, LOG_I_INFO,
                    "realm[%s]: Client[%s]: user[%d]: CLOSED (udp mode)", get_realmname(config, j),
                    get_clientname(pointer,
                      ConnectUser_get_whatClient(srUsersTable[i])), get_username(pointer, i));
                time(&now);
                aflog(LOG_T_USER, LOG_I_NOTICE,
                    "REALM: %s CLIENT: %s USER: %d IP: %s PORT: %s DURATION: %s",
                    get_realmname(config, j),
                    get_clientname(pointer, ConnectUser_get_whatClient(srUsersTable[i])),
                    get_username(pointer, i),
                    ConnectUser_get_nameBuf(srUsersTable[i]),
                    ConnectUser_get_portBuf(srUsersTable[i]),
                    timeperiod(now - ConnectUser_get_connectTime(srUsersTable[i])));
                close(ConnectUser_get_connFd(srUsersTable[i]));
                FD_CLR(ConnectUser_get_connFd(srUsersTable[i]), &allset);
                FD_CLR(ConnectUser_get_connFd(srUsersTable[i]), &wset);
                ConnectUser_set_state(srUsersTable[i], S_STATE_CLOSING);
                BufList_clear(ConnectUser_get_bufList(srUsersTable[i]));
                buff[0] = AF_S_CONCLOSED; /* closing connection */
                buff[1] = k >> 8;	/* high bits of user number */
                buff[2] = k;		/* low bits of user number */
                SslFd_send_message(ServerRealm_get_realmType(pointer),
                    ConnectClient_get_sslFd(
                      srClientsTable[ConnectUser_get_whatClient(srUsersTable[i])]),
                    buff, 5);
              }

            }
          }
        }
      }
      /* ------------------------------------ */
      for (i = 0; i < ServerRealm_get_usersLimit(pointer); ++i) {
        if ((ConnectUser_get_state(srUsersTable[i]) == S_STATE_STOPPED) ||
            (ConnectUser_get_state(srUsersTable[i]) == S_STATE_KICKING))
          if (FD_ISSET(ConnectUser_get_connFd(srUsersTable[i]), &tmpset)) {
            k = eval_usernum(srClientsTable[ConnectUser_get_whatClient(srUsersTable[i])], i);
            aflog(LOG_T_USER, LOG_I_DDEBUG,
                "realm[%s]: Client[%s]: user[%d]: FD_ISSET - WRITE", get_realmname(config, j),
                get_clientname(pointer, ConnectUser_get_whatClient(srUsersTable[i])),
                get_username(pointer, i));
            n = BufListNode_readMessageLength(BufList_get_first(ConnectUser_get_bufList(srUsersTable[i])));
            sent = write(ConnectUser_get_connFd(srUsersTable[i]),
                BufListNode_readMessage(BufList_get_first(ConnectUser_get_bufList(srUsersTable[i]))), n);
            if ((sent > 0) && (sent != n)) {
              BufListNode_set_actPtr(BufList_get_first(ConnectUser_get_bufList(srUsersTable[i])),
                  BufListNode_get_actPtr(BufList_get_first(ConnectUser_get_bufList(srUsersTable[i]))) + sent);
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "realm[%s]: Client[%s]: user[%d]: (%d/%d)", get_realmname(config, j),
                  get_clientname(pointer, ConnectUser_get_whatClient(srUsersTable[i])),
                  get_username(pointer, i), sent, n);
            }
            else if ((sent == -1) && (errno == EAGAIN)) {
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "realm[%s]: Client[%s]: user[%d]: EAGAIN", get_realmname(config, j),
                  get_clientname(pointer, ConnectUser_get_whatClient(srUsersTable[i])),
                  get_username(pointer, i));
            }
            else if (sent == -1) {
              aflog(LOG_T_USER, LOG_I_INFO,
                  "realm[%s]: Client[%s]: user[%d]: CLOSED", get_realmname(config, j),
                  get_clientname(pointer, ConnectUser_get_whatClient(srUsersTable[i])),
                  get_username(pointer, i));
              time(&now);
              aflog(LOG_T_USER, LOG_I_NOTICE,
                  "REALM: %s CLIENT: %s USER: %d IP: %s PORT: %s DURATION: %s",
                  get_realmname(config, j),
                  get_clientname(pointer, ConnectUser_get_whatClient(srUsersTable[i])),
                  get_username(pointer, i),
                  ConnectUser_get_nameBuf(srUsersTable[i]),
                  ConnectUser_get_portBuf(srUsersTable[i]),
                  timeperiod(now - ConnectUser_get_connectTime(srUsersTable[i])));
              close(ConnectUser_get_connFd(srUsersTable[i]));
              FD_CLR(ConnectUser_get_connFd(srUsersTable[i]), &allset);
              FD_CLR(ConnectUser_get_connFd(srUsersTable[i]), &wset);
              if (ConnectUser_get_state(srUsersTable[i]) == S_STATE_KICKING) {
                ConnectUser_set_state(srUsersTable[i], S_STATE_CLEAR);
                ServerRealm_decrease_connectedUsers(pointer);
                ConnectClient_decrease_connected(srClientsTable[ConnectUser_get_whatClient(srUsersTable[i])]);
                ConnectClient_get_users(srClientsTable[ConnectUser_get_whatClient(srUsersTable[i])])[k] = -1;
              }
              else {
                ConnectUser_set_state(srUsersTable[i], S_STATE_CLOSING);
              }
              BufList_clear(ConnectUser_get_bufList(srUsersTable[i]));
              buff[0] = AF_S_CONCLOSED; /* closing connection */
              buff[1] = k >> 8;	/* high bits of user number */
              buff[2] = k;		/* low bits of user number */
              SslFd_send_message(ServerRealm_get_realmType(pointer),
                  ConnectClient_get_sslFd(
                    srClientsTable[ConnectUser_get_whatClient(srUsersTable[i])]),
                  buff, 5);
            }
            else {
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "realm[%s]: Client[%s]: user[%d]: (%d/%d)", get_realmname(config, j),
                  get_clientname(pointer, ConnectUser_get_whatClient(srUsersTable[i])),
                  get_username(pointer, i), sent, n);
              BufList_delete_first(ConnectUser_get_bufList(srUsersTable[i]));
              if (BufList_get_first(ConnectUser_get_bufList(srUsersTable[i])) == NULL) {
                FD_CLR(ConnectUser_get_connFd(srUsersTable[i]), &wset);
                buff[0] = AF_S_CAN_SEND; /* stopping transfer */
                buff[1] = k >> 8;	/* high bits of user number */
                buff[2] = k;		/* low bits of user number */
                aflog(LOG_T_USER, LOG_I_DDEBUG,
                    "realm[%s]: Client[%s]: TO user[%d]: BUFFERING MESSAGE ENDED",
                    get_realmname(config, j),
                    get_clientname(pointer, ConnectUser_get_whatClient(srUsersTable[i])),
                    get_username(pointer, i));
                SslFd_send_message(ServerRealm_get_realmType(pointer),
                    ConnectClient_get_sslFd(
                      srClientsTable[ConnectUser_get_whatClient(srUsersTable[i])]),
                    buff, 5);
                if (ConnectUser_get_state(srUsersTable[i]) == S_STATE_KICKING) {
                  aflog(LOG_T_USER, LOG_I_INFO,
                      "realm[%s]: Client[%s]: user[%d]: delayed CLOSED", get_realmname(config, j),
                      get_clientname(pointer, ConnectUser_get_whatClient(srUsersTable[i])),
                      get_username(pointer, i));
                  time(&now);
                  aflog(LOG_T_USER, LOG_I_NOTICE,
                      "REALM: %s CLIENT: %s USER: %d IP: %s PORT: %s DURATION: %s",
                      get_realmname(config, j),
                      get_clientname(pointer, ConnectUser_get_whatClient(srUsersTable[i])),
                      get_username(pointer, i),
                      ConnectUser_get_nameBuf(srUsersTable[i]),
                      ConnectUser_get_portBuf(srUsersTable[i]),
                      timeperiod(now - ConnectUser_get_connectTime(srUsersTable[i])));
                  close(ConnectUser_get_connFd(srUsersTable[i]));
                  FD_CLR(ConnectUser_get_connFd(srUsersTable[i]), &allset);
                  FD_CLR(ConnectUser_get_connFd(srUsersTable[i]), &wset);
                  ConnectUser_set_state(srUsersTable[i], S_STATE_CLEAR);
                  ServerRealm_decrease_connectedUsers(pointer);
                  ConnectClient_decrease_connected(srClientsTable[ConnectUser_get_whatClient(srUsersTable[i])]);
                  ConnectClient_get_users(srClientsTable[ConnectUser_get_whatClient(srUsersTable[i])])[k] = -1;
                  BufList_clear(ConnectUser_get_bufList(srUsersTable[i]));
                  buff[0] = AF_S_CONCLOSED; /* closing connection */
                  buff[1] = k >> 8;	/* high bits of user number */
                  buff[2] = k;		/* low bits of user number */
                  SslFd_send_message(ServerRealm_get_realmType(pointer),
                      ConnectClient_get_sslFd(
                        srClientsTable[ConnectUser_get_whatClient(srUsersTable[i])]),
                      buff, 5);
                }
                else {
                  ConnectUser_set_state(srUsersTable[i], S_STATE_OPEN);
                }
              }
            }
          }
      }
      /* ------------------------------------ */
      if (ServerRealm_get_basePortOn(pointer) == 0) {
        for (l = 0; l < ServerRealm_get_userClientPairs(pointer); ++l) {
          if (FD_ISSET(UsrCli_get_listenFd(srUsersClientsTable[l]), &rset)) {
            len = ServerRealm_get_addressLength(pointer);
            sent = accept(UsrCli_get_listenFd(srUsersClientsTable[l]), ServerRealm_get_clientAddress(pointer), &len);
            if (sent == -1) {
              if (errno == EAGAIN) {
                aflog(LOG_T_USER, LOG_I_DDEBUG,
                    "realm[%s]: listenfd: FD_ISSET --> EAGAIN", get_realmname(config, j));
              }
              else {
                aflog(LOG_T_USER, LOG_I_DDEBUG,
                    "realm[%s]: listenfd: FD_ISSET --> errno=%d", get_realmname(config, j), errno);
              }
              continue;
            }
            flags = fcntl(sent, F_GETFL, 0);
            fcntl(sent, F_SETFL, flags | O_NONBLOCK);
            aflog(LOG_T_USER, LOG_I_DDEBUG,
                "realm[%s]: listenfd: FD_ISSET", get_realmname(config, j));
            k = find_client(pointer, ServerRealm_get_clientMode(pointer), l);
            
            if (ConnectClient_get_state(srClientsTable[k]) == CONNECTCLIENT_STATE_ACCEPTED) {
              if (ServerRealm_get_connectedUsers(pointer) == ServerRealm_get_usersLimit(pointer)) {
                close(sent);
                aflog(LOG_T_USER, LOG_I_WARNING,
                    "realm[%s]: user limit EXCEEDED", get_realmname(config, j));
              }
              else if (ConnectClient_get_connected(srClientsTable[k]) ==
                  ConnectClient_get_limit(srClientsTable[k])) {
                close(sent);
                aflog(LOG_T_USER, LOG_I_WARNING,
                    "realm[%s]: Client[%s]: usrpcli limit EXCEEDED",
                    get_realmname(config, j), get_clientname(pointer, k));
              }
              else {
                for (i = 0; i < ServerRealm_get_usersLimit(pointer); ++i) {
                  if (ConnectUser_get_state(srUsersTable[i]) == S_STATE_CLEAR) {
                    ConnectUser_set_userId(srUsersTable[i], ServerRealm_get_usersCounter(pointer));
                    ServerRealm_increase_usersCounter(pointer);
                    aflog(LOG_T_USER, LOG_I_INFO,
                        "realm[%s]: Client[%s]: new user: CONNECTING from IP: %s",
                        get_realmname(config, j), get_clientname(pointer, k),
                        sock_ntop(ServerRealm_get_clientAddress(pointer), len, ConnectUser_get_nameBuf(srUsersTable[i]),
                          ConnectUser_get_portBuf(srUsersTable[i]), ServerRealm_get_dnsLookupsOn(pointer)));
                    ConnectUser_set_connFd(srUsersTable[i], sent);
                    ConnectUser_set_state(srUsersTable[i], S_STATE_OPENING);
                    ConnectUser_set_whatClient(srUsersTable[i], k);
                    time(&now);
                    ConnectUser_set_connectTime(srUsersTable[i], now);
                    UserStats_clear(ConnectUser_get_stats(srUsersTable[i]));
                    UserStats_set_lastActivity(ConnectUser_get_stats(srUsersTable[i]), now);
                    ServerRealm_increase_connectedUsers(pointer);
                    ConnectClient_increase_connected(srClientsTable[k]);
                    memcpy(&buff[5], ConnectUser_get_nameBuf(srUsersTable[i]), 128);
                    memcpy(&buff[133], ConnectUser_get_portBuf(srUsersTable[i]), 7);
                    n = 135;
                    if (ConnectClient_get_multi(srClientsTable[k]) == CONNECTCLIENT_MULTI_ENABLED) {
                      n = 136;
                      buff[140] = UsrCli_get_number(srUsersClientsTable[l]);
                    }
                    i = find_usernum(srClientsTable[k], i);
                    buff[0] = AF_S_CONOPEN; /* opening connection */
                    buff[1] = i >> 8;	/* high bits of user number */
                    buff[2] = i;		/* low bits of user number */
                    buff[3] = n >> 8;	/* high bits of message length */
                    buff[4] = n;		/* low bits of message length */
                    SslFd_send_message(ServerRealm_get_realmType(pointer),
                        ConnectClient_get_sslFd(
                          srClientsTable[k]),
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
                  get_realmname(config, j), k);
            }
          }
        }
      }
      /* ------------------------------------ */
      if (ServerRealm_get_basePortOn(pointer) == 1) {
        for (k = 0; k < ServerRealm_get_clientsLimit(pointer); ++k) {
          if (ConnectClient_get_state(srClientsTable[k]) == CONNECTCLIENT_STATE_ACCEPTED) {
            if (FD_ISSET(ConnectClient_get_listenFd(srClientsTable[k]), &rset)) {

              len = ServerRealm_get_addressLength(pointer);
              sent = accept(ConnectClient_get_listenFd(srClientsTable[k]), ServerRealm_get_clientAddress(pointer), &len);
              if (sent == -1) {
                if (errno == EAGAIN) {
                  aflog(LOG_T_USER, LOG_I_DDEBUG,
                      "realm[%s]: listenfd: FD_ISSET --> EAGAIN", get_realmname(config, j));
                }
                else {
                  aflog(LOG_T_USER, LOG_I_DDEBUG,
                      "realm[%s]: listenfd: FD_ISSET --> errno=%d", get_realmname(config, j), errno);
                }
                continue;
              }
              flags = fcntl(sent, F_GETFL, 0);
              fcntl(sent, F_SETFL, flags | O_NONBLOCK);
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "realm[%s]: Client[%s]: listenfd: FD_ISSET",
                  get_realmname(config, j), get_clientname(pointer, k));
              if (ServerRealm_get_connectedUsers(pointer) == ServerRealm_get_usersLimit(pointer)) {
                close(sent);
                aflog(LOG_T_USER, LOG_I_WARNING,
                    "realm[%s]: user limit EXCEEDED", get_realmname(config, j));
              }
              else if(ConnectClient_get_connected(srClientsTable[k]) ==
                  ConnectClient_get_limit(srClientsTable[k])) {
                close(sent);
                aflog(LOG_T_USER, LOG_I_WARNING,
                    "realm[%s]: Client[%s]: usrpcli limit EXCEEDED",
                    get_realmname(config, j), get_clientname(pointer, k));
              }
              else {
                for (i = 0; i < ServerRealm_get_usersLimit(pointer); ++i) {
                  if (ConnectUser_get_state(srUsersTable[i]) == S_STATE_CLEAR) {
                    ConnectUser_set_userId(srUsersTable[i], ServerRealm_get_usersCounter(pointer));
                    ServerRealm_increase_usersCounter(pointer);
                    aflog(LOG_T_USER, LOG_I_INFO,
                        "realm[%s]: Client[%s]: new user: CONNECTING from IP: %s",
                        get_realmname(config, j), get_clientname(pointer, k),
                        sock_ntop(ServerRealm_get_clientAddress(pointer), len,
                          ConnectUser_get_nameBuf(srUsersTable[i]),
                          ConnectUser_get_portBuf(srUsersTable[i]), ServerRealm_get_dnsLookupsOn(pointer)));
                    ConnectUser_set_connFd(srUsersTable[i], sent);
                    ConnectUser_set_state(srUsersTable[i], S_STATE_OPENING);
                    ConnectUser_set_whatClient(srUsersTable[i], k);
                    time(&now);
                    ConnectUser_set_connectTime(srUsersTable[i], now);
                    UserStats_clear(ConnectUser_get_stats(srUsersTable[i]));
                    UserStats_set_lastActivity(ConnectUser_get_stats(srUsersTable[i]), now);
                    ServerRealm_increase_connectedUsers(pointer);
                    ConnectClient_increase_connected(srClientsTable[k]);
                    memcpy(&buff[5], ConnectUser_get_nameBuf(srUsersTable[i]), 128);
                    memcpy(&buff[133], ConnectUser_get_portBuf(srUsersTable[i]), 7);
                    n = 135;
                    i = find_usernum(srClientsTable[k], i);
                    buff[0] = AF_S_CONOPEN; /* opening connection */
                    buff[1] = i >> 8;	/* high bits of user number */
                    buff[2] = i;		/* low bits of user number */
                    buff[3] = n >> 8;	/* high bits of message length */
                    buff[4] = n;		/* low bits of message length */
                    SslFd_send_message(ServerRealm_get_realmType(pointer),
                        ConnectClient_get_sslFd(
                          srClientsTable[k]),
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
      for (k = 0; k < ServerRealm_get_clientsLimit(pointer); ++k)
        if ((ConnectClient_get_state(srClientsTable[k]) > CONNECTCLIENT_STATE_FREE) &&
            (FD_ISSET(SslFd_get_fd(ConnectClient_get_sslFd(srClientsTable[k])), &rset))) {
          if (ConnectClient_get_state(srClientsTable[k]) == CONNECTCLIENT_STATE_CONNECTING) {
            make_ssl_initialize(ConnectClient_get_sslFd(srClientsTable[k]));
            aflog(LOG_T_CLIENT, LOG_I_DDEBUG,
                "realm[%s]: new Client[%s]: SSL_accept",
                get_realmname(config, j), get_clientname(pointer, k));
            switch (make_ssl_accept(ConnectClient_get_sslFd(srClientsTable[k]))) {
              case 2: {
                        close(SslFd_get_fd(ConnectClient_get_sslFd(srClientsTable[k])));
                        FD_CLR(SslFd_get_fd(ConnectClient_get_sslFd(srClientsTable[k])), &allset);

                        /* This SSL-object is busted; don't reuse it
                           (SSL_clear isn't sufficient because ssl->new_session is set): */
                        SslFd_set_ssl(ConnectClient_get_sslFd(srClientsTable[k]),
                                      SSL_new (ctx));

                        ConnectClient_set_state(srClientsTable[k], CONNECTCLIENT_STATE_FREE);
                        if ((task = ConnectClient_get_task(srClientsTable[k]))) {
                          TaskScheduler_removeTask(scheduler, task);
                          ConnectClient_set_task(srClientsTable[k], NULL);
                        }
                        ServerRealm_decrease_connectedClients(pointer);
                        aflog(LOG_T_CLIENT, LOG_I_ERR,
                            "realm[%s]: new Client[%s]: DENIED by SSL_accept",
                            get_realmname(config, j), get_clientname(pointer, k));
                      }
              case 1: {
                        continue;
                      }
              default: {
                         aflog(LOG_T_CLIENT, LOG_I_DEBUG,
                             "realm[%s]: new Client[%s]: ACCEPTED by SSL_accept",
                             get_realmname(config, j), get_clientname(pointer, k));
                         ConnectClient_set_state(srClientsTable[k], CONNECTCLIENT_STATE_AUTHORIZING);
                         continue;
                       }
            }
          }
          aflog(LOG_T_CLIENT, LOG_I_DDEBUG,
              "realm[%s]: Client[%s]: commfd: FD_ISSET",
              get_realmname(config, j), get_clientname(pointer, k));
          if (ConnectClient_get_state(srClientsTable[k]) == CONNECTCLIENT_STATE_AUTHORIZING) {
            n = SslFd_get_message(ServerRealm_get_realmType(pointer) | TYPE_SSL | TYPE_ZLIB,
                ConnectClient_get_sslFd(srClientsTable[k]),
                buff, (-1) * HeaderBuffer_to_read(ConnectClient_get_header(srClientsTable[k])));
          }
          else {
            n = SslFd_get_message(ServerRealm_get_realmType(pointer),
                ConnectClient_get_sslFd(srClientsTable[k]),
                buff, (-1) * HeaderBuffer_to_read(ConnectClient_get_header(srClientsTable[k])));
          }
          if (n == -1) {
            if (errno == EAGAIN) {
              aflog(LOG_T_CLIENT, LOG_I_DDEBUG,
                  "realm[%s]: Client[%s]: commfd: EAGAIN",
                  get_realmname(config, j), get_clientname(pointer, k));
              continue;
            }
            else {
              aflog(LOG_T_CLIENT, LOG_I_ERR,
                  "realm[%s]: Client[%s]: commfd: ERROR: %d",
                  get_realmname(config, j), get_clientname(pointer, k), errno);
              n = 0;
            }
          }
          else if (n != 5) {
            if (n != 0) {
              aflog(LOG_T_CLIENT, LOG_I_DEBUG,
                  "realm[%s]: Client[%s]: header length = %d --> buffering",
                  get_realmname(config, j), get_clientname(pointer, k), n);
              HeaderBuffer_store(ConnectClient_get_header(srClientsTable[k]), buff, n);
              if (HeaderBuffer_to_read(ConnectClient_get_header(srClientsTable[k])) == 0) {
                HeaderBuffer_restore(ConnectClient_get_header(srClientsTable[k]), buff);
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
                get_realmname(config, j), get_clientname(pointer, k));
            time(&now);
            aflog(LOG_T_CLIENT, LOG_I_NOTICE,
                "REALM: %s CLIENT: %s IP: %s PORT: %s DURATION: %s",
                get_realmname(config, j),
                get_clientname(pointer, k),
                ConnectClient_get_nameBuf(srClientsTable[k]),
                ConnectClient_get_portBuf(srClientsTable[k]),
                timeperiod(now - ConnectClient_get_connectTime(srClientsTable[k])));
            if (ServerRealm_get_auditOn(pointer)) {
              while (AuditList_get_first(ConnectClient_get_auditList(srClientsTable[k]))) {
                aflog(LOG_T_CLIENT, LOG_I_NOTICE,
                    "USERID: %d IP: %s PORT: %s CONNECTED: %s DURATION: %s",
                    AuditListNode_get_userId(
                      AuditList_get_first(
                        ConnectClient_get_auditList(srClientsTable[k]))),
                    AuditListNode_get_nameBuf(
                      AuditList_get_first(
                        ConnectClient_get_auditList(srClientsTable[k]))),
                    AuditListNode_get_portBuf(
                      AuditList_get_first(
                        ConnectClient_get_auditList(srClientsTable[k]))),
                    localdate(AuditListNode_get_connectTimep(
                        AuditList_get_first(
                          ConnectClient_get_auditList(srClientsTable[k])))),
                    timeperiod(AuditListNode_get_duration(
                        AuditList_get_first(
                          ConnectClient_get_auditList(srClientsTable[k])))));
                AuditList_delete_first(ConnectClient_get_auditList(srClientsTable[k]));
              }
            }
            remove_client(pointer, k, &allset, &wset, scheduler);
            continue;
          }

          numofcon = buff[1];
          numofcon = numofcon << 8;
          numofcon += buff[2]; /* this is id of user */
          length = buff[3];
          length = length << 8;
          length += buff[4]; /* this is length of message */ 

          if ((k == ServerRealm_get_clientsLimit(pointer)) && (buff[0] != AF_S_LOGIN) &&
              (buff[0] != AF_S_ADMIN_LOGIN) && (buff[0] != AF_S_ADMIN_CMD)) {
            buff[0] = AF_S_WRONG;
          }
          if (ConnectClient_get_state(srClientsTable[k]) < CONNECTCLIENT_STATE_AUTHORIZING) {
            aflog(LOG_T_CLIENT, LOG_I_WARNING,
                "realm[%s]: Client[%s]: Impossible behaviour --> ignoring",
                get_realmname(config, j), get_clientname(pointer, k));
            continue;
          }
          if ((ConnectClient_get_state(srClientsTable[k]) == CONNECTCLIENT_STATE_AUTHORIZING) &&
              (buff[0] != AF_S_LOGIN) && (buff[0] != AF_S_ADMIN_LOGIN)) {
            buff[0] = AF_S_WRONG;
          }
          
          time(&now);
          ConnectClient_set_lastActivity(srClientsTable[k], now);
          if (ServerRealm_get_maxIdle(pointer)) {
            ConnectClient_set_timer(srClientsTable[k], timeval_create(ServerRealm_get_maxIdle(pointer), 0));
            TaskScheduler_update(scheduler);
          }

          switch (buff[0]) {
            case AF_S_CONCLOSED : {
                                    n = numofcon;
                                    numofcon = eval_numofcon(pointer, k, numofcon);
                                    if ((numofcon>=0) && (numofcon<(ServerRealm_get_usersLimit(pointer))) &&
                                        (ConnectClient_get_state(srClientsTable[k]) ==
                                         CONNECTCLIENT_STATE_ACCEPTED)) {
                                      if (ConnectUser_get_state(srUsersTable[numofcon]) ==
                                          S_STATE_STOPPED) {
                                        ConnectUser_set_state(srUsersTable[numofcon], S_STATE_KICKING);
                                        aflog(LOG_T_USER, LOG_I_INFO,
                                            "realm[%s]: user[%d]: KICKING...",
                                            get_realmname(config, j), get_username(pointer, numofcon));
                                      }
                                      else {
                                        ServerRealm_decrease_connectedUsers(pointer);
                                        ConnectClient_decrease_connected(srClientsTable[k]);
                                        ConnectClient_get_users(srClientsTable[k])[n] = -1;
                                        if (ConnectUser_get_state(srUsersTable[numofcon]) == S_STATE_CLOSING) {
                                          ConnectUser_set_state(srUsersTable[numofcon], S_STATE_CLEAR);
                                          aflog(LOG_T_USER, LOG_I_DEBUG,
                                              "realm[%s]: user[%d]: CLOSE CONFIRMED",
                                              get_realmname(config, j), get_username(pointer, numofcon));
                                        }
                                        else if (ConnectUser_get_state(srUsersTable[numofcon]) == S_STATE_OPEN) {
                                          aflog(LOG_T_USER, LOG_I_INFO,
                                              "realm[%s]: user[%d]: KICKED",
                                              get_realmname(config, j), get_username(pointer, numofcon));
                                          time(&now);
                                          aflog(LOG_T_USER, LOG_I_NOTICE,
                                              "REALM: %s USER: %d IP: %s PORT: %s DURATION: %s",
                                              get_realmname(config, j),
                                              get_username(pointer, numofcon),
                                              ConnectUser_get_nameBuf(srUsersTable[numofcon]),
                                              ConnectUser_get_portBuf(srUsersTable[numofcon]),
                                              timeperiod(now -
                                                ConnectUser_get_connectTime(srUsersTable[numofcon])));
                                          close(ConnectUser_get_connFd(srUsersTable[numofcon]));
                                          FD_CLR(ConnectUser_get_connFd(srUsersTable[numofcon]), &allset);
                                          FD_CLR(ConnectUser_get_connFd(srUsersTable[numofcon]), &wset);
                                          ConnectUser_set_state(srUsersTable[numofcon], S_STATE_CLEAR);
                                          BufList_clear(ConnectUser_get_bufList(srUsersTable[numofcon]));
                                          buff[0] = AF_S_CONCLOSED; /* closing connection */
                                          buff[1] = n >> 8;	/* high bits of user number */
                                          buff[2] = n;		/* low bits of user number */
                                          SslFd_send_message(ServerRealm_get_realmType(pointer),
                                              ConnectClient_get_sslFd(
                                                srClientsTable[k]),
                                              buff, 5);
                                        }
                                      }
                                    }
                                    else {
                                      remove_client(pointer, k, &allset, &wset, scheduler);
                                    }
                                    break;
                                  }
            case AF_S_CONOPEN : {
                                  n = numofcon;
                                  numofcon = eval_numofcon(pointer, k, numofcon);
                                  if ((numofcon>=0) && (numofcon<(ServerRealm_get_usersLimit(pointer))) &&
                                      (ConnectClient_get_state(srClientsTable[k]) ==
                                       CONNECTCLIENT_STATE_ACCEPTED)) {
                                    if (ConnectUser_get_state(srUsersTable[numofcon]) ==
                                          S_STATE_OPENING) {
                                      aflog(LOG_T_USER, LOG_I_INFO,
                                          "realm[%s]: user[%d]: NEW",
                                          get_realmname(config, j), get_username(pointer, numofcon));
                                      FD_SET(ConnectUser_get_connFd(srUsersTable[numofcon]), &allset);
                                      maxfdp1 = (maxfdp1 > (ConnectUser_get_connFd(srUsersTable[numofcon]) + 1)) ?
                                        maxfdp1 : (ConnectUser_get_connFd(srUsersTable[numofcon]) + 1);
                                      ConnectUser_set_state(srUsersTable[numofcon], S_STATE_OPEN);
                                    }
                                    if (ConnectUser_get_state(srUsersTable[numofcon]) ==
                                         S_STATE_OPENING_CLOSED) {
                                      aflog(LOG_T_USER, LOG_I_INFO,
                                          "realm[%s]: user[%d]: delayed CLOSING",
                                          get_realmname(config, j), get_username(pointer, numofcon));
                                      ConnectUser_set_state(srUsersTable[numofcon], S_STATE_CLOSING);
                                      buff[0] = AF_S_CONCLOSED; /* closing connection */
                                      buff[1] = n >> 8;	/* high bits of user number */
                                      buff[2] = n;		/* low bits of user number */
                                      SslFd_send_message(ServerRealm_get_realmType(pointer),
                                          ConnectClient_get_sslFd(
                                            srClientsTable[k]),
                                          buff, 5);
                                    }
                                  }
                                  else {
                                    remove_client(pointer, k, &allset, &wset, scheduler);
                                  }
                                  break;
                                }
            case AF_S_CANT_OPEN : {
                                    n = numofcon;
                                    numofcon = eval_numofcon(pointer, k, numofcon);
                                    if ((numofcon>=0) && (numofcon<(ServerRealm_get_usersLimit(pointer))) &&
                                        (ConnectClient_get_state(srClientsTable[k]) ==
                                         CONNECTCLIENT_STATE_ACCEPTED)) {
                                      if ((ConnectUser_get_state(srUsersTable[numofcon]) ==
                                          S_STATE_OPENING) ||
                                        (ConnectUser_get_state(srUsersTable[numofcon]) ==
                                         S_STATE_OPENING_CLOSED)) {
                                        aflog(LOG_T_USER, LOG_I_INFO,
                                            "realm[%s]: user[%d]: DROPPED",
                                            get_realmname(config, j), get_username(pointer, numofcon));
                                        ServerRealm_decrease_connectedUsers(pointer);
                                        ConnectClient_decrease_connected(srClientsTable[k]);
                                        ConnectClient_get_users(srClientsTable[k])[n] = -1;
                                        if (ConnectUser_get_state(srUsersTable[numofcon]) ==
                                            S_STATE_OPENING) {
                                          close(ConnectUser_get_connFd(srUsersTable[numofcon]));
                                        }
                                        ConnectUser_set_state(srUsersTable[numofcon], S_STATE_CLEAR);
                                      }
                                    }
                                    else {
                                      remove_client(pointer, k, &allset, &wset, scheduler);
                                    }
                                    break;
                                  }						    
            case AF_S_MESSAGE : {
                                  if (ConnectClient_get_state(srClientsTable[k]) !=
                                      CONNECTCLIENT_STATE_ACCEPTED) {
                                    remove_client(pointer, k, &allset, &wset, scheduler);
                                    break;
                                  }
                                  if (TYPE_IS_UDP(ServerRealm_get_realmType(pointer))) { /* udp */
                                    n = SslFd_get_message(ServerRealm_get_realmType(pointer),
                                        ConnectClient_get_sslFd(
                                          srClientsTable[k]),
                                        &buff[5], length);
                                  }
                                  else {
                                    n = SslFd_get_message(ServerRealm_get_realmType(pointer),
                                        ConnectClient_get_sslFd(
                                          srClientsTable[k]),
                                        buff, length);
                                  }
                                  temp = numofcon;
                                  numofcon = eval_numofcon(pointer, k, numofcon);
                                  if ((numofcon>=0) && (numofcon<(ServerRealm_get_usersLimit(pointer)))) {
                                    if (ConnectUser_get_state(srUsersTable[numofcon]) == S_STATE_OPEN) {
                                      aflog(LOG_T_USER, LOG_I_DEBUG,
                                          "realm[%s]: TO user[%d]: MESSAGE length=%d",
                                          get_realmname(config, j), get_username(pointer, numofcon), n);
                                      UserStats_add_download(ConnectUser_get_stats(srUsersTable[numofcon]), n);
                                      if (TYPE_IS_UDP(ServerRealm_get_realmType(pointer))) { /* udp */
                                        buff[1] = AF_S_LOGIN;
                                        buff[2] = AF_S_MESSAGE;
                                        buff[3] = n >> 8; /* high bits of message length */
                                        buff[4] = n;      /* low bits of message length */
                                        sent = write(ConnectUser_get_connFd(srUsersTable[numofcon]), buff, n+5);
                                        if (sent == -1) {
                                          aflog(LOG_T_USER, LOG_I_INFO,
                                              "realm[%s]: user[%d]: CLOSED (write-udp)",
                                              get_realmname(config, j), get_username(pointer, numofcon));
                                          time(&now);
                                          aflog(LOG_T_USER, LOG_I_NOTICE,
                                              "REALM: %s USER: %d IP: %s PORT: %s DURATION: %s",
                                              get_realmname(config, j),
                                              get_username(pointer, numofcon),
                                              ConnectUser_get_nameBuf(srUsersTable[numofcon]),
                                              ConnectUser_get_portBuf(srUsersTable[numofcon]),
                                              timeperiod(now - ConnectUser_get_connectTime(srUsersTable[numofcon])));
                                          close(ConnectUser_get_connFd(srUsersTable[numofcon]));
                                          FD_CLR(ConnectUser_get_connFd(srUsersTable[numofcon]), &allset);
                                          FD_CLR(ConnectUser_get_connFd(srUsersTable[numofcon]), &wset);
                                          ConnectUser_set_state(srUsersTable[numofcon], S_STATE_CLOSING);
                                          BufList_clear(ConnectUser_get_bufList(srUsersTable[numofcon]));
                                          buff[0] = AF_S_CONCLOSED; /* closing connection */
                                          buff[1] = temp >> 8;	/* high bits of user number */
                                          buff[2] = temp;		/* low bits of user number */
                                          SslFd_send_message(ServerRealm_get_realmType(pointer),
                                              ConnectClient_get_sslFd(
                                                srClientsTable[k]),
                                              buff, 5);
                                        }
                                      }
                                      else { /* tcp */
                                        sent = write(ConnectUser_get_connFd(srUsersTable[numofcon]), buff, n);
                                        if ((sent > 0) && (sent != n)) {
                                          BufList_insert_back(ConnectUser_get_bufList(srUsersTable[numofcon]),
                                              BufListNode_new_message(sent, n, buff));
                                          ConnectUser_set_state(srUsersTable[numofcon], S_STATE_STOPPED);
                                          FD_SET(ConnectUser_get_connFd(srUsersTable[numofcon]), &wset);
                                          buff[0] = AF_S_DONT_SEND; /* stopping transfer */
                                          buff[1] = temp >> 8;	/* high bits of user number */
                                          buff[2] = temp;		/* low bits of user number */
                                          aflog(LOG_T_USER, LOG_I_DDEBUG,
                                              "realm[%s]: TO user[%d]: BUFFERING MESSAGE STARTED (%d/%d)",
                                              get_realmname(config, j), get_username(pointer, numofcon), sent, n);
                                          SslFd_send_message(ServerRealm_get_realmType(pointer),
                                              ConnectClient_get_sslFd(
                                                srClientsTable[k]),
                                              buff, 5);
                                        }
                                        else if ((sent == -1) && (errno == EAGAIN)) {
                                          BufList_insert_back(ConnectUser_get_bufList(srUsersTable[numofcon]),
                                              BufListNode_new_message(0, n, buff));
                                          ConnectUser_set_state(srUsersTable[numofcon], S_STATE_STOPPED);
                                          FD_SET(ConnectUser_get_connFd(srUsersTable[numofcon]), &wset);
                                          buff[0] = AF_S_DONT_SEND; /* stopping transfer */
                                          buff[1] = temp >> 8;	/* high bits of user number */
                                          buff[2] = temp;		/* low bits of user number */
                                          aflog(LOG_T_USER, LOG_I_DDEBUG,
                                              "realm[%s]: TO user[%d]: BUFFERING MESSAGE STARTED (%d/%d)",
                                              get_realmname(config, j), get_username(pointer, numofcon), sent, n);
                                          SslFd_send_message(ServerRealm_get_realmType(pointer),
                                              ConnectClient_get_sslFd(
                                                srClientsTable[k]),
                                              buff, 5);
                                        }
                                        else if (sent == -1) {
                                          aflog(LOG_T_USER, LOG_I_INFO,
                                              "realm[%s]: user[%d]: CLOSED (write-tcp)",
                                              get_realmname(config, j), get_username(pointer, numofcon));
                                          time(&now);
                                          aflog(LOG_T_USER, LOG_I_NOTICE,
                                              "REALM: %s USER: %d IP: %s PORT: %s DURATION: %s",
                                              get_realmname(config, j),
                                              get_username(pointer, numofcon),
                                              ConnectUser_get_nameBuf(srUsersTable[numofcon]),
                                              ConnectUser_get_portBuf(srUsersTable[numofcon]),
                                              timeperiod(now - ConnectUser_get_connectTime(srUsersTable[numofcon])));
                                          close(ConnectUser_get_connFd(srUsersTable[numofcon]));
                                          FD_CLR(ConnectUser_get_connFd(srUsersTable[numofcon]), &allset);
                                          FD_CLR(ConnectUser_get_connFd(srUsersTable[numofcon]), &wset);
                                          ConnectUser_set_state(srUsersTable[numofcon], S_STATE_CLOSING);
                                          BufList_clear(ConnectUser_get_bufList(srUsersTable[numofcon]));
                                          buff[0] = AF_S_CONCLOSED; /* closing connection */
                                          buff[1] = temp >> 8;	/* high bits of user number */
                                          buff[2] = temp;		/* low bits of user number */
                                          SslFd_send_message(ServerRealm_get_realmType(pointer),
                                              ConnectClient_get_sslFd(
                                                srClientsTable[k]),
                                              buff, 5);
                                        }
                                      }
                                    }
                                    else if (ConnectUser_get_state(srUsersTable[numofcon]) == S_STATE_STOPPED) {
                                      aflog(LOG_T_USER, LOG_I_DDEBUG,
                                          "realm[%s]: TO user[%d]: BUFFERING MESSAGE (%d)",
                                          get_realmname(config, j), get_username(pointer, numofcon), n);
                                      if (TYPE_IS_UDP(ServerRealm_get_realmType(pointer))) { /* udp */
                                        buff[1] = AF_S_LOGIN;
                                        buff[2] = AF_S_MESSAGE;
                                        buff[3] = n >> 8; /* high bits of message length */
                                        buff[4] = n;      /* low bits of message length */
                                        BufList_insert_back(ConnectUser_get_bufList(srUsersTable[numofcon]),
                                            BufListNode_new_message(0, n+5, buff));
                                      }
                                      else {
                                        BufList_insert_back(ConnectUser_get_bufList(srUsersTable[numofcon]),
                                            BufListNode_new_message(0, n, buff));
                                      }
                                    }
                                    else if (ConnectUser_get_state(srUsersTable[numofcon]) == S_STATE_CLOSING) {
                                      aflog(LOG_T_USER, LOG_I_WARNING,
                                          "realm[%s]: TO user[%d]: IGNORED message length=%d",
                                          get_realmname(config, j), get_username(pointer, numofcon), n);
                                    }
                                    else {
                                      aflog(LOG_T_USER, LOG_I_WARNING,
                                          "realm[%s]: TO user[%d]: user in wrong state - IGNORED",
                                          get_realmname(config, j), get_username(pointer, numofcon));
                                    }
                                  }
                                  else {
                                      aflog(LOG_T_USER, LOG_I_WARNING,
                                          "realm[%s]: message to non-existing user - IGNORED",
                                          get_realmname(config, j));
                                  }
                                  break;
                                }
            case AF_S_LOGIN : {
                                if ((ConnectClient_get_state(srClientsTable[k]) ==
                                      CONNECTCLIENT_STATE_AUTHORIZING) &&
                                    (numofcon==(ServerRealm_get_password(pointer)[0]*256+ServerRealm_get_password(pointer)[1])) &&
                                    (length==(ServerRealm_get_password(pointer)[2]*256+ServerRealm_get_password(pointer)[3]))) {
                                  ConnectClient_set_multi(srClientsTable[k], CONNECTCLIENT_MULTI_DISABLED);
                                  if (k != ServerRealm_get_clientsLimit(pointer)) {
                                    ConnectClient_set_state(srClientsTable[k], CONNECTCLIENT_STATE_ACCEPTED);
                                    aflog(LOG_T_CLIENT, LOG_I_INFO,
                                        "realm[%s]: Client[%s]: pass ok - ACCESS GRANTED",
                                        get_realmname(config, j), get_clientname(pointer, k));
                                    buff[0] = AF_S_LOGIN; /* sending message */
                                    buff[1] = ConnectClient_get_limit(
                                        srClientsTable[k]) >> 8;/* high bits of user number */
                                    buff[2] = ConnectClient_get_limit(
                                        srClientsTable[k]);     /* low bits of user number */
                                    buff[3] = ServerRealm_get_realmType(pointer);	/* type of connection */
                                    SslFd_send_message(ServerRealm_get_realmType(pointer) | TYPE_SSL | TYPE_ZLIB,
                                        ConnectClient_get_sslFd(
                                          srClientsTable[k]),
                                        buff, 5);
                                    if ((task = ConnectClient_get_task(srClientsTable[k]))) {
                                      TaskScheduler_removeTask(scheduler, task);
                                      ConnectClient_set_task(srClientsTable[k], NULL);
                                    }
                                    if (ServerRealm_get_maxIdle(pointer)) {
                                      ConnectClient_set_timer(srClientsTable[k],
                                          timeval_create(ServerRealm_get_maxIdle(pointer), 0));
                                      task = Task_new(ConnectClient_get_timerp(srClientsTable[k]),
                                          RCTfunction,
                                          RCTdata_new(config, j, k, 0, RCT_REASON_MAXIDLE, &allset, &wset),
                                          RCTdata_free);
                                      ConnectClient_set_task(srClientsTable[k], task);
                                      TaskScheduler_addTask(scheduler, task);
                                    }
                                    if (ServerRealm_get_basePortOn(pointer) == 1) {
                                      long tmp_val;
                                      char tmp_tab[6];
                                      if (check_long(
                                            UsrCli_get_listenPortName(
                                              srUsersClientsTable[
                                              ConnectClient_get_usrCliPair(srClientsTable[k])]),
                                            &tmp_val)) {
                                        aflog(LOG_T_CLIENT, LOG_I_ERR,
                                            "realm[%s]: INVALID listenport - removing Client[%s]",
                                            get_realmname(config, j), get_clientname(pointer, k));
                                        remove_client(pointer, k, &allset, &wset, scheduler);
                                        break;
                                      }
                                      tmp_val = tmp_val%65536;
                                      memset(tmp_tab, 0, 6);
                                      sprintf(tmp_tab, "%d", (int)tmp_val);
                                      ipfam = 0x01;
#ifdef AF_INET6
                                      if (TYPE_IS_IPV4(ServerRealm_get_realmType(pointer))) {
                                        ipfam |= 0x02;
                                      }
                                      else if (TYPE_IS_IPV6(ServerRealm_get_realmType(pointer))) {
                                        ipfam |= 0x04;
                                      }
#endif
                                      while (ip_listen(ConnectClient_get_listenFdp(srClientsTable[k]),
                                            UsrCli_get_listenHostName(srUsersClientsTable[
                                              ConnectClient_get_usrCliPair(srClientsTable[k])]) ?
                                            UsrCli_get_listenHostName(srUsersClientsTable[
                                              ConnectClient_get_usrCliPair(srClientsTable[k])]) :
                                            ServerRealm_get_hostName(pointer),
                                            tmp_tab, (&len), ipfam)) {
                                        tmp_val = (tmp_val+1)%65536;
                                        memset(tmp_tab, 0, 6);
                                        sprintf(tmp_tab, "%d", (int)tmp_val);
                                      }
                                      ServerRealm_set_addressLength(pointer, len);
                                      FD_SET(ConnectClient_get_listenFd(srClientsTable[k]), &allset);
                                      maxfdp1 = (maxfdp1>(ConnectClient_get_listenFd(srClientsTable[k])+1)) ?
                                        maxfdp1 : (ConnectClient_get_listenFd(srClientsTable[k]) + 1);
                                      aflog(LOG_T_CLIENT, LOG_I_INFO,
                                          "realm[%s]: Client[%s]: listenport=%s",
                                          get_realmname(config, j), get_clientname(pointer, k), tmp_tab);
                                    }
                                  }
                                  else {
                                    aflog(LOG_T_CLIENT, LOG_I_WARNING,
                                        "realm[%s]: client limit EXCEEDED", get_realmname(config, j));
                                    buff[0] = AF_S_CANT_OPEN; /* sending message */
                                    SslFd_send_message(ServerRealm_get_realmType(pointer) | TYPE_SSL,
                                        ConnectClient_get_sslFd(
                                          srClientsTable[k]),
                                        buff, 5);
                                    remove_client(pointer, k, &allset, &wset, scheduler);
                                  }
                                }
                                else if ((ConnectClient_get_state(srClientsTable[k]) ==
                                      CONNECTCLIENT_STATE_ACCEPTED) && (numofcon == 0)) {
                                  n = SslFd_get_message(ServerRealm_get_realmType(pointer),
                                      ConnectClient_get_sslFd(
                                        srClientsTable[k]),
                                      buff, length);
                                  buff[n] = 0;
                                  aflog(LOG_T_CLIENT, LOG_I_INFO,
                                      "realm[%s]: Client[%s]: ID received: %s",
                                      get_realmname(config, j), get_clientname(pointer, k), buff);
                                  ConnectClient_set_sClientId(srClientsTable[k], (char*) buff);
                                }
                                else {
                                  aflog(LOG_T_CLIENT, LOG_I_ERR,
                                      "realm[%s]: Client[%s]: Wrong password - CLOSING",
                                      get_realmname(config, j), get_clientname(pointer, k));
                                  buff[0] = AF_S_WRONG; /* sending message */
                                  SslFd_send_message(ServerRealm_get_realmType(pointer) | TYPE_SSL,
                                      ConnectClient_get_sslFd(
                                        srClientsTable[k]),
                                      buff, 5);
                                  remove_client(pointer, k, &allset, &wset, scheduler);
                                }
                                break;
                              }
            case AF_S_DONT_SEND: {
                                   if ((ConnectUser_get_state(srUsersTable[numofcon]) == S_STATE_OPEN) ||
                                       (ConnectUser_get_state(srUsersTable[numofcon]) == S_STATE_STOPPED)) {
                                     aflog(LOG_T_CLIENT, LOG_I_DEBUG,
                                         "realm[%s]: user[%d]: STOP READING",
                                         get_realmname(config, j), get_username(pointer, numofcon));
                                     FD_CLR(ConnectUser_get_connFd(srUsersTable[numofcon]), &allset);
                                   }
                                   else {
                                     aflog(LOG_T_CLIENT, LOG_I_DDEBUG,
                                         "realm[%s]: user[%d]: STOP READING - ignored",
                                         get_realmname(config, j), get_username(pointer, numofcon));
                                   }
                                   break;
                                 }
            case AF_S_CAN_SEND: {
                                  if ((ConnectUser_get_state(srUsersTable[numofcon]) == S_STATE_OPEN) ||
                                      (ConnectUser_get_state(srUsersTable[numofcon]) == S_STATE_STOPPED)) {
                                    aflog(LOG_T_CLIENT, LOG_I_DEBUG,
                                        "realm[%s]: user[%d]: START READING",
                                        get_realmname(config, j), get_username(pointer, numofcon));
                                    FD_SET(ConnectUser_get_connFd(srUsersTable[numofcon]), &allset);
                                  }
                                  else {
                                    aflog(LOG_T_CLIENT, LOG_I_DDEBUG,
                                        "realm[%s]: user[%d]: START READING - ignored",
                                        get_realmname(config, j), get_username(pointer, numofcon));
                                  }
                                  break;
                                }
            case AF_S_WRONG: {
                               aflog(LOG_T_CLIENT, LOG_I_ERR,
                                   "realm[%s]: Client[%s]: Wrong message - CLOSING",
                                   get_realmname(config, j), get_clientname(pointer, k));
                               remove_client(pointer, k, &allset, &wset, scheduler);
                               break;
                             }
            case AF_S_ADMIN_LOGIN: {
                                     if ((ConnectClient_get_state(srClientsTable[k]) ==
                                           CONNECTCLIENT_STATE_AUTHORIZING) &&
                                         (numofcon == (ServerRealm_get_password(pointer)[0]*256 + ServerRealm_get_password(pointer)[1])) &&
                                         (length == (ServerRealm_get_password(pointer)[2]*256 + ServerRealm_get_password(pointer)[3]))) {
                                       aflog(LOG_T_MANAGE, LOG_I_INFO,
                                           "realm[%s]: Client[%s]: NEW remote admin -- pass OK",
                                           get_realmname(config, j), get_clientname(pointer, k));
                                       for (l = 0; l < ServerRealm_get_raClientsLimit(pointer); ++l) {
                                         if (ConnectClient_get_state(srRaClientsTable[l]) ==
                                             CONNECTCLIENT_STATE_FREE) {
                                           SslFd_set_fd(
                                               ConnectClient_get_sslFd(srRaClientsTable[l]),
                                               SslFd_get_fd(
                                                 ConnectClient_get_sslFd(srClientsTable[k])));
                                           ConnectClient_set_connectTime(
                                               srRaClientsTable[l],
                                               ConnectClient_get_connectTime(srClientsTable[k]));
                                           ConnectClient_set_lastActivity(
                                               srRaClientsTable[l],
                                               ConnectClient_get_lastActivity(srClientsTable[k]));
#ifdef HAVE_LIBPTHREAD
                                           ConnectClient_set_tunnelType(
                                               srRaClientsTable[l],
                                               ConnectClient_get_tunnelType(srClientsTable[k]));
#endif
                                           ConnectClient_set_clientId(
                                               srRaClientsTable[l],
                                               ConnectClient_get_clientId(srClientsTable[k]));
                                           ConnectClient_set_nameBuf(
                                               srRaClientsTable[l],
                                               ConnectClient_get_nameBuf(srClientsTable[k]));
                                           ConnectClient_set_portBuf(
                                               srRaClientsTable[l],
                                               ConnectClient_get_portBuf(srClientsTable[k]));
                                           tmp_ssl = SslFd_get_ssl(
                                               ConnectClient_get_sslFd(srRaClientsTable[l]));
                                           SslFd_set_ssl_nf(
                                               ConnectClient_get_sslFd(srRaClientsTable[l]),
                                               SslFd_get_ssl(
                                                 ConnectClient_get_sslFd(srClientsTable[k])));
                                           SslFd_set_ssl_nf(
                                               ConnectClient_get_sslFd(srClientsTable[k]),
                                               tmp_ssl);
                                           ConnectClient_set_state(
                                               srClientsTable[k],
                                               CONNECTCLIENT_STATE_FREE);
                                           break;
                                         }
                                       }
                                       if (l != ServerRealm_get_raClientsLimit(pointer)) {
                                         ConnectClient_set_state(
                                             srRaClientsTable[l],
                                             CONNECTCLIENT_STATE_ACCEPTED);
                                         ServerRealm_increase_connectedRaClients(pointer);
                                         if ((task = ConnectClient_get_task(srClientsTable[k]))) {
                                           TaskScheduler_removeTask(scheduler, task);
                                           ConnectClient_set_task(srClientsTable[k], NULL);
                                         }
                                         sprintf((char*) &buff[5], AF_VER("AFSERVER"));
                                         n = strlen((char*) &buff[5]);
                                         buff[0] = AF_S_ADMIN_LOGIN; /* sending message */
                                         buff[1] = ServerRealm_get_realmType(pointer);	/* type of connection */
                                         buff[2] = AF_RA_UNDEFINED;
                                         buff[3] = n >> 8; /* high bits of message length */
                                         buff[4] = n;      /* low bits of message length */
                                         SslFd_send_message(ServerRealm_get_realmType(pointer) | TYPE_SSL,
                                             ConnectClient_get_sslFd(
                                               srRaClientsTable[l]),
                                             buff, n+5);
                                       }
                                       else {
                                         aflog(LOG_T_MANAGE, LOG_I_WARNING,
                                             "realm[%s]: Client[%s]: remote admin -- limit EXCEEDED",
                                             get_realmname(config, j), get_clientname(pointer, k));
                                         buff[0] = AF_S_CANT_OPEN; /* sending message */
                                         SslFd_send_message(ServerRealm_get_realmType(pointer) | TYPE_SSL | TYPE_ZLIB,
                                             ConnectClient_get_sslFd(
                                               srClientsTable[k]),
                                             buff, 5);
                                         remove_client(pointer, k, &allset, &wset, scheduler);
                                       }
                                     }
                                     break;
                                   }
            case AF_S_KEEP_ALIVE: {
                                    aflog(LOG_T_CLIENT, LOG_I_DEBUG,
                                        "realm[%s]: Client[%s]: Keep alive packet",
                                        get_realmname(config, j), get_clientname(pointer, k));
                                    break;
                                  }
            case AF_S_ENABLE_MULTI: {
                                      aflog(LOG_T_CLIENT, LOG_I_INFO,
                                          "realm[%s]: Client[%s]: MULTI enabled: %d",
                                          get_realmname(config, j), get_clientname(pointer, k), buff[1]);
                                      ConnectClient_set_multi(srClientsTable[k], CONNECTCLIENT_MULTI_ENABLED);
                                      break;
                                    }
            default : {
                        aflog(LOG_T_CLIENT, LOG_I_ERR,
                            "realm[%s]: Client[%s]: Unrecognized message - CLOSING",
                            get_realmname(config, j), get_clientname(pointer, k));
                        remove_client(pointer, k, &allset, &wset, scheduler);
                      }
          }
        }
      /* ------------------------------------ */
      for (k = 0; k < ServerRealm_get_raClientsLimit(pointer); ++k)
        if ((ConnectClient_get_state(srRaClientsTable[k]) > CONNECTCLIENT_STATE_FREE) &&
            (FD_ISSET(SslFd_get_fd(ConnectClient_get_sslFd(srRaClientsTable[k])), &rset))) {
          if (ConnectClient_get_state(srRaClientsTable[k]) == CONNECTCLIENT_STATE_CONNECTING) {
            make_ssl_initialize(ConnectClient_get_sslFd(srRaClientsTable[k]));
            aflog(LOG_T_MANAGE, LOG_I_DDEBUG,
                "realm[%s]: new Client[%s] (ra): SSL_accept",
                get_realmname(config, j), get_raclientname(pointer, k));
            switch (make_ssl_accept(ConnectClient_get_sslFd(srRaClientsTable[k]))) {
              case 2: {
                        close (SslFd_get_fd(ConnectClient_get_sslFd(srRaClientsTable[k])));
                        FD_CLR(SslFd_get_fd(ConnectClient_get_sslFd(srRaClientsTable[k])), &allset);
                        SSL_clear(SslFd_get_ssl(ConnectClient_get_sslFd(srRaClientsTable[k])));
                        ConnectClient_set_state(srRaClientsTable[k], CONNECTCLIENT_STATE_FREE);
                        if ((task = ConnectClient_get_task(srRaClientsTable[k]))) {
                          TaskScheduler_removeTask(scheduler, task);
                          ConnectClient_set_task(srRaClientsTable[k], NULL);
                        }
                        ServerRealm_decrease_connectedClients(pointer);
                        aflog(LOG_T_MANAGE, LOG_I_ERR,
                            "realm[%s]: new Client[%s] (ra): DENIED by SSL_accept",
                            get_realmname(config, j), get_raclientname(pointer, k));
                      }
              case 1: {
                        continue;
                      }
              default: {
                         aflog(LOG_T_MANAGE, LOG_I_DEBUG,
                             "realm[%s]: new Client[%s] (ra): ACCEPTED by SSL_accept",
                             get_realmname(config, j), get_raclientname(pointer, k));
                         ConnectClient_set_state(srRaClientsTable[k], CONNECTCLIENT_STATE_AUTHORIZING);
                         continue;
                       }
            }
          }
          aflog(LOG_T_MANAGE, LOG_I_DDEBUG,
              "realm[%s]: Client[%s] (ra): commfd: FD_ISSET",
              get_realmname(config, j), get_raclientname(pointer, k));
          n = SslFd_get_message(ServerRealm_get_realmType(pointer) | TYPE_SSL | TYPE_ZLIB,
              ConnectClient_get_sslFd(
                srRaClientsTable[k]),
              buff, (-1) * HeaderBuffer_to_read(ConnectClient_get_header(srRaClientsTable[k])));
          if (n == -1) {
            if (errno == EAGAIN) {
              aflog(LOG_T_MANAGE, LOG_I_DDEBUG,
                  "realm[%s]: Client[%s] (ra): commfd: EAGAIN",
                  get_realmname(config, j), get_raclientname(pointer, k));
              continue;
            }
            else {
              aflog(LOG_T_MANAGE, LOG_I_ERR,
                  "realm[%s]: Client[%s] (ra): commfd: ERROR: %d",
                  get_realmname(config, j), get_raclientname(pointer, k), errno);
              n = 0;
            }
          }
          else if (n != 5) {
            if (n != 0) {
              aflog(LOG_T_MANAGE, LOG_I_WARNING,
                  "realm[%s]: Client[%s] (ra): header length = %d --> buffering",
                  get_realmname(config, j), get_raclientname(pointer, k), n);
              HeaderBuffer_store(ConnectClient_get_header(srRaClientsTable[k]), buff, n);
              if (HeaderBuffer_to_read(ConnectClient_get_header(srRaClientsTable[k])) == 0) {
                HeaderBuffer_restore(ConnectClient_get_header(srRaClientsTable[k]), buff);
                n = 5;
              }
              else {
                continue;
              }
            }
          }
          if (n==0) { 
            remove_raclient(pointer, k, &allset, &wset, scheduler);
            aflog(LOG_T_MANAGE, LOG_I_INFO,
                "realm[%s]: Client[%s] (ra): commfd: CLOSED",
                get_realmname(config, j), get_raclientname(pointer, k));
            continue;
          }

          numofcon = buff[1];
          numofcon = numofcon << 8;
          numofcon += buff[2]; /* this is id of user */
          length = buff[3];
          length = length << 8;
          length += buff[4]; /* this is length of message */ 

          if (ConnectClient_get_state(srRaClientsTable[k]) < CONNECTCLIENT_STATE_AUTHORIZING) {
            aflog(LOG_T_MANAGE, LOG_I_WARNING,
                "realm[%s]: Client[%s] (ra): Impossible behaviour --> ignoring",
                get_realmname(config, j), get_raclientname(pointer, k));
            continue;
          }
          if ((ConnectClient_get_state(srRaClientsTable[k]) == CONNECTCLIENT_STATE_AUTHORIZING) &&
              (buff[0] != AF_S_LOGIN) && (buff[0] != AF_S_ADMIN_LOGIN)) {
            buff[0] = AF_S_WRONG;
          }
          
          time(&now);
          ConnectClient_set_lastActivity(srRaClientsTable[k], now);

          switch (buff[0]) {
            case AF_S_LOGIN : {
                                if ((ConnectClient_get_state(srRaClientsTable[k]) == 
                                      CONNECTCLIENT_STATE_AUTHORIZING) &&
                                    (numofcon==(ServerRealm_get_password(pointer)[0]*256+ServerRealm_get_password(pointer)[1])) &&
                                    (length==(ServerRealm_get_password(pointer)[2]*256+ServerRealm_get_password(pointer)[3]))) {
                                  ConnectClient_set_multi(srRaClientsTable[k], CONNECTCLIENT_MULTI_DISABLED);
                                  for (l = 0; l < ServerRealm_get_clientsLimit(pointer); ++l) {
                                    if (ConnectClient_get_state(srClientsTable[l]) ==
                                        CONNECTCLIENT_STATE_FREE) {
                                      aflog(LOG_T_MANAGE | LOG_T_CLIENT, LOG_I_INFO,
                                          "realm[%s]: Client[%s] (ra) --> Client[%s]",
                                          get_realmname(config, j),
                                          get_raclientname(pointer, k), get_clientname(pointer, l));
                                      SslFd_set_fd(
                                          ConnectClient_get_sslFd(srClientsTable[l]),
                                          SslFd_get_fd(
                                            ConnectClient_get_sslFd(srRaClientsTable[k])));
                                      ConnectClient_set_connectTime(
                                          srClientsTable[l],
                                          ConnectClient_get_connectTime(srRaClientsTable[k]));
                                      ConnectClient_set_lastActivity(
                                          srClientsTable[l],
                                          ConnectClient_get_lastActivity(srRaClientsTable[k]));
#ifdef HAVE_LIBPTHREAD
                                      ConnectClient_set_tunnelType(
                                          srClientsTable[l],
                                          ConnectClient_get_tunnelType(srRaClientsTable[k]));
#endif
                                      ConnectClient_set_clientId(
                                          srClientsTable[l],
                                          ConnectClient_get_clientId(srRaClientsTable[k]));
                                      ConnectClient_set_nameBuf(
                                          srClientsTable[l],
                                          ConnectClient_get_nameBuf(srRaClientsTable[k]));
                                      ConnectClient_set_portBuf(
                                          srClientsTable[l],
                                          ConnectClient_get_portBuf(srRaClientsTable[k]));
                                      tmp_ssl = SslFd_get_ssl(
                                          ConnectClient_get_sslFd(srClientsTable[l]));
                                      SslFd_set_ssl_nf(
                                          ConnectClient_get_sslFd(srClientsTable[l]),
                                          SslFd_get_ssl(
                                            ConnectClient_get_sslFd(srRaClientsTable[k])));
                                      SslFd_set_ssl_nf(
                                          ConnectClient_get_sslFd(srRaClientsTable[k]),
                                          tmp_ssl);
                                      ConnectClient_set_usrCliPair(
                                          srClientsTable[l],
                                          ConnectClient_get_usrCliPair(srRaClientsTable[k]));
                                      ConnectClient_set_state(srRaClientsTable[k], CONNECTCLIENT_STATE_FREE);
                                      break;
                                    }
                                  }
                                  if (l != ServerRealm_get_clientsLimit(pointer)) {
                                    ConnectClient_set_state(srClientsTable[l], CONNECTCLIENT_STATE_ACCEPTED);
                                    aflog(LOG_T_CLIENT, LOG_I_INFO,
                                        "realm[%s]: Client[%s]: pass ok - ACCESS GRANTED",
                                        get_realmname(config, j), get_clientname(pointer, l));
                                    buff[0] = AF_S_LOGIN; /* sending message */
                                    buff[1] = ConnectClient_get_limit(
                                        srClientsTable[l]) >> 8;/* high bits of user number */
                                    buff[2] = ConnectClient_get_limit(
                                        srClientsTable[l]);     /* low bits of user number */
                                    buff[3] = ServerRealm_get_realmType(pointer);	/* type of connection */
                                    SslFd_send_message(ServerRealm_get_realmType(pointer) | TYPE_SSL | TYPE_ZLIB,
                                        ConnectClient_get_sslFd(
                                          srClientsTable[l]),
                                        buff, 5);
                                    if ((task = ConnectClient_get_task(srRaClientsTable[k]))) {
                                      TaskScheduler_removeTask(scheduler, task);
                                      ConnectClient_set_task(srRaClientsTable[k], NULL);
                                    }
                                    if (ServerRealm_get_maxIdle(pointer)) {
                                      ConnectClient_set_timer(srClientsTable[l],
                                          timeval_create(ServerRealm_get_maxIdle(pointer), 0));
                                      task = Task_new(ConnectClient_get_timerp(srClientsTable[l]),
                                          RCTfunction,
                                          RCTdata_new(config, j, l, 0, RCT_REASON_MAXIDLE, &allset, &wset),
                                          RCTdata_free);
                                      ConnectClient_set_task(srClientsTable[l], task);
                                      TaskScheduler_addTask(scheduler, task);
                                    }
                                    if (ServerRealm_get_basePortOn(pointer) == 1) {
                                      long tmp_val;
                                      char tmp_tab[6];
                                      if (check_long(
                                            UsrCli_get_listenPortName(
                                              srUsersClientsTable[
                                              ConnectClient_get_usrCliPair(srClientsTable[l])]),
                                            &tmp_val)) {
                                        aflog(LOG_T_CLIENT, LOG_I_ERR,
                                            "realm[%s]: INVALID listenport - removing Client[%s]",
                                            get_realmname(config, j), get_clientname(pointer, l));
                                        remove_client(pointer, l, &allset, &wset, scheduler);
                                        break;
                                      }
                                      tmp_val = tmp_val%65536;
                                      memset(tmp_tab, 0, 6);
                                      sprintf(tmp_tab, "%d", (int)tmp_val);
                                      ipfam = 0x01;
#ifdef AF_INET6
                                      if (TYPE_IS_IPV4(ServerRealm_get_realmType(pointer))) {
                                        ipfam |= 0x02;
                                      }
                                      else if (TYPE_IS_IPV6(ServerRealm_get_realmType(pointer))) {
                                        ipfam |= 0x04;
                                      }
#endif
                                      while (ip_listen(ConnectClient_get_listenFdp(srClientsTable[l]),
                                            UsrCli_get_listenHostName(srUsersClientsTable[
                                              ConnectClient_get_usrCliPair(srClientsTable[l])]) ?
                                            UsrCli_get_listenHostName(srUsersClientsTable[
                                              ConnectClient_get_usrCliPair(srClientsTable[l])]) :
                                            ServerRealm_get_hostName(pointer),
                                            tmp_tab, (&len), ipfam)) {
                                        tmp_val = (tmp_val+1)%65536;
                                        memset(tmp_tab, 0, 6);
                                        sprintf(tmp_tab, "%d", (int)tmp_val);
                                      }
                                      ServerRealm_set_addressLength(pointer, len);
                                      FD_SET(ConnectClient_get_listenFd(srClientsTable[l]), &allset);
                                      maxfdp1 = (maxfdp1>(ConnectClient_get_listenFd(srClientsTable[l])+1)) ?
                                        maxfdp1 : (ConnectClient_get_listenFd(srClientsTable[l])+1);
                                      aflog(LOG_T_CLIENT, LOG_I_INFO,
                                          "realm[%s]: Client[%s]: listenport=%s",
                                          get_realmname(config, j), get_clientname(pointer, l), tmp_tab);
                                    }
                                  }
                                  else {
                                    aflog(LOG_T_CLIENT, LOG_I_WARNING,
                                        "realm[%s]: client limit EXCEEDED", get_realmname(config, j));
                                    buff[0] = AF_S_CANT_OPEN; /* sending message */
                                    SslFd_send_message(ServerRealm_get_realmType(pointer) | TYPE_SSL | TYPE_ZLIB,
                                        ConnectClient_get_sslFd(
                                          srRaClientsTable[k]),
                                        buff, 5);
                                    remove_raclient(pointer, k, &allset, &wset, scheduler);
                                  }
                                }
                                else if ((ConnectClient_get_state(srRaClientsTable[k]) ==
                                      CONNECTCLIENT_STATE_ACCEPTED) && (numofcon == 0)) {
                                  n = SslFd_get_message(ServerRealm_get_realmType(pointer),
                                      ConnectClient_get_sslFd(
                                        srRaClientsTable[k]),
                                      buff, length);
                                  buff[n] = 0;
                                  aflog(LOG_T_MANAGE, LOG_I_INFO,
                                      "realm[%s]: Client[%s] (ra): ID received: %s",
                                      get_realmname(config, j), get_raclientname(pointer, k), buff);
                                  ConnectClient_set_sClientId(srRaClientsTable[k], (char*) buff);
                                }
                                else {
                                  aflog(LOG_T_MANAGE, LOG_I_ERR,
                                      "realm[%s]: Client[%s] (ra): Wrong password - CLOSING",
                                      get_realmname(config, j), get_raclientname(pointer, k));
                                  remove_raclient(pointer, k, &allset, &wset, scheduler);
                                }
                                break;
                              }
            case AF_S_WRONG: {
                               aflog(LOG_T_MANAGE, LOG_I_ERR,
                                   "realm[%s]: Client[%s] (ra): Wrong message - CLOSING",
                                   get_realmname(config, j), get_raclientname(pointer, k));
                               remove_raclient(pointer, k, &allset, &wset, scheduler);
                               break;
                             }
            case AF_S_ADMIN_LOGIN: {
                                     if ((ConnectClient_get_state(srRaClientsTable[k]) ==
                                           CONNECTCLIENT_STATE_AUTHORIZING) &&
                                         (numofcon==(ServerRealm_get_password(pointer)[0]*256+ServerRealm_get_password(pointer)[1])) &&
                                         (length==(ServerRealm_get_password(pointer)[2]*256+ServerRealm_get_password(pointer)[3]))) {
                                       aflog(LOG_T_MANAGE, LOG_I_INFO,
                                           "realm[%s]: Client[%s] (ra): NEW remote admin -- pass OK",
                                           get_realmname(config, j), get_raclientname(pointer, k));
                                       ConnectClient_set_state(
                                           srRaClientsTable[k],
                                           CONNECTCLIENT_STATE_ACCEPTED);
                                       ServerRealm_increase_connectedRaClients(pointer);
                                       if ((task = ConnectClient_get_task(srRaClientsTable[k]))) {
                                         TaskScheduler_removeTask(scheduler, task);
                                         ConnectClient_set_task(srRaClientsTable[k], NULL);
                                       }
                                       sprintf((char*) &buff[5], AF_VER("AFSERVER"));
                                       n = strlen((char*) &buff[5]);
                                       buff[0] = AF_S_ADMIN_LOGIN; /* sending message */
                                       buff[1] = ServerRealm_get_realmType(pointer);	/* type of connection */
                                       buff[2] = AF_RA_UNDEFINED;
                                       buff[3] = n >> 8; /* high bits of message length */
                                       buff[4] = n;      /* low bits of message length */
                                       SslFd_send_message(ServerRealm_get_realmType(pointer) | TYPE_SSL | TYPE_ZLIB,
                                           ConnectClient_get_sslFd(
                                             srRaClientsTable[k]),
                                           buff, n+5);
                                     }
                                     break;
                                   }
            case AF_S_ADMIN_CMD: {
                                   if (ConnectClient_get_state(srRaClientsTable[k]) ==
                                       CONNECTCLIENT_STATE_ACCEPTED) {
                                     if ((n = serve_admin(config, j, k, buff))) {
                                       if (n == 1) {
                                         aflog(LOG_T_MANAGE, LOG_I_NOTICE,
                                             "realm[%s]: Client[%s] (ra): remote admin -- closing",
                                             get_realmname(config, j), get_raclientname(pointer, k));
                                         remove_raclient(pointer, k, &allset, &wset, scheduler);
                                       }
                                       else {
                                         for (i = 0; i < ServerConfiguration_get_realmsNumber(config); ++i) {
                                           srClientsTable = ServerRealm_get_clientsTable(scRealmsTable[i]);
                                           l = get_clientnumber(scRealmsTable[i], n-2);
                                           if (l != -1) {
                                             aflog(LOG_T_MANAGE, LOG_I_NOTICE,
                                                 "realm[%s]: Client[%s] (ra): remote admin: KICKING realm[%s]: Client[%s]",
                                                 get_realmname(config, j), get_raclientname(pointer, k),
                                                 get_realmname(config, i),
                                                 get_clientname(scRealmsTable[i], l));
                                             buff[0] = AF_S_CLOSING; /* closing */
                                             SslFd_send_message(ServerRealm_get_realmType(scRealmsTable[i]),
                                                 ConnectClient_get_sslFd(
                                                   srClientsTable[l]),
                                                 buff, 5);
                                             time(&now);
                                             aflog(LOG_T_CLIENT, LOG_I_NOTICE,
                                                 "REALM: %s CLIENT: %s IP: %s PORT: %s DURATION: %s",
                                                 get_realmname(config, j),
                                                 get_clientname(scRealmsTable[i], l),
                                                 ConnectClient_get_nameBuf(srClientsTable[l]),
                                                 ConnectClient_get_portBuf(srClientsTable[l]),
                                                 timeperiod(now - ConnectClient_get_connectTime(
                                                     srClientsTable[l])));
                                             if (ServerRealm_get_auditOn(scRealmsTable[i])) {
                                               while (AuditList_get_first(
                                                     ConnectClient_get_auditList(
                                                       srClientsTable[l]))) {
                                                 aflog(LOG_T_CLIENT, LOG_I_NOTICE,
                                                     "USERID: %d IP: %s PORT: %s CONNECTED: %s DURATION: %s",
                                                     AuditListNode_get_userId(
                                                       AuditList_get_first(
                                                         ConnectClient_get_auditList(
                                                           srClientsTable[l]))),
                                                     AuditListNode_get_nameBuf(
                                                       AuditList_get_first(
                                                         ConnectClient_get_auditList(
                                                           srClientsTable[l]))),
                                                     AuditListNode_get_portBuf(
                                                       AuditList_get_first(
                                                         ConnectClient_get_auditList(
                                                           srClientsTable[l]))),
                                                     localdate(
                                                       AuditListNode_get_connectTimep(
                                                         AuditList_get_first(
                                                           ConnectClient_get_auditList(
                                                             srClientsTable[l])))),
                                                     timeperiod(
                                                       AuditListNode_get_duration(
                                                         AuditList_get_first(
                                                           ConnectClient_get_auditList(
                                                             srClientsTable[l])))));
                                                     AuditList_delete_first(
                                                         ConnectClient_get_auditList(
                                                           srClientsTable[l]));
                                               }
                                             }
                                             remove_client(scRealmsTable[i], l,
                                                 &allset, &wset, scheduler);
                                             break;
                                           }
                                         }
                                       }
                                     }
                                   }
                                   else {
                                     aflog(LOG_T_MANAGE, LOG_I_ERR,
                                         "realm[%s]: Client[%s] (ra): remote admin -- security VIOLATION",
                                         get_realmname(config, j), get_raclientname(pointer, k));
                                     remove_raclient(pointer, k, &allset, &wset, scheduler);
                                   }
                                   break;
                                 }
            case AF_S_KEEP_ALIVE: {
                                    aflog(LOG_T_MANAGE, LOG_I_DEBUG,
                                        "realm[%s]: Client[%s] (ra): Keep alive packet",
                                        get_realmname(config, j), get_raclientname(pointer, k));
                                    break;
                                  }
            default : {
                        aflog(LOG_T_MANAGE, LOG_I_ERR,
                            "realm[%s]: Client[%s] (ra): Unrecognized message - CLOSING",
                            get_realmname(config, j), get_raclientname(pointer, k));
                        remove_raclient(pointer, k, &allset, &wset, scheduler);
                      }
          }
        }
      /* ------------------------------------ */    
      for (l = 0; l < ServerRealm_get_userClientPairs(pointer); ++l) {
        if (FD_ISSET(UsrCli_get_manageFd(srUsersClientsTable[l]), &rset)) {
          
          aflog(LOG_T_CLIENT, LOG_I_DDEBUG,
              "realm[%s]: managefd: FD_ISSET", get_realmname(config, j));
          len = ServerRealm_get_addressLength(pointer);
#ifdef HAVE_LIBPTHREAD
          sent = get_new_socket(UsrCli_get_manageFd(srUsersClientsTable[l]),
              ServerRealm_get_tunnelType(pointer),ServerRealm_get_clientAddress(pointer), &len, &tunneltype); 
#else
          sent = accept(UsrCli_get_manageFd(srUsersClientsTable[l]), ServerRealm_get_clientAddress(pointer), &len);
#endif
          if (sent == -1) {
            if (errno == EAGAIN) {
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "realm[%s]: managefd: FD_ISSET --> EAGAIN", get_realmname(config, j));
            }
            else {
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "realm[%s]: managefd: FD_ISSET --> errno=%d", get_realmname(config, j), errno);
            }
            break;
          }
          flags = fcntl(sent, F_GETFL, 0);
          fcntl(sent, F_SETFL, flags | O_NONBLOCK);
          for (k = 0; k < ServerRealm_get_clientsLimit(pointer); ++k) {
            if (ConnectClient_get_state(srClientsTable[k]) == CONNECTCLIENT_STATE_FREE) {
              ConnectClient_set_clientId(srClientsTable[k], ServerRealm_get_clientsCounter(pointer));
              ServerRealm_increase_clientsCounter(pointer);
              aflog(LOG_T_CLIENT, LOG_I_INFO,
                  "realm[%s]: new Client[%s]: CONNECTING",
                  get_realmname(config, j), get_clientname(pointer, k));
              SslFd_set_fd(ConnectClient_get_sslFd(srClientsTable[k]), sent);
              ConnectClient_set_usrCliPair(srClientsTable[k], l);
              time(&now);
              ConnectClient_set_connectTime(srClientsTable[k], now);
              ConnectClient_set_lastActivity(srClientsTable[k], now);
#ifdef HAVE_LIBPTHREAD
              ConnectClient_set_tunnelType(srClientsTable[k], tunneltype);
#endif
              aflog(LOG_T_CLIENT, LOG_I_INFO,
                  "realm[%s]: new Client[%s] IP:%s", get_realmname(config, j), get_clientname(pointer, k),
                  sock_ntop(ServerRealm_get_clientAddress(pointer), len, ConnectClient_get_nameBuf(srClientsTable[k]),
                    ConnectClient_get_portBuf(srClientsTable[k]), ServerRealm_get_dnsLookupsOn(pointer)));
              FD_SET(SslFd_get_fd(ConnectClient_get_sslFd(srClientsTable[k])), &allset);
              maxfdp1 = (maxfdp1 > (SslFd_get_fd(ConnectClient_get_sslFd(srClientsTable[k])) + 1)) ?
                maxfdp1 : (SslFd_get_fd(ConnectClient_get_sslFd(srClientsTable[k])) + 1);
              ServerRealm_increase_connectedClients(pointer);
              ConnectClient_set_timer(srClientsTable[k], timeval_create(ServerRealm_get_timeout(pointer), 0));
              task = Task_new(ConnectClient_get_timerp(srClientsTable[k]),
                  RCTfunction,
                  RCTdata_new(config, j, k, 0, RCT_REASON_TIMEOUT, &allset, &wset),
                  RCTdata_free);
              ConnectClient_set_task(srClientsTable[k], task);
              TaskScheduler_addTask(scheduler, task);
              ConnectClient_set_state(srClientsTable[k], CONNECTCLIENT_STATE_CONNECTING);
              break;
            }
          }
          if (k == ServerRealm_get_clientsLimit(pointer)) {
            for (k = 0; k < ServerRealm_get_raClientsLimit(pointer); ++k) {
              if (ConnectClient_get_state(srRaClientsTable[k]) ==
                  CONNECTCLIENT_STATE_FREE) {
                ConnectClient_set_clientId(srRaClientsTable[k], ServerRealm_get_clientsCounter(pointer));
                ServerRealm_increase_clientsCounter(pointer);
                aflog(LOG_T_MANAGE, LOG_I_INFO,
                    "realm[%s]: new Client[%s] (ra): CONNECTING",
                    get_realmname(config, j), get_raclientname(pointer, k));
                SslFd_set_fd(ConnectClient_get_sslFd(srRaClientsTable[k]), sent);
                ConnectClient_set_usrCliPair(srRaClientsTable[k], l);
                time(&now);
                ConnectClient_set_connectTime(srRaClientsTable[k], now);
                ConnectClient_set_lastActivity(srRaClientsTable[k], now);
#ifdef HAVE_LIBPTHREAD
                ConnectClient_set_tunnelType(srRaClientsTable[k], tunneltype);
#endif
                aflog(LOG_T_MANAGE, LOG_I_INFO,
                    "realm[%s]: new Client[%s] (ra) IP:%s",
                    get_realmname(config, j), get_raclientname(pointer, k),
                    sock_ntop(ServerRealm_get_clientAddress(pointer), len,
                      ConnectClient_get_nameBuf(srRaClientsTable[k]),
                      ConnectClient_get_portBuf(srRaClientsTable[k]),
                      ServerRealm_get_dnsLookupsOn(pointer)));
                FD_SET(SslFd_get_fd(ConnectClient_get_sslFd(srRaClientsTable[k])), &allset);
                maxfdp1 = (maxfdp1 > (SslFd_get_fd(ConnectClient_get_sslFd(srRaClientsTable[k])) + 1)) ?
                  maxfdp1 : (SslFd_get_fd(ConnectClient_get_sslFd(srRaClientsTable[k])) + 1);
                ServerRealm_increase_connectedClients(pointer);
                ConnectClient_set_timer(srRaClientsTable[k],
                    timeval_create(ServerRealm_get_timeout(pointer), 0));
                task = Task_new(ConnectClient_get_timerp(srRaClientsTable[k]),
                    RCTfunction,
                    RCTdata_new(config, j, k, 1, RCT_REASON_TIMEOUT, &allset, &wset),
                    RCTdata_free);
                ConnectClient_set_task(srRaClientsTable[k], task);
                TaskScheduler_addTask(scheduler, task);
                ConnectClient_set_state(srRaClientsTable[k], CONNECTCLIENT_STATE_CONNECTING);
                break;
              }
            }
            if (k == ServerRealm_get_raClientsLimit(pointer)) {
              aflog(LOG_T_CLIENT | LOG_T_MANAGE, LOG_I_WARNING,
                  "realm[%s]: client limit EXCEEDED", get_realmname(config, j));
              close(sent);
            }
          }
          break;
        }
      }
    } /* realms loop */
  }
}
