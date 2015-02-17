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

#include "afclient.h"

#include <unistd.h>

static struct option long_options[] = {
  {"help", 0, 0, 'h'},
  {"udpmode", 0, 0, 'u'},
  {"reverseudp", 0, 0, 'U'},
  {"servername", 1, 0, 'n'},
  {"manageport", 1, 0, 'm'},
  {"hostname", 1, 0, 'd'},
  {"portnum", 1, 0, 'p'},
  {"verbose", 0, 0, 'v'},
  {"keyfile", 1, 0, 'k'},
  {"cerfile", 1, 0, 'c'},
  {"storefile", 1, 0, 's'},
  {"cfgfile", 1, 0, 'f'},
  {"log", 1, 0, 'o'},
  {"pass", 1, 0, 301},
  {"ignorepkeys", 0, 0, 302},
#ifdef AF_INET6
  {"ipv4", 0, 0, '4'},
  {"ipv6", 0, 0, '6'},
#endif
#ifdef HAVE_LIBDL
  {"load", 1, 0, 'l'},
  {"Load", 1, 0, 'L'},
#endif
  {"id", 1, 0, 'i'},
  {"dateformat", 1, 0, 'D'},
  {"remoteadmin", 0, 0, 'r'},
#ifdef HAVE_LIBPTHREAD
  {"use-https", 0, 0, 'S'},
  {"proxyname", 1, 0, 'P'},
  {"proxyport", 1, 0, 'X'},
  {"pa-t-basic", 0, 0, 'B'},
  {"pa-cred", 1, 0, 'C'},
#endif
  {"version", 0, 0, 'V'},
  {"keep-alive", 1, 0, 'K'},
  {"ar-tries", 1, 0, 'A'},
  {"ar-delay", 1, 0, 'T'},
  {"ar-start", 0, 0, 305},
  {"ar-quit", 0, 0, 306},
  {"noar", 0, 0, 307},
  {"localname", 1, 0, 311},
  {"localport", 1, 0, 312},
  {"localdesname", 1, 0, 313},
  {0, 0, 0, 0}
};

ClientConfiguration* cconfig;

int
main(int argc, char **argv)
{

  /*
   * variables
   */
  
  int i, n, numofcon, length, buflength, temp, temp2 = 0;
#ifdef HAVE_LINUX_SOCKIOS_H
  int notsent;
  socklen_t aLength;
#endif
  ConnectUser** usersTable = NULL;
  unsigned char buff[9000];
  char hostname[100];
  int maxfdp1;
  socklen_t addressLength;
  struct sockaddr* clientAddress;
  fd_set rset, allset, wset, tmpset;
  struct timeval keepAlive;
  char verbose = 0;
  HttpProxyOptions* hpo = HttpProxyOptions_new();
  char hpoUsed = 0;
  ArOptions* ao = ArOptions_new();
  ClientRealm* pointer;
  char aoUsed = 0;
  char passwordWasSet = 0;
  char* realmId = NULL;
  char* serverName = NULL;
  char* managePort = NULL;
  char* hostName = NULL;
  PortList*  destinationPorts = PortList_new();
  char* localName = NULL;
  char* localPort = NULL;
  char* localDestinationName = NULL;
  char* keys = NULL;
  char* certif = NULL;
  char* store = NULL;
  char* dateformat = NULL;
  char* kaTimeout = NULL;
  char* filenam = NULL;
  char ipFamily = 0;
  unsigned char password[4] = {1, 2, 3, 4};
  char udpMode = 0;
  char reverseMode = 0;
  char remoteMode = 0;
  char realmType = 0;
  char ignorePublicKeys = 0;
  struct sigaction act;
#ifdef HAVE_LIBDL
  Module *moduleA = Module_new(), *moduleB = Module_new();
#endif
  const SSL_METHOD* method;
  SSL_CTX* ctx = NULL;

  /*
   * initialization
   */

#ifdef HAVE_LIBPTHREAD
  if (hpo == NULL) {
    printf("Problems with memory allocation... exiting\n");
    exit(1);
  }
#endif

  if (ao == NULL) {
    printf("Problems with memory allocation... exiting\n");
    exit(1);
  }
  
#ifdef HAVE_LIBDL
  if ((moduleA == NULL) || (moduleB == NULL)) {
    printf("Problems with memory allocation... exiting\n");
    exit(1);
  }
#endif
  sigfillset(&(act.sa_mask));
  act.sa_flags = 0;
	
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, NULL);
  act.sa_handler = client_sig_int;
  sigaction(SIGINT, &act, NULL);
  sigaction(SIGTERM, &act, NULL);
  act.sa_handler = client_sig_alrm;
  sigaction(SIGALRM, &act, NULL);
  
#ifdef HAVE_LIBPTHREAD
  remember_mainthread();
#endif

#ifdef AF_INET6
#define GETOPT_LONG_AF_INET6(x) "46"x
#else
#define GETOPT_LONG_AF_INET6(x) x
#endif
#ifdef HAVE_LIBPTHREAD
#define GETOPT_LONG_LIBPTHREAD(x) "SP:X:BC:"x
#else
#define GETOPT_LONG_LIBPTHREAD(x) x
#endif
#ifdef HAVE_LIBDL
#define GETOPT_LONG_LIBDL(x) "l:L:"x
#else
#define GETOPT_LONG_LIBDL(x) x
#endif
  
  while ((n = getopt_long(argc, argv,
          GETOPT_LONG_LIBDL(GETOPT_LONG_LIBPTHREAD(
              GETOPT_LONG_AF_INET6("huUn:m:d:p:vk:c:s:o:i:D:rP:X:VK:A:T:f:")))
          , long_options, 0)) != -1) {
    switch (n) {
      case 'h': {
        client_long_usage(AF_VER("Active port forwarder (client)"));
        break;
      }
      case 'n': {
        serverName = optarg;
        break;
      }
#ifdef HAVE_LIBPTHREAD
      case 'S': {
        HttpProxyOptions_use_https(hpo);
        hpoUsed = 1;
        break;
      }
      case 'P': {
        HttpProxyOptions_set_proxyname(hpo, optarg);
        hpoUsed = 1;
        break;
      }
      case 'X': {
        HttpProxyOptions_set_proxyport(hpo, optarg);
        hpoUsed = 1;
        break;
      }
      case 'B': {
        HttpProxyOptions_set_proxyauth_type(hpo, PROXYAUTH_TYPE_BASIC);
        hpoUsed = 1;
        break;
      }
      case 'C': {
        HttpProxyOptions_set_proxyauth_cred(hpo, optarg);
        hpoUsed = 1;
        break;
      }
#endif
      case 'i': {
        realmId = optarg;
        break;
      }
      case 'm': {
        managePort = optarg;
        break;
      }
      case 'd': {
        hostName = optarg;
        break;
      }
      case 'p': {
        PortList_insert_back(destinationPorts, PortListNode_new(optarg));
        break;
      }
      case 'v': {
        ++verbose;
        break;
      }
      case 'u': {
        udpMode = 1;
        break;
      }
      case 'U': {
        reverseMode = 1;
        break;
      }
      case 'k': {
        keys = optarg;
        break;
      }
      case 'c': {
        certif = optarg;
        break;
      }
      case 's': {
        store = optarg;
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
        n = strlen(optarg);
        memset(password, 0, 4);
        for (i = 0; i < n; ++i) {
          password[i%4] += optarg[i];
        }
        passwordWasSet = 1;
        break;
      }
      case 302: {
        ignorePublicKeys = 1;
        break;
      }
      case 305: {
        ArOptions_set_arStart(ao, AR_OPTION_ENABLED);
        aoUsed = 1;
        break;
      }
      case 306: {
        ArOptions_set_arQuit(ao, AR_OPTION_ENABLED);
        aoUsed = 1;
        break;
      }
      case 307: {
        ArOptions_set_arPremature(ao, AR_OPTION_DISABLED);
        aoUsed = 1;
        break;
      }
      case 311: {
        localName = optarg;
        break;
      }
      case 312: {
        localPort = optarg;
        break;
      }
      case 313: {
        localDestinationName = optarg;
        break;
      }
#ifdef AF_INET6
      case '4': {
        if (ipFamily != 0) {
          ipFamily = -1;
        }
        else {
          ipFamily = 4;
        }
        break;
      }
      case '6': {
        if (ipFamily != 0) {
          ipFamily = -1;
        }
        else {
          ipFamily = 6;
        }
        break;
      }
#endif
#ifdef HAVE_LIBDL
      case 'l': {
        Module_set_fileName(moduleA, optarg);
        break;
      }
      case 'L': {
        Module_set_fileName(moduleB, optarg);
        break;
      }
#endif
      case 'D': {
            dateformat = optarg;
            break;
      }
      case 'r': {
                  remoteMode = 1;
                  break;
                }
      case 'V': {
            printf("%s\n", (AF_VER("Active port forwarder (client)")));
            exit(0);
          break;
          }
      case 'K': {
        kaTimeout = optarg;
        break;
      }
      case 'A': {
        ArOptions_set_s_arTries(ao, optarg);
        aoUsed = 1;
        break;
      }
      case 'T': {
        ArOptions_set_s_arDelay(ao, optarg);
        aoUsed = 1;
        break;
      }
      case '?': {
        client_short_usage("");
        break;
      }
    }
  }

  if (optind < argc) {
    client_short_usage("Unrecognized non-option elements");
  }

  if (filenam != NULL) {
    cconfig = cparsefile(filenam, &n);
    if (n) {
      printf("parsing failed! line:%d\n", n);
      exit(1);
    }
    else {
      if (keys == NULL) {
        if (ClientConfiguration_get_keysFile(cconfig) == NULL) {
          ClientConfiguration_set_keysFile(cconfig, "client.rsa");
        }
      }
      else {
        ClientConfiguration_set_keysFile(cconfig, keys);
      }
      if (certif != NULL) {
        ClientConfiguration_set_certificateFile(cconfig, certif);
      }
      if (store == NULL) {
        if (ClientConfiguration_get_storeFile(cconfig) == NULL) {
          ClientConfiguration_set_storeFile(cconfig, "known_hosts");
        }
      }
      else {
        ClientConfiguration_set_storeFile(cconfig, store);
      }
      if (dateformat != NULL) {
        ClientConfiguration_set_dateFormat(cconfig, dateformat);
      }
      if (ignorePublicKeys) {
        ClientConfiguration_set_ignorePublicKeys(cconfig, ignorePublicKeys);
      }

      initializelogging(verbose, ClientConfiguration_get_dateFormat(cconfig));
      
      aflog(LOG_T_INIT, LOG_I_INFO,
          "client's cfg file OK! (readed realms: %d)", ClientConfiguration_get_realmsNumber(cconfig));
      if ((ClientConfiguration_get_realmsNumber(cconfig) == 0) ||
          (ClientConfiguration_get_realmsTable(cconfig) == NULL) ||
          ((pointer = ClientConfiguration_get_realmsTable(cconfig)[0]) == NULL)) {
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "Working without sense is really without sense...");
        exit(1);
      }
      if (hpoUsed) {
        ClientRealm_set_httpProxyOptions(pointer, hpo);
      }
      else {
        HttpProxyOptions_free(&hpo);
      }
      if (aoUsed) {
        ClientRealm_set_arOptions(pointer, ao);
      }
      else {
        ArOptions_free(&ao);
      }
      if ((serverName != NULL) && (ClientRealm_get_serverName(pointer) == NULL)) {
        ClientRealm_set_serverName(pointer, serverName);
      }
      if ((managePort != NULL) && (ClientRealm_get_managePort(pointer) == NULL)) {
        ClientRealm_set_managePort(pointer, managePort);
      }
      if ((hostName != NULL) && (ClientRealm_get_hostName(pointer) == NULL)) {
        ClientRealm_set_hostName(pointer, hostName);
      }
      if ((PortList_get_size(destinationPorts) != 0) &&
          (PortList_get_size(ClientRealm_get_destinationPorts(pointer)) == 0)) {
        ClientRealm_set_destinationPorts(pointer, destinationPorts);
      }
      if ((realmId != NULL) && (ClientRealm_get_realmId(pointer) == NULL)) {
        ClientRealm_set_realmId(pointer, realmId);
      }
      if ((localName != NULL) && (ClientRealm_get_localName(pointer) == NULL)) {
        ClientRealm_set_localName(pointer, localName);
      }
      if ((localPort != NULL) && (ClientRealm_get_localPort(pointer) == NULL)) {
        ClientRealm_set_localPort(pointer, localPort);
      }
      if ((localDestinationName != NULL) & (ClientRealm_get_localDestinationName(pointer) == NULL)) {
        ClientRealm_set_localDestinationName(pointer, localDestinationName);
      }
      if ((kaTimeout != NULL) && (ClientRealm_get_sKeepAliveTimeout(pointer) == NULL)) {
        ClientRealm_set_sKeepAliveTimeout(pointer, kaTimeout);
      }
      if (reverseMode) {
        aflog(LOG_T_INIT, LOG_I_WARNING,
            "Warning: reverseudp will be ignored");
      }
      if (udpMode) {
        aflog(LOG_T_INIT, LOG_I_WARNING,
            "Warning: udpmode will be ignored");
      }
      if (remoteMode) {
        aflog(LOG_T_INIT, LOG_I_WARNING,
            "Warning: remoteadmin will be ignored");
      }
      if (passwordWasSet) {
        aflog(LOG_T_INIT, LOG_I_WARNING,
            "Warning: pass will be ignored");
      }
#ifdef HAVE_LIBDL
      if (Module_get_fileName(moduleA)) {
        aflog(LOG_T_INIT, LOG_I_WARNING,
            "Warning: load will be ignored");
      }
      if (Module_get_fileName(moduleB)) {
        aflog(LOG_T_INIT, LOG_I_WARNING,
            "Warning: Load will be ignored");
      }
#endif
    }
  }
  else {
    cconfig = ClientConfiguration_new();
    if (cconfig == NULL) {
      printf("Can't allocate memory for client configuration... exiting\n");
      exit(1);
    }
    ClientConfiguration_set_keysFile(cconfig, keys);
    ClientConfiguration_set_certificateFile(cconfig, certif);
    ClientConfiguration_set_storeFile(cconfig, store);
    ClientConfiguration_set_dateFormat(cconfig, dateformat);
    ClientConfiguration_set_realmsNumber(cconfig, 1);
    ClientConfiguration_set_ignorePublicKeys(cconfig, ignorePublicKeys);

    initializelogging(verbose, ClientConfiguration_get_dateFormat(cconfig));

    if (ClientConfiguration_get_keysFile(cconfig) == NULL) {
      ClientConfiguration_set_keysFile(cconfig, "client.rsa");
    }
    if (ClientConfiguration_get_storeFile(cconfig) == NULL) {
      ClientConfiguration_set_storeFile(cconfig, "known_hosts");
    }
    ClientConfiguration_set_realmsTable(cconfig,
        calloc(ClientConfiguration_get_realmsNumber(cconfig), sizeof(ClientRealm*)));
    if (ClientConfiguration_get_realmsTable(cconfig) == NULL) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "Can't allocate memory for ClientRealm* table... exiting");
      exit(1);
    }
    pointer = ClientRealm_new();
    if (pointer == NULL) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "Can't allocate memory for ClientRealm structure... exiting");
      exit(1);
    }
    
    ClientConfiguration_get_realmsTable(cconfig)[0] = pointer;
    ClientRealm_set_serverName(pointer, serverName);
    ClientRealm_set_managePort(pointer, managePort);
    ClientRealm_set_hostName(pointer, hostName);
    ClientRealm_set_destinationPorts(pointer, destinationPorts);
    ClientRealm_set_realmId(pointer, realmId);
    ClientRealm_set_httpProxyOptions(pointer, hpo);
    ClientRealm_set_arOptions(pointer, ao);
    ClientRealm_set_password(pointer, password);
    ClientRealm_set_localName(pointer, localName);
    ClientRealm_set_localPort(pointer, localPort);
    ClientRealm_set_localDestinationName(pointer, localDestinationName);
    ClientRealm_set_realmId(pointer, realmId);
    ClientRealm_set_sKeepAliveTimeout(pointer, kaTimeout);
#ifdef HAVE_LIBDL
    ClientRealm_set_userModule(pointer, moduleA);
    ClientRealm_set_serviceModule(pointer, moduleB);
#endif
    
    if (reverseMode) {
      if (ClientRealm_get_clientMode(pointer) == CLIENTREALM_MODE_TCP) {
        ClientRealm_set_clientMode(pointer, CLIENTREALM_MODE_REVERSE);
      }
      else {
        ClientRealm_set_clientMode(pointer, CLIENTREALM_MODE_UNKNOWN);
      }
    }
    if (udpMode) {
      if (ClientRealm_get_clientMode(pointer) == CLIENTREALM_MODE_TCP) {
        ClientRealm_set_clientMode(pointer, CLIENTREALM_MODE_UDP);
      }
      else {
        ClientRealm_set_clientMode(pointer, CLIENTREALM_MODE_UNKNOWN);
      }
    }
    if (remoteMode) {
      if (ClientRealm_get_clientMode(pointer) == CLIENTREALM_MODE_TCP) {
        ClientRealm_set_clientMode(pointer, CLIENTREALM_MODE_REMOTE);
      }
      else {
        ClientRealm_set_clientMode(pointer, CLIENTREALM_MODE_UNKNOWN);
      }
    }   
  }

  /*
   * WARNING: we have only one ClientRealm at the moment
   */
  
  if (ClientRealm_get_serverName(pointer) == NULL) {
    client_short_usage("Name of the server is required");
  }
  if (ClientRealm_get_clientMode(pointer) == CLIENTREALM_MODE_UNKNOWN) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "Conflicting/unknown client modes... exiting");
    exit(1);
  }
  if (ClientRealm_get_managePort(pointer) == NULL) {
    ClientRealm_set_managePort(pointer, "50126");
    if (ClientRealm_get_clientMode(pointer) == CLIENTREALM_MODE_REVERSE)
      client_short_usage("Port on the server is required in reverse mode");
  }
#ifdef HAVE_LIBPTHREAD
  if ((HttpProxyOptions_get_proxyname(ClientRealm_get_httpProxyOptions(pointer))) ||
      (HttpProxyOptions_get_proxyport(ClientRealm_get_httpProxyOptions(pointer)))) {
    if (ClientRealm_get_tunnelType(pointer) == CLIENTREALM_TUNNELTYPE_DIRECT) {
      ClientRealm_set_tunnelType(pointer, CLIENTREALM_TUNNELTYPE_HTTPPROXY);
    }
    else {
      ClientRealm_set_tunnelType(pointer, CLIENTREALM_TUNNELTYPE_UNKNOWN);
    }
  }
  if (ClientRealm_get_tunnelType(pointer) == CLIENTREALM_TUNNELTYPE_HTTPPROXY) {
    if (HttpProxyOptions_get_proxyport(ClientRealm_get_httpProxyOptions(pointer)) == NULL) {
      HttpProxyOptions_set_proxyport(ClientRealm_get_httpProxyOptions(pointer), "8080");
    }
  }
#endif
  if ((ClientRealm_get_clientMode(pointer) != CLIENTREALM_MODE_REVERSE) &&
      (ClientRealm_get_clientMode(pointer) != CLIENTREALM_MODE_REMOTE) &&
      (ClientRealm_get_hostName(pointer) == NULL)) {
    gethostname(hostname, 100);
    ClientRealm_set_hostName(pointer, hostname);
  }
  if ((ClientRealm_get_clientMode(pointer) != CLIENTREALM_MODE_REMOTE) &&
      (PortList_get_size(ClientRealm_get_destinationPorts(pointer)) == 0)) {
    client_short_usage("Destination port number is required");
  }
  
  if (ClientRealm_get_sKeepAliveTimeout(pointer)) {
    ClientRealm_set_keepAliveTimeout(pointer,
        check_value(ClientRealm_get_sKeepAliveTimeout(pointer), "Invalid timeout value"));
    keepAlive.tv_sec = ClientRealm_get_keepAliveTimeout(pointer);
    keepAlive.tv_usec = 0;
    ClientRealm_set_keepAlive(pointer, keepAlive);
  }
  ArOptions_evaluate_values(ClientRealm_get_arOptions(pointer));

  if (ignorePublicKeys) {
    ClientConfiguration_set_ignorePublicKeys(cconfig, ignorePublicKeys);
  }
  
#ifdef HAVE_LIBDL
  if (Module_loadModule(ClientRealm_get_userModule(pointer))) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "Loading a module %s failed!", Module_get_fileName(ClientRealm_get_userModule(pointer)));
      exit(1);
  }
  if (Module_loadModule(ClientRealm_get_serviceModule(pointer))) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "Loading a module %s failed!", Module_get_fileName(ClientRealm_get_serviceModule(pointer)));
      exit(1);
  }
#endif

  TYPE_SET_ZERO(realmType);
  TYPE_SET_SSL(realmType);
  TYPE_SET_ZLIB(realmType);

#ifdef AF_INET6
  if ((ipFamily != 0) && (ClientRealm_get_ipFamily(pointer) <= 0)) {
    ClientRealm_set_ipFamily(pointer, ipFamily);
  }
  if (ClientRealm_get_ipFamily(pointer) == -1) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "Conflicting types of ip protocol family... exiting");
    exit(1);
  }
  else if (ClientRealm_get_ipFamily(pointer) == 4) {
    TYPE_SET_IPV4(realmType);
  }
  else if (ClientRealm_get_ipFamily(pointer) == 6) {
    TYPE_SET_IPV6(realmType);
  }
#endif
  ipFamily = 0x01;
#ifdef AF_INET6
  if (TYPE_IS_IPV4(realmType)) {
    ipFamily |= 0x02;
  }
  else if (TYPE_IS_IPV6(realmType)) {
    ipFamily |= 0x04;
  }
#endif

  ClientRealm_set_ipFamily(pointer, ipFamily);
  ClientRealm_set_realmType(pointer, realmType);
  
  if (ClientRealm_get_clientMode(pointer) != CLIENTREALM_MODE_REVERSE) {
    SSL_library_init();

    /* Use the latest TLS version we can: */
    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    /* Both SSLv2 and SSLv3 are broken--refuse to use them;
       this should get us at least some version of TLS,
       ideally whatever the best both our OpenSSL library
       and the server's OpenSSL library can support:
    */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    if (SSL_CTX_set_cipher_list(ctx, "ALL:@STRENGTH") == 0) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "Setting cipher list failed... exiting");
      exit(1);
    }
    if ((temp2 = create_apf_dir(0))) {
      aflog(LOG_T_INIT, LOG_I_WARNING,
          "Warning: Creating ~/.apf directory failed (%d)", temp2);
      if ((temp2 = create_apf_dir(1))) {
        aflog(LOG_T_INIT, LOG_I_WARNING,
            "Warning: Creating ./apf directory failed (%d)", temp2);
      }
    }
    store = ClientConfiguration_get_storeFile(cconfig);
    if ((temp2 = create_publickey_store(&store))) {
      aflog(LOG_T_INIT, LOG_I_WARNING,
          "Warning: Something bad happened when creating public key store... (%d)", temp2);
    }
    ClientConfiguration_set_storeFile(cconfig, store);
    keys = ClientConfiguration_get_keysFile(cconfig);
    if ((temp2 = generate_rsa_key(&keys))) {
      aflog(LOG_T_INIT, LOG_I_WARNING,
          "Warning: Something bad happened when generating rsa keys... (%d)", temp2);
    }
    ClientConfiguration_set_keysFile(cconfig, keys);
    if (SSL_CTX_use_RSAPrivateKey_file(ctx, keys, SSL_FILETYPE_PEM) != 1) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "Setting rsa key failed (%s)... exiting", keys);
      exit(1);
    }

    certif = ClientConfiguration_get_certificateFile(cconfig);
    if (certif) {
      if (SSL_CTX_use_certificate_chain_file(ctx, certif) != 1) {
        aflog(LOG_T_INIT, LOG_I_CRIT,
            "Setting certificate failed (%s)... exiting", certif);
        exit(1);
      }
    }

    if ((ClientRealm_get_clientMode(pointer) != CLIENTREALM_MODE_REMOTE) &&
        (!verbose))
      daemon(0, 0);
    
    if (ClientRealm_get_clientMode(pointer) == CLIENTREALM_MODE_REMOTE) {
      temp2 = -1;
      if (PortList_get_size(ClientRealm_get_destinationPorts(pointer)) > 0) {
        if (ip_listen(&n, ClientRealm_get_serverName(pointer),
              PortListNode_get_portName(PortList_get_nth(ClientRealm_get_destinationPorts(pointer), 0)),
              &addressLength,
              ClientRealm_get_ipFamily(pointer))) {
#ifdef AF_INET6
          aflog(LOG_T_INIT, LOG_I_CRIT,
              "tcp_listen_%s error for %s, %s",
              (ClientRealm_get_ipFamily(pointer) & 0x02) ?
                "ipv4" :
                (ClientRealm_get_ipFamily(pointer) & 0x04) ?
                  "ipv6" :
                  "unspec",
              ClientRealm_get_serverName(pointer),
              PortListNode_get_portName(PortList_get_nth(ClientRealm_get_destinationPorts(pointer), 0)));
#else
          aflog(LOG_T_INIT, LOG_I_CRIT,
              "tcp_listen error for %s, %s", ClientRealm_get_serverName(pointer),
              PortListNode_get_portName(PortList_get_nth(ClientRealm_get_destinationPorts(pointer), 0)));
#endif
          exit(1);
        }
        clientAddress = malloc(addressLength);
        if (clientAddress == NULL) {
          aflog(LOG_T_INIT, LOG_I_CRIT,
              "Can't allocate memory for sockaddr structure... exiting");
          exit(1);
        }
        ClientRealm_set_addressLength(pointer, addressLength);
        ClientRealm_set_clientAddress(pointer, clientAddress);
        temp2 = accept(n, ClientRealm_get_clientAddress(pointer), &addressLength);
      }
    }

  }

  i = ArOptions_get_arTries(ClientRealm_get_arOptions(pointer));
  SslFd_set_fd(ClientRealm_get_masterSslFd(pointer), -1);

  do {  
    temp = 0;
    if (SslFd_get_fd(ClientRealm_get_masterSslFd(pointer)) != -1) {
      close(SslFd_get_fd(ClientRealm_get_masterSslFd(pointer)));
    }
    ClientRealm_closeUsersConnections(pointer);
    SslFd_set_ssl(ClientRealm_get_masterSslFd(pointer), NULL);
    
    if (ClientRealm_get_clientMode(pointer) != CLIENTREALM_MODE_REVERSE) {
      if (temp == 0) {
        if (initialize_client_stage1(pointer, ctx, buff,
              (ArOptions_get_arStart(ClientRealm_get_arOptions(pointer)) == AR_OPTION_ENABLED) ? 0 : 1,
            ClientConfiguration_get_ignorePublicKeys(cconfig))) {
          temp = 1;
        }
      }

      if ((temp == 0) && (ClientRealm_get_clientMode(pointer) == CLIENTREALM_MODE_REMOTE)) {
        return client_admin(ClientRealm_get_realmType(pointer),
                            ClientRealm_get_masterSslFd(pointer), buff, temp2,
                            ClientRealm_get_realmId(pointer));
      }

      if (temp == 0) {
        realmType = ClientRealm_get_realmType(pointer);
        if (initialize_client_stage2(pointer, buff,
                (ArOptions_get_arStart(ClientRealm_get_arOptions(pointer)) == AR_OPTION_ENABLED) ? 0 : 1)) {
          temp = 1;
        }
      }
    } /* !reverse */
    else {
      if (initialize_client_reverse_udp(pointer)) {
        temp = 1;
      }
    }

    if (temp == 0) {
      if (initialize_client_stage3(pointer, &buflength, &allset, &wset, &maxfdp1,
              (ArOptions_get_arStart(ClientRealm_get_arOptions(pointer)) == AR_OPTION_ENABLED) ? 0 : 1)) {
        temp = 1;
      }
    }

    /* UDP REVERSE MODE */

    if ((temp == 0) && (ClientRealm_get_clientMode(pointer) == CLIENTREALM_MODE_REVERSE)) {
      client_reverse_udp(pointer, buff, buflength);
    }

    if (i > 0) {
      --i;
    }
    if ((i != 0) && (temp == 1)) {
      aflog(LOG_T_INIT, LOG_I_INFO,
          "Trying to reconnect...");
      sleep(ArOptions_get_arDelay(ClientRealm_get_arOptions(pointer)));
      ClientRealm_set_realmType(pointer, realmType);
    }
    if (temp == 0) {
      break;
    }
  } while (i);

  /* NORMAL MODE */
	
  aflog(LOG_T_CLIENT, LOG_I_INFO,
      "CLIENT STARTED mode: %s", (ClientRealm_get_clientMode(pointer) == CLIENTREALM_MODE_UDP) ? "udp" : "tcp");
  aflog(LOG_T_CLIENT, LOG_I_INFO, "SERVER SSL: %s, ZLIB: %s, MODE: %s",
        (TYPE_IS_SSL(ClientRealm_get_realmType(pointer)) ?
         SSL_get_version(SslFd_get_ssl(ClientRealm_get_masterSslFd(pointer)))
         : "no"),
        (TYPE_IS_ZLIB(ClientRealm_get_realmType(pointer))) ? "yes" : "no",
        (TYPE_IS_TCP(ClientRealm_get_realmType(pointer))) ? "tcp" : "udp");
  aflog(LOG_T_CLIENT, LOG_I_INFO,
      "SERVER MULTI: %s", (TYPE_IS_SUPPORTED_MULTI(ClientRealm_get_realmType(pointer))) ? "yes" : "no");
  aflog(LOG_T_CLIENT, LOG_I_NOTICE,
      "CIPHER: %s VER: %s", SSL_get_cipher_name(SslFd_get_ssl(ClientRealm_get_masterSslFd(pointer))),
      SSL_get_cipher_version(SslFd_get_ssl(ClientRealm_get_masterSslFd(pointer))));
#ifdef HAVE_LIBDL
  if (Module_isModuleLoaded(ClientRealm_get_userModule(pointer))) {
    aflog(LOG_T_CLIENT, LOG_I_INFO,
        "LOADED MODULE: %s INFO: %s", Module_get_fileName(ClientRealm_get_userModule(pointer)),
        Module_function_info(ClientRealm_get_userModule(pointer)));
  }
  if (Module_isModuleLoaded(ClientRealm_get_serviceModule(pointer))) {
    aflog(LOG_T_CLIENT, LOG_I_INFO,
        "LOADED MODULE (ser): %s INFO: %s", Module_get_fileName(ClientRealm_get_serviceModule(pointer)),
        Module_function_info(ClientRealm_get_serviceModule(pointer)));
  }
#endif
  
  ClientRealm_send_realmId(pointer, buff);
  ClientRealm_enable_multi(pointer);
    
  for ( ; ; ) {
    rset = allset;
    tmpset = wset;
    aflog(LOG_T_MAIN, LOG_I_DDEBUG,
        "select");
    if (ClientRealm_get_sKeepAliveTimeout(pointer)) {
      if (select(maxfdp1, &rset, &tmpset, NULL, ClientRealm_get_keepAlivePointer(pointer)) == 0) {
        aflog(LOG_T_CLIENT, LOG_I_DEBUG,
            "timeout: sending keep-alive packet");
        buff[0] = AF_S_KEEP_ALIVE;
        SslFd_send_message(ClientRealm_get_realmType(pointer),
            ClientRealm_get_masterSslFd(pointer), buff, 5);
        keepAlive.tv_sec = ClientRealm_get_keepAliveTimeout(pointer);
        keepAlive.tv_usec = 0;
        ClientRealm_set_keepAlive(pointer, keepAlive);
      }
    }
    else {
      select(maxfdp1, &rset, &tmpset, NULL, NULL);
    }
    aflog(LOG_T_MAIN, LOG_I_DDEBUG,
        "after select...");

    usersTable = ClientRealm_get_usersTable(pointer);
    for (i = 0; i < ClientRealm_get_usersLimit(pointer); ++i) {
      if ((ConnectUser_get_state(usersTable[i]) == S_STATE_OPEN) ||
          (ConnectUser_get_state(usersTable[i]) == S_STATE_STOPPED) ||
          (ConnectUser_get_state(usersTable[i]) == S_STATE_KICKING)) {
        if (FD_ISSET(ConnectUser_get_connFd(usersTable[i]), &rset)) { /* FD_ISSET   CONTABLE[i].CONNFD   RSET */
          aflog(LOG_T_USER, LOG_I_DDEBUG,
              "user[%d]: FD_ISSET", i);
          n = read(ConnectUser_get_connFd(usersTable[i]), &buff[5], 8091);
          if (n == -1) {
            if (errno == EAGAIN) {
              continue;
            }
            aflog(LOG_T_USER, LOG_I_ERR,
                "error (%d): while reading from service", errno);
            n = 0;
          }
#ifdef HAVE_LINUX_SOCKIOS_H
# ifdef SIOCOUTQ
          if (ioctl(SslFd_get_fd(ClientRealm_get_masterSslFd(pointer)), SIOCOUTQ, &notsent)) {
            aflog(LOG_T_USER, LOG_I_CRIT,
                "ioctl error -> exiting...");
            exit(1);
          }
          if (ClientRealm_get_clientMode(pointer) == CLIENTREALM_MODE_UDP) {
            aLength = 4;
            if (getsockopt(SslFd_get_fd(ClientRealm_get_masterSslFd(pointer)),
                  SOL_SOCKET, SO_SNDBUF, &temp2, &aLength) != -1) {
              if (temp2 != buflength) {
                buflength = temp2;
                aflog(LOG_T_USER, LOG_I_WARNING,
                    "Send buffer size changed...");
              }
            }
            if (buflength <= notsent + n + 5) { /* when we can't send this */
              aflog(LOG_T_USER, LOG_I_WARNING,
                  "user[%d]: DROP size:%d, buf:%d, w:%d/%d", i, n+5, buflength, notsent, buflength);
# else
          if (ioctl(master.commfd, TIOCOUTQ, &notsent)) {
            aflog(LOG_T_USER, LOG_I_CRIT,
                "ioctl error -> exiting...");
            exit(1);
          }
          if (ClientRealm_get_clientMode(pointer) == CLIENTREALM_MODE_UDP) {
            len = 4;
            if (getsockopt(master.commfd, SOL_SOCKET, SO_SNDBUF, &temp2, &len) != -1) {
              if (temp2 != buflength) {
                buflength = temp2;
                aflog(LOG_T_USER, LOG_I_WARNING,
                    "Send buffer size changed...");
              }
            }
            if (notsent <= n + 5) { /* when we can't send this */
              aflog(LOG_T_USER, LOG_I_WARNING,
                  "user[%d]: DROP size:%d, buf:%d, w:%d/%d", 
			      i, n+5, buflength, buflength-notsent, buflength);
# endif
              continue; /* drop this packet */
            }
          }
#endif
          if (n) {
#ifdef HAVE_LIBDL
              if (Module_isModuleLoaded(ClientRealm_get_serviceModule(pointer))) {
                switch ((temp2 = Module_function_filter(ClientRealm_get_serviceModule(pointer),
                        ConnectUser_get_nameBuf(usersTable[i]), &buff[5], &n))) {
                  case 1: case 4: {
                    aflog(LOG_T_USER, LOG_I_WARNING,
                        "user[%d] (by ser): PACKET IGNORED BY MODULE", i);
		    if (temp2 == 4) {
                      aflog(LOG_T_MAIN, LOG_I_INFO,
                          "RELEASED MODULE (ser): %s INFO: %s",
                          Module_get_fileName(ClientRealm_get_serviceModule(pointer)),
                          Module_function_info(ClientRealm_get_serviceModule(pointer)));
		      Module_releaseModule(ClientRealm_get_serviceModule(pointer));
		    }
                    continue;
                    break;
                  }
                  case 2: case 5: {
                    aflog(LOG_T_USER, LOG_I_NOTICE,
                        "user[%d] (by ser): DROPPED BY MODULE", i);
                    close(ConnectUser_get_connFd(usersTable[i]));
                    aflog(LOG_T_USER, LOG_I_DDEBUG,
                        "user[%d]: Closing connFd: %d", i, ConnectUser_get_connFd(usersTable[i]));
                    FD_CLR(ConnectUser_get_connFd(usersTable[i]), &allset);
                    FD_CLR(ConnectUser_get_connFd(usersTable[i]), &wset);
                    ConnectUser_set_state(usersTable[i], S_STATE_CLOSING);
                    BufList_clear(ConnectUser_get_bufList(usersTable[i]));
                    buff[0] = AF_S_CONCLOSED; /* closing connection */
                    buff[1] = i >> 8;	/* high bits of user number */
                    buff[2] = i;		/* low bits of user number */
                    SslFd_send_message(ClientRealm_get_realmType(pointer), ClientRealm_get_masterSslFd(pointer), buff, 5);
		    if (temp2 == 5) {
                      aflog(LOG_T_MAIN, LOG_I_INFO,
                          "RELEASED MODULE (ser): %s INFO: %s",
                          Module_get_fileName(ClientRealm_get_serviceModule(pointer)),
                          Module_function_info(ClientRealm_get_serviceModule(pointer)));
		      Module_releaseModule(ClientRealm_get_serviceModule(pointer));
		    }
		    continue;
                    break;
                  }
                  case 3: {
                    aflog(LOG_T_MAIN, LOG_I_INFO,
                        "RELEASED MODULE (ser): %s INFO: %s",
                          Module_get_fileName(ClientRealm_get_serviceModule(pointer)),
                          Module_function_info(ClientRealm_get_serviceModule(pointer)));
		      Module_releaseModule(ClientRealm_get_serviceModule(pointer));
                    break;
                  }
                }
              }
#endif
            buff[0] = AF_S_MESSAGE; /* sending message */
            buff[1] = i >> 8;	/* high bits of user number */
            buff[2] = i;		/* low bits of user number */
            buff[3] = n >> 8;	/* high bits of message length */
            buff[4] = n;		/* low bits of message length */
#ifdef HAVE_LINUX_SOCKIOS_H
            aflog(LOG_T_USER, LOG_I_DEBUG,
                "user[%d]: TO msglen: %d [%d/%d]", i, n,
# ifdef SIOCOUTQ
			notsent
# else
			buflength - notsent
# endif
			, buflength);
#else
            aflog(LOG_T_USER, LOG_I_DEBUG,
                "user[%d]: TO msglen: %d", i, n);
#endif
            SslFd_send_message(ClientRealm_get_realmType(pointer), ClientRealm_get_masterSslFd(pointer), buff, n+5);
          }
          else if (ClientRealm_get_clientMode(pointer) != CLIENTREALM_MODE_UDP) {
            aflog(LOG_T_USER, LOG_I_INFO,
                "user[%d]: CLOSING", i);
            close(ConnectUser_get_connFd(usersTable[i]));
            aflog(LOG_T_USER, LOG_I_DDEBUG,
                "user[%d]: Closing connFd: %d", i, ConnectUser_get_connFd(usersTable[i]));
            FD_CLR(ConnectUser_get_connFd(usersTable[i]), &allset);
            FD_CLR(ConnectUser_get_connFd(usersTable[i]), &wset);
            if (ConnectUser_get_state(usersTable[i]) == S_STATE_KICKING) {
              ConnectUser_set_state(usersTable[i], S_STATE_CLEAR);
            }
            else {
              ConnectUser_set_state(usersTable[i], S_STATE_CLOSING);
            }
            BufList_clear(ConnectUser_get_bufList(usersTable[i]));
            buff[0] = AF_S_CONCLOSED; /* closing connection */
            buff[1] = i >> 8;	/* high bits of user number */
            buff[2] = i;		/* low bits of user number */
            SslFd_send_message(ClientRealm_get_realmType(pointer), ClientRealm_get_masterSslFd(pointer), buff, 5);
          }
        } /* - FD_ISSET   CONTABLE[i].CONNFD   RSET */
      }
    }
    for (i = 0; i < ClientRealm_get_usersLimit(pointer); ++i) {
      if ((ConnectUser_get_state(usersTable[i]) == S_STATE_STOPPED) ||
          (ConnectUser_get_state(usersTable[i]) == S_STATE_KICKING)) {
        if (FD_ISSET(ConnectUser_get_connFd(usersTable[i]), &tmpset)) { /* FD_ISSET  CONTABLE[i].CONNFD  TMPSET */
          aflog(LOG_T_USER, LOG_I_DDEBUG,
              "user[%d]: FD_ISSET - WRITE", i);
          n = BufListNode_readMessageLength(BufList_get_first(ConnectUser_get_bufList(usersTable[i])));
          temp2 = write(ConnectUser_get_connFd(usersTable[i]),
              BufListNode_readMessage(BufList_get_first(ConnectUser_get_bufList(usersTable[i]))), n);
          if ((temp2 > 0) && (temp2 != n)) {
            BufListNode_set_actPtr(BufList_get_first(ConnectUser_get_bufList(usersTable[i])),
                BufListNode_get_actPtr(BufList_get_first(ConnectUser_get_bufList(usersTable[i]))) + temp2);
          }
          else if ((temp2 == -1) && (errno == EAGAIN)) {
            aflog(LOG_T_USER, LOG_I_DEBUG,
                "user[%d]: Couldn't write?", i);
          }
          else if (temp2 == -1) {
            close(ConnectUser_get_connFd(usersTable[i]));
            aflog(LOG_T_USER, LOG_I_DDEBUG,
                "user[%d]: Closing connFd: %d", i, ConnectUser_get_connFd(usersTable[i]));
            FD_CLR(ConnectUser_get_connFd(usersTable[i]), &allset);
            FD_CLR(ConnectUser_get_connFd(usersTable[i]), &wset);
            if (ConnectUser_get_state(usersTable[i]) == S_STATE_KICKING) {
              ConnectUser_set_state(usersTable[i], S_STATE_CLEAR);
            }
            else {
              ConnectUser_set_state(usersTable[i], S_STATE_CLOSING);
            }
            buff[0] = AF_S_CONCLOSED; /* closing connection */
            buff[1] = i >> 8;	/* high bits of user number */
            buff[2] = i;		/* low bits of user number */
            SslFd_send_message(ClientRealm_get_realmType(pointer),
                ClientRealm_get_masterSslFd(pointer), buff, 5);
          }
          else {
            BufList_delete_first(ConnectUser_get_bufList(usersTable[i]));
            if (BufList_get_first(ConnectUser_get_bufList(usersTable[i])) == NULL) {
              FD_CLR(ConnectUser_get_connFd(usersTable[i]), &wset);
              buff[0] = AF_S_CAN_SEND; /* stopping transfer */
              buff[1] = i >> 8;       /* high bits of user number */
              buff[2] = i;            /* low bits of user number */
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "FROM user[%d]: BUFFERING MESSAGE ENDED", i);
              SslFd_send_message(ClientRealm_get_realmType(pointer),
                  ClientRealm_get_masterSslFd(pointer), buff, 5);
              if (ConnectUser_get_state(usersTable[i]) == S_STATE_KICKING) {
                close(ConnectUser_get_connFd(usersTable[i]));
                aflog(LOG_T_USER, LOG_I_DDEBUG,
                    "user[%d]: Closing connFd: %d", i, ConnectUser_get_connFd(usersTable[i]));
                FD_CLR(ConnectUser_get_connFd(usersTable[i]), &allset);
                FD_CLR(ConnectUser_get_connFd(usersTable[i]), &wset);
                ConnectUser_set_state(usersTable[i], S_STATE_CLEAR);
                buff[0] = AF_S_CONCLOSED; /* closing connection */
                buff[1] = i >> 8;	/* high bits of user number */
                buff[2] = i;		/* low bits of user number */
                SslFd_send_message(ClientRealm_get_realmType(pointer),
                    ClientRealm_get_masterSslFd(pointer), buff, 5);
              }
              else {
                ConnectUser_set_state(usersTable[i], S_STATE_OPEN);
              }
            }
          }
        } /* - FD_ISSET   CONTABLE[i].CONNFD   TMPSET */
      }
    }
    if (FD_ISSET(SslFd_get_fd(ClientRealm_get_masterSslFd(pointer)), &rset)) { /* FD_ISSET   MASTER.COMMFD   RSET */
      aflog(LOG_T_CLIENT, LOG_I_DDEBUG,
          "masterfd: FD_ISSET");
      n = SslFd_get_message(ClientRealm_get_realmType(pointer), ClientRealm_get_masterSslFd(pointer), buff, 5);
      if (n != 5) {
        aflog(LOG_T_CLIENT, LOG_I_ERR,
            "FATAL ERROR! (%d)", n);
        if (n == -1) {
          if (TYPE_IS_SSL(ClientRealm_get_realmType(pointer))) {
            get_ssl_error(ClientRealm_get_masterSslFd(pointer), "FE", n);
            continue; /* what happened? */
          }
        }
        if (n != 0)
          exit(1);
      }
      if (n == 0) { /* server quits -> we do the same... */
        i = ArOptions_get_arTries(ClientRealm_get_arOptions(pointer));
        if (ArOptions_get_arPremature(ClientRealm_get_arOptions(pointer)) == AR_OPTION_DISABLED) {
          i = 0;
        }
        if (i) {
          aflog(LOG_T_CLIENT, LOG_I_ERR,
              "SERVER: premature quit -> auto-reconnect enabled");
        }
        while (i) {
          ClientRealm_closeUsersConnections(pointer);
          close(SslFd_get_fd(ClientRealm_get_masterSslFd(pointer)));
          SslFd_set_ssl(ClientRealm_get_masterSslFd(pointer), NULL);
          sleep(ArOptions_get_arDelay(ClientRealm_get_arOptions(pointer)));
          aflog(LOG_T_CLIENT, LOG_I_INFO,
              "Trying to reconnect...");
          
          temp2 = 0;
          if (temp2 == 0) {
            if (initialize_client_stage1(pointer, ctx, buff, 0,
                  ClientConfiguration_get_ignorePublicKeys(cconfig))) {
              temp2 = 1;
            }
          }
          if (temp2 == 0) {
            if (initialize_client_stage2(pointer, buff, 0)) {
              temp2 = 1;
            }
          }
          if (temp2 == 0) {
            if (initialize_client_stage3(pointer, &buflength, &allset, &wset, &maxfdp1, 0)) {
              temp2 = 1;
            }
          }

          if (temp2 == 0) {
            n = 1;
            aflog(LOG_T_CLIENT, LOG_I_INFO,
                "Reconnected successfully...");
            usersTable = ClientRealm_get_usersTable(pointer);

            ClientRealm_send_realmId(pointer, buff);
            ClientRealm_enable_multi(pointer);

            break;
          }
          
          if (i > 0) {
            --i;
          }
        }
        if (n == 0) {
          aflog(LOG_T_CLIENT, LOG_I_CRIT,
              "SERVER: premature quit -> exiting...");
          exit(1);
        }
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
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "user[%d]: AF_S_CONCLOSED", numofcon);
          if ((numofcon>=0) && (numofcon<=ClientRealm_get_usersLimit(pointer))) {
            if (ConnectUser_get_state(usersTable[numofcon]) == S_STATE_CLOSING) {
              ConnectUser_set_state(usersTable[numofcon], S_STATE_CLEAR);
              aflog(LOG_T_USER, LOG_I_INFO,
                  "user[%d]: CLOSE CONFIRMED", numofcon);
            }
            else if (ConnectUser_get_state(usersTable[numofcon]) == S_STATE_OPEN) {
              aflog(LOG_T_USER, LOG_I_INFO,
                  "user[%d]: CLOSED", numofcon);
              close(ConnectUser_get_connFd(usersTable[numofcon]));
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "user[%d]: Closing connFd: %d", numofcon, ConnectUser_get_connFd(usersTable[numofcon]));
              FD_CLR(ConnectUser_get_connFd(usersTable[numofcon]), &allset);
              FD_CLR(ConnectUser_get_connFd(usersTable[numofcon]), &wset);
              ConnectUser_set_state(usersTable[numofcon], S_STATE_CLEAR);
              BufList_clear(ConnectUser_get_bufList(usersTable[numofcon]));
              buff[0] = AF_S_CONCLOSED; /* closing connection */
              buff[1] = numofcon >> 8;		/* high bits of user number */
              buff[2] = numofcon;		/* low bits of user number */
              SslFd_send_message(ClientRealm_get_realmType(pointer), ClientRealm_get_masterSslFd(pointer), buff, 5);
            }
            else if (ConnectUser_get_state(usersTable[numofcon]) == S_STATE_STOPPED) {
              ConnectUser_set_state(usersTable[numofcon], S_STATE_KICKING);
              aflog(LOG_T_USER, LOG_I_INFO,
                  "user[%d]: CLOSING...", numofcon);
            }
          }
          break;
        }
        case AF_S_CONOPEN : {
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "user[%d]: AF_S_CONOPEN", numofcon);
          if ((numofcon>=0) && (numofcon<=ClientRealm_get_usersLimit(pointer))) {
            if (ConnectUser_get_state(usersTable[numofcon]) == S_STATE_CLEAR) {
              n = SslFd_get_message(ClientRealm_get_realmType(pointer), ClientRealm_get_masterSslFd(pointer), buff, length);
              ConnectUser_set_nameBuf(usersTable[numofcon], (char*) buff);
              ConnectUser_set_portBuf(usersTable[numofcon], (char*) &buff[128]);
              aflog(LOG_T_USER, LOG_I_INFO,
                  "user[%d]: OPENING", numofcon);
              aflog(LOG_T_USER, LOG_I_INFO,
                  "user[%d]: IP:%s PORT:%s", numofcon,
              ConnectUser_get_nameBuf(usersTable[numofcon]), ConnectUser_get_portBuf(usersTable[numofcon]));
#ifdef HAVE_LIBDL
              if (Module_isModuleLoaded(ClientRealm_get_userModule(pointer)) &&
                  Module_function_allow(ClientRealm_get_userModule(pointer),
                    ConnectUser_get_nameBuf(usersTable[numofcon]),
                    ConnectUser_get_portBuf(usersTable[numofcon]))) {
                aflog(LOG_T_USER, LOG_I_WARNING,
                    "user[%d]: IT'S NOT ALLOWED - DROPPING", numofcon);
                buff[0] = AF_S_CANT_OPEN; /* not opening connection */
                buff[1] = numofcon >> 8;		/* high bits of user number */
                buff[2] = numofcon;		/* low bits of user number */
                SslFd_send_message(ClientRealm_get_realmType(pointer), ClientRealm_get_masterSslFd(pointer), buff, 5);
                continue;
              }
#endif
              if (ClientRealm_get_clientMode(pointer) == CLIENTREALM_MODE_UDP) {
                ipFamily = 0;
              }
              else {
                ipFamily = 0x01;
              }
#ifdef AF_INET6
              if (TYPE_IS_IPV4(ClientRealm_get_realmType(pointer))) {
                ipFamily |= 0x02;
              }
              else if (TYPE_IS_IPV6(ClientRealm_get_realmType(pointer))) {
                ipFamily |= 0x04;
              }
#endif
              temp2 = 0;
              if (n == 136) {
                if (PortList_get_size(ClientRealm_get_destinationPorts(pointer)) == 1) {
                  temp2 = 0;
                }
                else {
                  temp2 = buff[135] % PortList_get_size(ClientRealm_get_destinationPorts(pointer));
                }
              }
              if (ip_connect(&temp, ClientRealm_get_hostName(pointer),
                    PortListNode_get_portName(PortList_get_nth(ClientRealm_get_destinationPorts(pointer), temp2)), ipFamily,
                    ClientRealm_get_localDestinationName(pointer), NULL)) {
                aflog(LOG_T_USER, LOG_I_WARNING,
                    "user[%d]: CAN'T CONNECT to %s:%s - DROPPING", numofcon,
                    ClientRealm_get_hostName(pointer),
                    PortListNode_get_portName(PortList_get_nth(ClientRealm_get_destinationPorts(pointer), temp2)));
                buff[0] = AF_S_CANT_OPEN; /* not opening connection */
                buff[1] = numofcon >> 8;		/* high bits of user number */
                buff[2] = numofcon;		/* low bits of user number */
                SslFd_send_message(ClientRealm_get_realmType(pointer), ClientRealm_get_masterSslFd(pointer), buff, 5);
                continue;
              }
              ConnectUser_set_connFd(usersTable[numofcon], temp);
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "user[%d]: Setting connFd: %d", numofcon, temp);
              temp2 = fcntl(ConnectUser_get_connFd(usersTable[numofcon]), F_GETFL, 0);
              fcntl(ConnectUser_get_connFd(usersTable[numofcon]), F_SETFL, temp2 | O_NONBLOCK);
              FD_SET(ConnectUser_get_connFd(usersTable[numofcon]), &allset);
              maxfdp1 = (maxfdp1 > (ConnectUser_get_connFd(usersTable[numofcon]) + 1)) ?
                maxfdp1 : (ConnectUser_get_connFd(usersTable[numofcon]) + 1);
              buff[0] = AF_S_CONOPEN; /* opening connection */
              buff[1] = numofcon >> 8;		/* high bits of user number */
              buff[2] = numofcon; 		/* low bits of user number */
              SslFd_send_message(ClientRealm_get_realmType(pointer), ClientRealm_get_masterSslFd(pointer), buff, 5);
              ConnectUser_set_state(usersTable[numofcon], S_STATE_OPEN);
            }
          }
          break;
        }
        case AF_S_MESSAGE : {
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "user[%d]: AF_S_MESSAGE", numofcon);
          aflog(LOG_T_USER, LOG_I_DEBUG,
              "user[%d]: FROM msglen: %d", numofcon, length);
          n = SslFd_get_message(ClientRealm_get_realmType(pointer), ClientRealm_get_masterSslFd(pointer), buff, length);
          if ((numofcon>=0) && (numofcon<=ClientRealm_get_usersLimit(pointer))) {
            if (ConnectUser_get_state(usersTable[numofcon]) == S_STATE_OPEN) {
#ifdef HAVE_LIBDL
              if (Module_isModuleLoaded(ClientRealm_get_userModule(pointer))) {
                switch ((temp2 = Module_function_filter(ClientRealm_get_userModule(pointer),
                        ConnectUser_get_nameBuf(usersTable[numofcon]), buff, &n))) {
                  case 1: case 4:{
                    aflog(LOG_T_USER, LOG_I_WARNING,
                        "user[%d]: PACKET IGNORED BY MODULE", numofcon);
		    if (temp2 == 4) {
                      aflog(LOG_T_MAIN, LOG_I_INFO,
                          "RELEASED MODULE: %s INFO: %s",
                          Module_get_fileName(ClientRealm_get_userModule(pointer)),
                          Module_function_info(ClientRealm_get_userModule(pointer)));
		      Module_releaseModule(ClientRealm_get_userModule(pointer));
		    }
                    continue;
                    break;
                  }
                  case 2: case 5:{
                    aflog(LOG_T_USER, LOG_I_NOTICE,
                        "user[%d]: DROPPED BY MODULE", numofcon);
                    close(ConnectUser_get_connFd(usersTable[numofcon]));
                    aflog(LOG_T_USER, LOG_I_DDEBUG,
                        "user[%d]: Closing connFd: %d", numofcon, ConnectUser_get_connFd(usersTable[numofcon]));
                    FD_CLR(ConnectUser_get_connFd(usersTable[numofcon]), &allset);
                    FD_CLR(ConnectUser_get_connFd(usersTable[numofcon]), &wset);
                    ConnectUser_set_state(usersTable[numofcon], S_STATE_CLOSING);
                    BufList_clear(ConnectUser_get_bufList(usersTable[numofcon]));
                    buff[0] = AF_S_CONCLOSED; /* closing connection */
                    buff[1] = numofcon >> 8;	/* high bits of user number */
                    buff[2] = numofcon;		/* low bits of user number */
                    SslFd_send_message(ClientRealm_get_realmType(pointer), ClientRealm_get_masterSslFd(pointer), buff, 5);
		    if (temp2 == 5) {
                      aflog(LOG_T_MAIN, LOG_I_INFO,
                          "RELEASED MODULE: %s INFO: %s",
                          Module_get_fileName(ClientRealm_get_userModule(pointer)),
                          Module_function_info(ClientRealm_get_userModule(pointer)));
		      Module_releaseModule(ClientRealm_get_userModule(pointer));
		    }
		    continue;
                    break;
                  }
                  case 3: {
                    aflog(LOG_T_MAIN, LOG_I_INFO,
                        "RELEASED MODULE: %s INFO: %s",
                          Module_get_fileName(ClientRealm_get_userModule(pointer)),
                          Module_function_info(ClientRealm_get_userModule(pointer)));
		      Module_releaseModule(ClientRealm_get_userModule(pointer));
                    break;
                  }
                }
              }
#endif
              aflog(LOG_T_USER, LOG_I_DEBUG,
                  "user[%d]: FROM msglen: %d SENT", numofcon, n);
              temp2 = write(ConnectUser_get_connFd(usersTable[numofcon]), buff, n);
              if ((temp2 > 0) && (temp2 != n)) {
                BufList_insert_back(ConnectUser_get_bufList(usersTable[numofcon]),
                    BufListNode_new_message(temp2, n, buff));
                ConnectUser_set_state(usersTable[numofcon], S_STATE_STOPPED);
                FD_SET(ConnectUser_get_connFd(usersTable[numofcon]), &wset);
                buff[0] = AF_S_DONT_SEND; /* stopping transfer */
                buff[1] = numofcon >> 8;        /* high bits of user number */
                buff[2] = numofcon;             /* low bits of user number */
                aflog(LOG_T_USER, LOG_I_DDEBUG,
                    "FROM user[%d]: BUFFERING MESSAGE STARTED", numofcon);
                SslFd_send_message(ClientRealm_get_realmType(pointer), ClientRealm_get_masterSslFd(pointer), buff, 5);
              }
              else if ((temp2 == -1) && (errno == EAGAIN)) {
                BufList_insert_back(ConnectUser_get_bufList(usersTable[numofcon]),
                    BufListNode_new_message(0, n, buff));
                ConnectUser_set_state(usersTable[numofcon], S_STATE_STOPPED);
                FD_SET(ConnectUser_get_connFd(usersTable[numofcon]), &wset);
                buff[0] = AF_S_DONT_SEND; /* stopping transfer */
                buff[1] = numofcon >> 8;        /* high bits of user number */
                buff[2] = numofcon;             /* low bits of user number */
                aflog(LOG_T_USER, LOG_I_DDEBUG,
                    "FROM user[%d]: BUFFERING MESSAGE STARTED", numofcon);
                SslFd_send_message(ClientRealm_get_realmType(pointer), ClientRealm_get_masterSslFd(pointer), buff, 5);
              }
              else if (temp2 == -1) {
                close(ConnectUser_get_connFd(usersTable[numofcon]));
                aflog(LOG_T_USER, LOG_I_DDEBUG,
                    "user[%d]: Closing connFd: %d", numofcon, ConnectUser_get_connFd(usersTable[numofcon]));
                FD_CLR(ConnectUser_get_connFd(usersTable[numofcon]), &allset);
                FD_CLR(ConnectUser_get_connFd(usersTable[numofcon]), &wset);
                ConnectUser_set_state(usersTable[numofcon], S_STATE_CLOSING);
                BufList_clear(ConnectUser_get_bufList(usersTable[numofcon]));
                buff[0] = AF_S_CONCLOSED; /* closing connection */
                buff[1] = numofcon >> 8;	/* high bits of user number */
                buff[2] = numofcon;		/* low bits of user number */
                SslFd_send_message(ClientRealm_get_realmType(pointer), ClientRealm_get_masterSslFd(pointer), buff, 5);
              }
            }
            else if (ConnectUser_get_state(usersTable[numofcon]) == S_STATE_STOPPED) {
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "FROM user[%d]: BUFFERING MESSAGE", numofcon);
              BufList_insert_back(ConnectUser_get_bufList(usersTable[numofcon]),
                  BufListNode_new_message(0, n, buff));
            }
          }
          break;
        }
        case AF_S_CLOSING : { /* server shut down */
          n = 0;
          i = ArOptions_get_arTries(ClientRealm_get_arOptions(pointer));
          if (ArOptions_get_arQuit(ClientRealm_get_arOptions(pointer)) == AR_OPTION_DISABLED) {
            i = 0;
          }
          if (i) {
            aflog(LOG_T_CLIENT, LOG_I_ERR,
                "SERVER: CLOSED -> auto-reconnect enabled");
          }
          while (i) {
            ClientRealm_closeUsersConnections(pointer);
            close(SslFd_get_fd(ClientRealm_get_masterSslFd(pointer)));
            SslFd_set_ssl(ClientRealm_get_masterSslFd(pointer), NULL);
            sleep(ArOptions_get_arDelay(ClientRealm_get_arOptions(pointer)));
            aflog(LOG_T_CLIENT, LOG_I_INFO,
                "Trying to reconnect...");
          
            temp2 = 0;
            if (temp2 == 0) {
              if (initialize_client_stage1(pointer, ctx, buff, 0,
                    ClientConfiguration_get_ignorePublicKeys(cconfig))) {
                temp2 = 1;
              }
            }
            if (temp2 == 0) {
              if (initialize_client_stage2(pointer, buff, 0)) {
                temp2 = 1;
              }
            }
            if (temp2 == 0) {
              if (initialize_client_stage3(pointer, &buflength, &allset, &wset, &maxfdp1, 0)) {
                temp2 = 1;
              }
            }

            if (temp2 == 0) {
              n = 1;
              aflog(LOG_T_CLIENT, LOG_I_INFO,
                  "Reconnected successfully...");
              usersTable = ClientRealm_get_usersTable(pointer);

              ClientRealm_send_realmId(pointer, buff);
              ClientRealm_enable_multi(pointer);

              break;
            }
          
            if (i > 0) {
              --i;
            }
          }
          if (n == 0) {
            aflog(LOG_T_CLIENT, LOG_I_INFO,
                "SERVER: CLOSED -> exiting... cg: %ld bytes", getcg());
            exit(1);
          }
          break;
        }
        case AF_S_DONT_SEND: {
                               if ((ConnectUser_get_state(usersTable[numofcon]) == S_STATE_OPEN) ||
                                   (ConnectUser_get_state(usersTable[numofcon]) == S_STATE_STOPPED)) {
                                 aflog(LOG_T_USER, LOG_I_DEBUG,
                                     "user[%d]: AF_S_DONT_SEND", numofcon);
                                 FD_CLR(ConnectUser_get_connFd(usersTable[numofcon]), &allset);
                               }
                               else {
                                 aflog(LOG_T_USER, LOG_I_DEBUG,
                                     "user[%d]: AF_S_DONT_SEND - ignored", numofcon);
                               }
                               break;
                             }
        case AF_S_CAN_SEND: {
                              if ((ConnectUser_get_state(usersTable[numofcon]) == S_STATE_OPEN) ||
                                  (ConnectUser_get_state(usersTable[numofcon]) == S_STATE_STOPPED)) {
                                aflog(LOG_T_USER, LOG_I_DEBUG,
                                    "user[%d]: AF_S_CAN_SEND", numofcon);
                                FD_SET(ConnectUser_get_connFd(usersTable[numofcon]), &allset);
                              }
                              else {
                                aflog(LOG_T_USER, LOG_I_DEBUG,
                                    "user[%d]: AF_S_CAN_SEND - ignored", numofcon);
                              }
                              break;
                            }
        default : { /* unrecognized type of message -> exiting... */
          aflog(LOG_T_CLIENT, LOG_I_ERR,
              "SERVER: unrecognized message -> exiting... cg: %ld bytes", getcg());
          exit(1);
          break;
        }
      }
    } /* - FD_ISSET   MASTER.COMMFD   RSET */
  }
}
