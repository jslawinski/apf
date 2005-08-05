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

#include "afclient.h"

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
  {"storefile", 1, 0, 's'},
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
  {0, 0, 0, 0}
};

int
main(int argc, char **argv)
{
  /*
   * variables
   */
  
  int i, n, numofcon, length, buflength, notsent, temp, temp2; 
  ConnectUser** contable = NULL;
  SslFd* master = SslFd_new();
  unsigned char buff[9000];
  char hostname[100];
  int maxfdp1, usernum, usercon;
  socklen_t len, addrlen;
  struct sockaddr* cliaddr;
  fd_set rset, allset, wset, tmpset;
  struct timeval keepalive;
  int timeout = 0;
  char verbose = 0;
  char remote = 0;
  char sendkapackets = 0;
  char* name = NULL;
#ifdef HAVE_LIBPTHREAD
  HttpProxyOptions* hpo = HttpProxyOptions_new();
#endif
  ArOptions* ao = ArOptions_new();
  char* id = NULL;
  char* manage = NULL;
  char* desnam = NULL;
  char* despor = NULL;
  char* keys = NULL;
  char* store = NULL;
  char* dateformat = NULL;
  char* katimeout = NULL;
  char ipfam = 0;
  unsigned char pass[4] = {1, 2, 3, 4};
  char udp = 0;
  char reverse = 0;
  char tunneltype = 0;
  char type = 0;
  char ignorepkeys = 0;
  struct sigaction act;
#ifdef HAVE_LIBDL
  moduleT module = {0, NULL, NULL, NULL, NULL}, secmodule = {0, NULL, NULL, NULL, NULL};
#endif
  SSL_METHOD* method;
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
  
  if (master == NULL) {
    printf("Problems with memory allocation... exiting\n");
    exit(1);
  }
  
  sigfillset(&(act.sa_mask));
  act.sa_flags = 0;
	
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, NULL);
  act.sa_handler = client_sig_int;
  sigaction(SIGINT, &act, NULL);
  
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
              GETOPT_LONG_AF_INET6("huUn:m:d:p:vk:s:o:i:D:rP:X:VK:A:T:")))
          , long_options, 0)) != -1) {
    switch (n) {
      case 'h': {
        client_long_usage(AF_VER("Active port forwarder (client)"));
        break;
      }
      case 'n': {
        name = optarg;
        break;
      }
#ifdef HAVE_LIBPTHREAD
      case 'S': {
        HttpProxyOptions_use_https(hpo);
        break;
      }
      case 'P': {
        HttpProxyOptions_set_proxyname(hpo, optarg);
        break;
      }
      case 'X': {
        HttpProxyOptions_set_proxyport(hpo, optarg);
        break;
      }
      case 'B': {
        HttpProxyOptions_set_proxyauth_type(hpo, PROXYAUTH_TYPE_BASIC);
        break;
      }
      case 'C': {
        HttpProxyOptions_set_proxyauth_cred(hpo, optarg);
        break;
      }
#endif
      case 'i': {
        id = optarg;
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
      case 's': {
        store = optarg;
        break;
      }
      case 'o': {
        addlogtarget(optarg);
        break;
      }
      case 301: {
        n = strlen(optarg);
        memset(pass, 0, 4);
        for (i = 0; i < n; ++i) {
          pass[i%4] += optarg[i];
        }
        break;
      }
      case 302: {
        ignorepkeys = 1;
        break;
      }
      case 305: {
        ArOptions_set_arStart(ao, AR_OPTION_ENABLED);
        break;
      }
      case 306: {
        ArOptions_set_arQuit(ao, AR_OPTION_ENABLED);
        break;
      }
      case 307: {
        ArOptions_set_arPremature(ao, AR_OPTION_DISABLED);
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
#ifdef HAVE_LIBDL
      case 'l': {
        module.name = optarg;
        break;
      }
      case 'L': {
        secmodule.name = optarg;
        break;
      }
#endif
      case 'D': {
            dateformat = optarg;
            break;
      }
      case 'r': {
                  remote = 1;
                  break;
                }
      case 'V': {
            printf("%s\n", (AF_VER("Active port forwarder (client)")));
            exit(0);
          break;
          }
      case 'K': {
        katimeout = optarg;
        sendkapackets = 1;
        break;
      }
      case 'A': {
        ArOptions_set_s_arTries(ao, optarg);
        break;
      }
      case 'T': {
        ArOptions_set_s_arDelay(ao, optarg);
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

  if (name == NULL) {
    client_short_usage("Name of the server is required");
  }
  if (manage == NULL) {
    manage = "50126";
    if (reverse)
      client_short_usage("Port on the server is required in reverse mode");
  }
#ifdef HAVE_LIBPTHREAD
  if ((HttpProxyOptions_get_proxyname(hpo)) || (HttpProxyOptions_get_proxyport(hpo))) {
    if (tunneltype == 0) {
      tunneltype = 1;
    }
    else {
      tunneltype = -1;
    }
  }
  if (tunneltype == 1) {
    if (HttpProxyOptions_get_proxyport(hpo) == NULL) {
      HttpProxyOptions_set_proxyport(hpo, "8080");
    }
  }
#endif
  if (keys == NULL) {
    keys = "client.rsa";
  }
  if (store == NULL) {
    store = "known_hosts";
  }
  if ((reverse == 0) && (remote == 0) && (desnam == NULL)) {
    gethostname(hostname, 100);
    desnam = hostname;
  }
  if ((!remote) && (despor == NULL)) {
    client_short_usage("Destination port number is required");
  }

  initializelogging(verbose, dateformat);
  
  if (sendkapackets) {
    check_value(&timeout, katimeout, "Invalid timeout value");
    keepalive.tv_sec = timeout;
    keepalive.tv_usec = 0;
  }
  ArOptions_evaluate_values(ao);
  
#ifdef HAVE_LIBDL
  if (loadmodule(&module)) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "Loading a module %s failed!", module.name);
      exit(1);
  }
  if (loadmodule(&secmodule)) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "Loading a module %s failed!", secmodule.name);
      exit(1);
  }
#endif
  
  TYPE_SET_SSL(type);
  TYPE_SET_ZLIB(type);

#ifdef AF_INET6
  if (ipfam == -1) {
    aflog(LOG_T_INIT, LOG_I_CRIT,
        "Conflicting types of ip protocol family... exiting");
    exit(1);
  }
  else if (ipfam == 4) {
    TYPE_SET_IPV4(type);
  }
  else if (ipfam == 6) {
    TYPE_SET_IPV6(type);
  }
#endif
  ipfam = 0x01;
#ifdef AF_INET6
  if (TYPE_IS_IPV4(type)) {
    ipfam |= 0x02;
  }
  else if (TYPE_IS_IPV6(type)) {
    ipfam |= 0x04;
  }
#endif

  if (!reverse) {
    SSL_library_init();
    method = SSLv3_client_method();
    ctx = SSL_CTX_new(method);
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
    if ((temp2 = create_publickey_store(&store))) {
      aflog(LOG_T_INIT, LOG_I_WARNING,
          "Warning: Something bad happened when creating public key store... (%d)", temp2);
    }
    if ((temp2 = generate_rsa_key(&keys))) {
      aflog(LOG_T_INIT, LOG_I_WARNING,
          "Warning: Something bad happened when generating rsa keys... (%d)", temp2);
    }
    if (SSL_CTX_use_RSAPrivateKey_file(ctx, keys, SSL_FILETYPE_PEM) != 1) {
      aflog(LOG_T_INIT, LOG_I_CRIT,
          "Setting rsa key failed (%s)... exiting", keys);
      exit(1);
    }
    
    if ((!remote) && (!verbose))
      daemon(0, 0);
    
    if (remote) {
      temp2 = -1;
      if (despor) {
        if (ip_listen(&n, desnam, despor, &addrlen, ipfam)) {
#ifdef AF_INET6
          aflog(LOG_T_INIT, LOG_I_CRIT,
              "tcp_listen_%s error for %s, %s",
              (ipfam & 0x02)?"ipv4":(ipfam & 0x04)?"ipv6":"unspec", desnam, despor);
#else
          aflog(LOG_T_INIT, LOG_I_CRIT,
              "tcp_listen error for %s, %s", desnam, despor);
#endif
          exit(1);
        }
        cliaddr = malloc(addrlen);
        temp2 = accept(n, cliaddr, &addrlen);
      }
    }

  }

  i = ArOptions_get_arTries(ao);
  usernum = 0;
  SslFd_set_fd(master, -1);

  do {  
    temp = 0;
    if (SslFd_get_fd(master) != -1) {
      close(SslFd_get_fd(master));
    }
    close_connections(usernum, &contable);
    SslFd_set_ssl(master, NULL);
    
    if (!reverse) {
      if (temp == 0) {
#ifdef HAVE_LIBPTHREAD
        if (initialize_client_stage1(tunneltype, master, name, manage, hpo,
              ipfam, ctx, buff, pass,
              (ArOptions_get_arStart(ao) == AR_OPTION_ENABLED) ? 0 : 1,
              ignorepkeys)) {
#else
        if (initialize_client_stage1(tunneltype, master, name, manage, NULL,
              ipfam, ctx, buff, pass,
              (ArOptions_get_arStart(ao) == AR_OPTION_ENABLED) ? 0 : 1,
              ignorepkeys)) {
#endif
          temp = 1;
        }
      }

      if ((temp == 0) && remote) {
        return client_admin(type, master, buff, temp2, id);
      }

      if (temp == 0) {
        if (initialize_client_stage2(&type, master, &usernum, buff,
                (ArOptions_get_arStart(ao) == AR_OPTION_ENABLED) ? 0 : 1)) {
          temp = 1;
        }
      }
    } /* !reverse */
    else {
      if (initialize_client_reverse_udp(&usernum, master, name, manage, ipfam,
              (ArOptions_get_arStart(ao) == AR_OPTION_ENABLED) ? 0 : 1)) {
        temp = 1;
      }
    }

    if (temp == 0) {
      if (initialize_client_stage3(&contable, master, usernum, &buflength, &len, &allset, &wset, &maxfdp1,
              (ArOptions_get_arStart(ao) == AR_OPTION_ENABLED) ? 0 : 1)) {
        temp = 1;
      }
    }

    /* UDP REVERSE MODE */

    if ((temp == 0) && reverse) {
      client_reverse_udp(contable, master, desnam, despor, type, buff, buflength);
    }

    if (i > 0) {
      --i;
    }
    if ((i != 0) && (temp == 1)) {
      aflog(LOG_T_INIT, LOG_I_INFO,
          "Trying to reconnect...");
      mysleep(ArOptions_get_arDelay(ao));
    }
    if (temp == 0) {
      break;
    }
  } while (i);

  /* NORMAL MODE */
	
  aflog(LOG_T_CLIENT, LOG_I_INFO,
      "CLIENT STARTED mode: %s", (udp)?"udp":"tcp");
  aflog(LOG_T_CLIENT, LOG_I_INFO,
      "SERVER SSL: %s, ZLIB: %s, MODE: %s", (TYPE_IS_SSL(type))?"yes":"no",
		  (TYPE_IS_ZLIB(type))?"yes":"no", (TYPE_IS_TCP(type))?"tcp":"udp");
  aflog(LOG_T_CLIENT, LOG_I_NOTICE,
      "CIPHER: %s VER: %s", SSL_get_cipher_name(SslFd_get_ssl(master)),
      SSL_get_cipher_version(SslFd_get_ssl(master)));
#ifdef HAVE_LIBDL
  if (ismloaded(&module)) {
    aflog(LOG_T_CLIENT, LOG_I_INFO,
        "LOADED MODULE: %s INFO: %s", module.name, module.info());
  }
  if (ismloaded(&secmodule)) {
    aflog(LOG_T_CLIENT, LOG_I_INFO,
        "LOADED MODULE (ser): %s INFO: %s", secmodule.name, secmodule.info());
  }
#endif
	if (id != NULL) {
    buff[0] = AF_S_LOGIN;
    buff[1] = buff[2] = 0;
    n = strlen(id);
    memcpy(&buff[5], id, n);
    buff[3] = n >> 8;	/* high bits of message length */
    buff[4] = n;		/* low bits of message length */
    SslFd_send_message(type, master, buff, n+5);
    aflog(LOG_T_CLIENT, LOG_I_INFO,
        "ID SENT: %s", id);
  }
    
  for ( ; ; ) {
    rset = allset;
    tmpset = wset;
    aflog(LOG_T_MAIN, LOG_I_DDEBUG,
        "select");
    if (sendkapackets) {
      if (select(maxfdp1, &rset, &tmpset, NULL, &keepalive) == 0) {
        aflog(LOG_T_CLIENT, LOG_I_DEBUG,
            "timeout: sending keep-alive packet");
        buff[0] = AF_S_KEEP_ALIVE;
        SslFd_send_message(type, master, buff, 5);
        keepalive.tv_sec = timeout;
        keepalive.tv_usec = 0;
      }
    }
    else {
      select(maxfdp1, &rset, &tmpset, NULL, NULL);
    }
    aflog(LOG_T_MAIN, LOG_I_DDEBUG,
        "after select...");

    for (i = 0; i < usernum; ++i) {
      if ((ConnectUser_get_state(contable[i]) == S_STATE_OPEN) ||
          (ConnectUser_get_state(contable[i]) == S_STATE_STOPPED)) {
        if (FD_ISSET(ConnectUser_get_connFd(contable[i]), &rset)) { /* FD_ISSET   CONTABLE[i].CONNFD   RSET */
          aflog(LOG_T_USER, LOG_I_DDEBUG,
              "user[%d]: FD_ISSET", i);
          n = read(ConnectUser_get_connFd(contable[i]), &buff[5], 8091);
          if (n == -1) {
            aflog(LOG_T_USER, LOG_I_ERR,
                "error (%d): while reading from service", n);
            n = 0;
          }
#ifdef HAVE_LINUX_SOCKIOS_H
# ifdef SIOCOUTQ
          if (ioctl(SslFd_get_fd(master), SIOCOUTQ, &notsent)) {
            aflog(LOG_T_USER, LOG_I_CRIT,
                "ioctl error -> exiting...");
            exit(1);
          }
          if (udp) {
            len = 4;
            if (getsockopt(SslFd_get_fd(master), SOL_SOCKET, SO_SNDBUF, &temp2, &len) != -1) {
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
          if (udp) {
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
              if (ismloaded(&secmodule)) {
                switch ((temp2 = secmodule.filter(ConnectUser_get_nameBuf(contable[i]), &buff[5], &n))) {
                  case 1: case 4: {
                    aflog(LOG_T_USER, LOG_I_WARNING,
                        "user[%d] (by ser): PACKET IGNORED BY MODULE", i);
		    if (temp2 == 4) {
                      aflog(LOG_T_MAIN, LOG_I_INFO,
                          "RELEASED MODULE (ser): %s INFO: %s", secmodule.name, secmodule.info());
		      releasemodule(&secmodule);
		    }
                    continue;
                    break;
                  }
                  case 2: case 5: {
                    aflog(LOG_T_USER, LOG_I_NOTICE,
                        "user[%d] (by ser): DROPPED BY MODULE", i);
                    close(ConnectUser_get_connFd(contable[i]));
                    FD_CLR(ConnectUser_get_connFd(contable[i]), &allset);
                    FD_CLR(ConnectUser_get_connFd(contable[i]), &wset);
                    ConnectUser_set_state(contable[i], S_STATE_CLOSING);
                    BufList_clear(ConnectUser_get_bufList(contable[i]));
                    buff[0] = AF_S_CONCLOSED; /* closing connection */
                    buff[1] = i >> 8;	/* high bits of user number */
                    buff[2] = i;		/* low bits of user number */
                    SslFd_send_message(type, master, buff, 5);
		    if (temp2 == 5) {
                      aflog(LOG_T_MAIN, LOG_I_INFO,
                          "RELEASED MODULE (ser): %s INFO: %s", secmodule.name, secmodule.info());
		      releasemodule(&secmodule);
		    }
		    continue;
                    break;
                  }
                  case 3: {
                    aflog(LOG_T_MAIN, LOG_I_INFO,
                        "RELEASED MODULE (ser): %s INFO: %s", secmodule.name, secmodule.info());
		    releasemodule(&secmodule);
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
            SslFd_send_message(type, master, buff, n+5);
          }
          else if (!udp) {
            aflog(LOG_T_USER, LOG_I_INFO,
                "user[%d]: CLOSING", i);
            close(ConnectUser_get_connFd(contable[i]));
            FD_CLR(ConnectUser_get_connFd(contable[i]), &allset);
            FD_CLR(ConnectUser_get_connFd(contable[i]), &wset);
            ConnectUser_set_state(contable[i], S_STATE_CLOSING);
            BufList_clear(ConnectUser_get_bufList(contable[i]));
            buff[0] = AF_S_CONCLOSED; /* closing connection */
            buff[1] = i >> 8;	/* high bits of user number */
            buff[2] = i;		/* low bits of user number */
            SslFd_send_message(type, master, buff, 5);
          }
        } /* - FD_ISSET   CONTABLE[i].CONNFD   RSET */
      }
    }
    for (i = 0; i < usernum; ++i) {
      if (ConnectUser_get_state(contable[i]) == S_STATE_STOPPED) {
        if (FD_ISSET(ConnectUser_get_connFd(contable[i]), &tmpset)) { /* FD_ISSET  CONTABLE[i].CONNFD  TMPSET */
          aflog(LOG_T_USER, LOG_I_DDEBUG,
              "user[%d]: FD_ISSET - WRITE", i);
          n = BufListNode_readMessageLength(BufList_get_first(ConnectUser_get_bufList(contable[i])));
          temp2 = write(ConnectUser_get_connFd(contable[i]),
              BufListNode_readMessage(BufList_get_first(ConnectUser_get_bufList(contable[i]))), n);
          if ((temp2 > 0) && (temp2 != n)) {
            BufListNode_set_actPtr(BufList_get_first(ConnectUser_get_bufList(contable[i])),
                BufListNode_get_actPtr(BufList_get_first(ConnectUser_get_bufList(contable[i]))) + temp2);
          }
          else if ((temp2 == -1) && (errno == EAGAIN)) {
            aflog(LOG_T_USER, LOG_I_DEBUG,
                "user[%d]: Couldn't write?", i);
          }
          else if (temp2 == -1) {
            close(ConnectUser_get_connFd(contable[i]));
            FD_CLR(ConnectUser_get_connFd(contable[i]), &allset);
            FD_CLR(ConnectUser_get_connFd(contable[i]), &wset);
            ConnectUser_set_state(contable[i], S_STATE_CLOSING);
            buff[0] = AF_S_CONCLOSED; /* closing connection */
            buff[1] = i >> 8;	/* high bits of user number */
            buff[2] = i;		/* low bits of user number */
            SslFd_send_message(type, master, buff, 5);
          }
          else {
            BufList_delete_first(ConnectUser_get_bufList(contable[i]));
            if (BufList_get_first(ConnectUser_get_bufList(contable[i])) == NULL) {
              ConnectUser_set_state(contable[i], S_STATE_OPEN);
              FD_CLR(ConnectUser_get_state(contable[i]), &wset);
              buff[0] = AF_S_CAN_SEND; /* stopping transfer */
              buff[1] = i >> 8;       /* high bits of user number */
              buff[2] = i;            /* low bits of user number */
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "FROM user[%d]: BUFFERING MESSAGE ENDED", i);
              SslFd_send_message(type, master, buff, 5);
            }
          }
        } /* - FD_ISSET   CONTABLE[i].CONNFD   TMPSET */
      }
    }
    if (FD_ISSET(SslFd_get_fd(master), &rset)) { /* FD_ISSET   MASTER.COMMFD   RSET */
      aflog(LOG_T_CLIENT, LOG_I_DDEBUG,
          "masterfd: FD_ISSET");
      n = SslFd_get_message(type, master, buff, 5);
      if (n != 5) {
        aflog(LOG_T_CLIENT, LOG_I_ERR,
            "FATAL ERROR! (%d)", n);
        if (n == -1) {
          if (TYPE_IS_SSL(type)) {
            get_ssl_error(master, "FE", n);
            continue; /* what happened? */
          }
        }
        if (n != 0)
          exit(1);
      }
      if (n == 0) { /* server quits -> we do the same... */
        i = ArOptions_get_arTries(ao);
        if (ArOptions_get_arPremature(ao) == AR_OPTION_DISABLED) {
          i = 0;
        }
        if (i) {
          aflog(LOG_T_CLIENT, LOG_I_ERR,
              "SERVER: premature quit -> auto-reconnect enabled");
        }
        while (i) {
          close_connections(usernum, &contable);
          SslFd_set_ssl(master, NULL);
          mysleep(ArOptions_get_arDelay(ao));
          aflog(LOG_T_CLIENT, LOG_I_INFO,
              "Trying to reconnect...");
          
          temp2 = 0;
          if (temp2 == 0) {
#ifdef HAVE_LIBPTHREAD
            if (initialize_client_stage1(tunneltype, master, name, manage, hpo,
                ipfam, ctx, buff, pass, 0, ignorepkeys)) {
#else
            if (initialize_client_stage1(tunneltype, master, name, manage, NULL,
                ipfam, ctx, buff, pass, 0, ignorepkeys)) {
#endif
              temp2 = 1;
            }
          }
          if (temp2 == 0) {
            if (initialize_client_stage2(&type, master, &usernum, buff, 0)) {
              temp2 = 1;
            }
          }
          if (temp2 == 0) {
            if (initialize_client_stage3(&contable, master, usernum, &buflength, &len, &allset,
                &wset, &maxfdp1, 0)) {
              temp2 = 1;
            }
          }

          if (temp2 == 0) {
            n = 1;
            aflog(LOG_T_CLIENT, LOG_I_INFO,
                "Reconnected successfully...");
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
          if ((numofcon>=0) && (numofcon<=usernum)) {
            usercon--;
            if (ConnectUser_get_state(contable[numofcon]) == S_STATE_CLOSING) {
              ConnectUser_set_state(contable[numofcon], S_STATE_CLEAR);
              aflog(LOG_T_USER, LOG_I_INFO,
                  "user[%d]: CLOSED", numofcon);
            }
            else if ((ConnectUser_get_state(contable[numofcon]) == S_STATE_OPEN) ||
                (ConnectUser_get_state(contable[numofcon]) == S_STATE_STOPPED)) {
              aflog(LOG_T_USER, LOG_I_INFO,
                  "user[%d]: CLOSED", numofcon);
              close(ConnectUser_get_connFd(contable[numofcon]));
              FD_CLR(ConnectUser_get_connFd(contable[numofcon]), &allset);
              FD_CLR(ConnectUser_get_connFd(contable[numofcon]), &wset);
              ConnectUser_set_state(contable[numofcon], S_STATE_CLEAR);
              BufList_clear(ConnectUser_get_bufList(contable[numofcon]));
              buff[0] = AF_S_CONCLOSED; /* closing connection */
              buff[1] = numofcon >> 8;		/* high bits of user number */
              buff[2] = numofcon;		/* low bits of user number */
              SslFd_send_message(type, master, buff, 5);
            }
          }
          break;
        }
        case AF_S_CONOPEN : {
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "user[%d]: AF_S_CONOPEN", numofcon);
          if ((numofcon>=0) && (numofcon<=usernum)) {
            usercon++;
            if (ConnectUser_get_state(contable[numofcon]) == S_STATE_CLEAR) {
              n = SslFd_get_message(type, master, buff, length);
              ConnectUser_set_nameBuf(contable[numofcon], (char*) buff);
              ConnectUser_set_portBuf(contable[numofcon], (char*) &buff[128]);
              aflog(LOG_T_USER, LOG_I_INFO,
                  "user[%d]: OPENING", numofcon);
              aflog(LOG_T_USER, LOG_I_INFO,
                  "user[%d]: IP:%s PORT:%s", numofcon,
              ConnectUser_get_nameBuf(contable[numofcon]), ConnectUser_get_portBuf(contable[numofcon]));
#ifdef HAVE_LIBDL
              if (ismloaded(&module) && module.allow(ConnectUser_get_nameBuf(contable[numofcon]),
                    ConnectUser_get_portBuf(contable[numofcon]))) {
                aflog(LOG_T_USER, LOG_I_WARNING,
                    "user[%d]: IT'S NOT ALLOWED - DROPPING", numofcon);
                buff[0] = AF_S_CANT_OPEN; /* not opening connection */
                buff[1] = numofcon >> 8;		/* high bits of user number */
                buff[2] = numofcon;		/* low bits of user number */
                SslFd_send_message(type, master, buff, 5);
                usercon--;
                continue;
              }
#endif
              if (udp) {
                ipfam = 0;
              }
              else {
                ipfam = 0x01;
              }
#ifdef AF_INET6
              if (TYPE_IS_IPV4(type)) {
                ipfam |= 0x02;
              }
              else if (TYPE_IS_IPV6(type)) {
                ipfam |= 0x04;
              }
#endif
              if (ip_connect(&temp, desnam, despor, ipfam)) {
                aflog(LOG_T_USER, LOG_I_WARNING,
                    "user[%d]: CAN'T CONNECT to %s:%s - DROPPING", numofcon, desnam, despor);
                buff[0] = AF_S_CANT_OPEN; /* not opening connection */
                buff[1] = numofcon >> 8;		/* high bits of user number */
                buff[2] = numofcon;		/* low bits of user number */
                SslFd_send_message(type, master, buff, 5);
                usercon--;
                continue;
              }
              ConnectUser_set_connFd(contable[numofcon], temp);
              temp2 = fcntl(ConnectUser_get_connFd(contable[numofcon]), F_GETFL, 0);
              fcntl(ConnectUser_get_connFd(contable[numofcon]), F_SETFL, temp2 | O_NONBLOCK);
              FD_SET(ConnectUser_get_connFd(contable[numofcon]), &allset);
              maxfdp1 = (maxfdp1 > (ConnectUser_get_connFd(contable[numofcon]) + 1)) ?
                maxfdp1 : (ConnectUser_get_connFd(contable[numofcon]) + 1);
              buff[0] = AF_S_CONOPEN; /* opening connection */
              buff[1] = numofcon >> 8;		/* high bits of user number */
              buff[2] = numofcon; 		/* low bits of user number */
              SslFd_send_message(type, master, buff, 5);
              ConnectUser_set_state(contable[numofcon], S_STATE_OPEN);
            }
          }
          break;
        }
        case AF_S_MESSAGE : {
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "user[%d]: AF_S_MESSAGE", numofcon);
          aflog(LOG_T_USER, LOG_I_DEBUG,
              "user[%d]: FROM msglen: %d", numofcon, length);
          n = SslFd_get_message(type, master, buff, length);
          if ((numofcon>=0) && (numofcon<=usernum)) {
            if (ConnectUser_get_state(contable[numofcon]) == S_STATE_OPEN) {
#ifdef HAVE_LIBDL
              if (ismloaded(&module)) {
                switch ((temp2 = module.filter(ConnectUser_get_nameBuf(contable[numofcon]), buff, &n))) {
                  case 1: case 4:{
                    aflog(LOG_T_USER, LOG_I_WARNING,
                        "user[%d]: PACKET IGNORED BY MODULE", numofcon);
		    if (temp2 == 4) {
                      aflog(LOG_T_MAIN, LOG_I_INFO,
                          "RELEASED MODULE: %s INFO: %s", module.name, module.info());
		      releasemodule(&module);
		    }
                    continue;
                    break;
                  }
                  case 2: case 5:{
                    aflog(LOG_T_USER, LOG_I_NOTICE,
                        "user[%d]: DROPPED BY MODULE", numofcon);
                    close(ConnectUser_get_connFd(contable[numofcon]));
                    FD_CLR(ConnectUser_get_connFd(contable[numofcon]), &allset);
                    FD_CLR(ConnectUser_get_connFd(contable[numofcon]), &wset);
                    ConnectUser_set_state(contable[numofcon], S_STATE_CLOSING);
                    BufList_clear(ConnectUser_get_bufList(contable[numofcon]));
                    buff[0] = AF_S_CONCLOSED; /* closing connection */
                    buff[1] = numofcon >> 8;	/* high bits of user number */
                    buff[2] = numofcon;		/* low bits of user number */
                    SslFd_send_message(type, master, buff, 5);
		    if (temp2 == 5) {
                      aflog(LOG_T_MAIN, LOG_I_INFO,
                          "RELEASED MODULE: %s INFO: %s", module.name, module.info());
		      releasemodule(&module);
		    }
		    continue;
                    break;
                  }
                  case 3: {
                    aflog(LOG_T_MAIN, LOG_I_INFO,
                        "RELEASED MODULE: %s INFO: %s", module.name, module.info());
		    releasemodule(&module);
                    break;
                  }
                }
              }
#endif
              aflog(LOG_T_USER, LOG_I_DEBUG,
                  "user[%d]: FROM msglen: %d SENT", numofcon, n);
              temp2 = write(ConnectUser_get_connFd(contable[numofcon]), buff, n);
              if ((temp2 > 0) && (temp2 != n)) {
                BufList_insert_back(ConnectUser_get_bufList(contable[numofcon]),
                    BufListNode_new_message(temp2, n, buff));
                ConnectUser_set_state(contable[numofcon], S_STATE_STOPPED);
                FD_SET(ConnectUser_get_connFd(contable[numofcon]), &wset);
                buff[0] = AF_S_DONT_SEND; /* stopping transfer */
                buff[1] = numofcon >> 8;        /* high bits of user number */
                buff[2] = numofcon;             /* low bits of user number */
                aflog(LOG_T_USER, LOG_I_DDEBUG,
                    "FROM user[%d]: BUFFERING MESSAGE STARTED", numofcon);
                SslFd_send_message(type, master, buff, 5);
              }
              else if ((temp2 == -1) && (errno == EAGAIN)) {
                BufList_insert_back(ConnectUser_get_bufList(contable[numofcon]),
                    BufListNode_new_message(0, n, buff));
                ConnectUser_set_state(contable[numofcon], S_STATE_STOPPED);
                FD_SET(ConnectUser_get_connFd(contable[numofcon]), &wset);
                buff[0] = AF_S_DONT_SEND; /* stopping transfer */
                buff[1] = numofcon >> 8;        /* high bits of user number */
                buff[2] = numofcon;             /* low bits of user number */
                aflog(LOG_T_USER, LOG_I_DDEBUG,
                    "FROM user[%d]: BUFFERING MESSAGE STARTED", numofcon);
                SslFd_send_message(type, master, buff, 5);
              }
              else if (temp2 == -1) {
                close(ConnectUser_get_connFd(contable[numofcon]));
                FD_CLR(ConnectUser_get_connFd(contable[numofcon]), &allset);
                FD_CLR(ConnectUser_get_connFd(contable[numofcon]), &wset);
                ConnectUser_set_state(contable[numofcon], S_STATE_CLOSING);
                BufList_clear(ConnectUser_get_bufList(contable[numofcon]));
                buff[0] = AF_S_CONCLOSED; /* closing connection */
                buff[1] = numofcon >> 8;	/* high bits of user number */
                buff[2] = numofcon;		/* low bits of user number */
                SslFd_send_message(type, master, buff, 5);
              }
            }
            else if (ConnectUser_get_state(contable[numofcon]) == S_STATE_STOPPED) {
              aflog(LOG_T_USER, LOG_I_DDEBUG,
                  "FROM user[%d]: BUFFERING MESSAGE", numofcon);
              BufList_insert_back(ConnectUser_get_bufList(contable[numofcon]),
                  BufListNode_new_message(0, n, buff));
            }
          }
          break;
        }
        case AF_S_CLOSING : { /* server shut down */
          n = 0;
          i = ArOptions_get_arTries(ao);
          if (ArOptions_get_arQuit(ao) == AR_OPTION_DISABLED) {
            i = 0;
          }
          if (i) {
            aflog(LOG_T_CLIENT, LOG_I_ERR,
                "SERVER: CLOSED -> auto-reconnect enabled");
          }
          while (i) {
            close_connections(usernum, &contable);
            SslFd_set_ssl(master, NULL);
            mysleep(ArOptions_get_arDelay(ao));
            aflog(LOG_T_CLIENT, LOG_I_INFO,
                "Trying to reconnect...");
          
            temp2 = 0;
            if (temp2 == 0) {
#ifdef HAVE_LIBPTHREAD
              if (initialize_client_stage1(tunneltype, master, name, manage, hpo,
                  ipfam, ctx, buff, pass, 0, ignorepkeys)) {
#else
              if (initialize_client_stage1(tunneltype, master, name, manage, NULL,
                  ipfam, ctx, buff, pass, 0, ignorepkeys)) {
#endif
                temp2 = 1;
              }
            }
            if (temp2 == 0) {
              if (initialize_client_stage2(&type, master, &usernum, buff, 0)) {
                temp2 = 1;
              }
            }
            if (temp2 == 0) {
              if (initialize_client_stage3(&contable, master, usernum, &buflength, &len, &allset,
                  &wset, &maxfdp1, 0)) {
                temp2 = 1;
              }
            }

            if (temp2 == 0) {
              n = 1;
              aflog(LOG_T_CLIENT, LOG_I_INFO,
                  "Reconnected successfully...");
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
              aflog(LOG_T_USER, LOG_I_DEBUG,
                  "user[%d]: AF_S_DONT_SEND", numofcon);
          FD_CLR(ConnectUser_get_connFd(contable[numofcon]), &allset);
          break;
        }
        case AF_S_CAN_SEND: {
              aflog(LOG_T_USER, LOG_I_DEBUG,
                  "user[%d]: AF_S_CAN_SEND", numofcon);
          FD_SET(ConnectUser_get_connFd(contable[numofcon]), &allset);
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
