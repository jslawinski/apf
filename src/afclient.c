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
  {"heavylog", 1, 0, 'O'},
  {"lightlog", 1, 0, 'o'},
  {"heavysocklog", 1, 0, 'S'},
  {"lightsocklog", 1, 0, 's'},
  {"pass", 1, 0, 301},
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
  {0, 0, 0, 0}
};

int
main(int argc, char **argv)
{
  int i, n, numofcon, length, buflength, notsent, temp2; 
  ConnectuserT* contable = NULL;
  clifd master;
  unsigned char buff[9000];
  char hostname[100];
  int maxfdp1, usernum, usercon;
  socklen_t len, addrlen;
  struct sockaddr* cliaddr;
  fd_set rset, allset, wset, tmpset;
  char verbose = 0;
  char remote = 0;
  char logging = 0;
  char socklogging = 0;
  char* name = NULL;
  char* id = NULL;
  char* manage = NULL;
  char* desnam = NULL;
  char* despor = NULL;
  char* keys = NULL;
  char* logfname = NULL;
  char* logsport = NULL;
  char* dateformat = NULL;
  char ipfam = 0;
  unsigned char pass[4] = {1, 2, 3, 4};
  char udp = 0;
  char reverse = 0;
  char type = 0;
  struct sigaction act;
#ifdef HAVE_LIBDL
  moduleT module = {0, NULL, NULL, NULL, NULL}, secmodule = {0, NULL, NULL, NULL, NULL};
#endif

  SSL_METHOD* method;
  SSL_CTX* ctx;
 
  sigfillset(&(act.sa_mask));
  act.sa_flags = 0;
	
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, NULL);
  act.sa_handler = sig_int;
  sigaction(SIGINT, &act, NULL);

#ifdef AF_INET6
#  ifdef HAVE_LIBDL
  while ((n = getopt_long(argc, argv, "huUn:m:d:p:vk:O:o:46l:L:i:D:S:s:r", long_options, 0)) != -1) {
#  else
  while ((n = getopt_long(argc, argv, "huUn:m:d:p:vk:O:o:46i:D:S:s:r", long_options, 0)) != -1) {
#  endif
#else
#  ifdef HAVE_LIBDL
  while ((n = getopt_long(argc, argv, "huUn:m:d:p:vk:O:o:l:L:i:D:S:s:r", long_options, 0)) != -1) {
#  else
  while ((n = getopt_long(argc, argv, "huUn:m:d:p:vk:O:o:i:D:S:s:r", long_options, 0)) != -1) {
#  endif
#endif
    switch (n) {
      case 'h': {
        usage(AF_VER("Active port forwarder (client)"));
        break;
      }
      case 'n': {
        name = optarg;
        break;
      }
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
      case 'O': {
        logfname = optarg;
        logging = 3;
        break;
      }
      case 'o': {
        logfname = optarg;
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
        n = strlen(optarg);
        memset(pass, 0, 4);
        for (i = 0; i < n; ++i) {
          pass[i%4] += optarg[i];
        }
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
      case '?': {
        usage("");
        break;
      }
    }
  }

  if (optind < argc) {
    usage("Unrecognized non-option elements");
  }

  if (name == NULL) {
    usage("Name of the server is required");
  }
  if (manage == NULL) {
    manage = "50126";
    if (reverse)
      usage("Port on the server is required in reverse mode");
  }
  if (keys == NULL) {
    keys = "client.rsa";
  }
  if ((reverse == 0) && (remote == 0) && (desnam == NULL)) {
    gethostname(hostname, 100);
    desnam = hostname;
  }
  if ((!remote) && (despor == NULL)) {
    usage("Destination port number is required");
  }

  if ((temp2 = loginit(verbose, logging, socklogging, logfname, logsport, dateformat))) {
    switch (temp2) {
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
  
#ifdef HAVE_LIBDL
  if (loadmodule(&module)) {
      aflog(0, "Loading a module %s failed!", module.name);
      exit(1);
  }
  if (loadmodule(&secmodule)) {
      aflog(0, "Loading a module %s failed!", secmodule.name);
      exit(1);
  }
#endif
  
  TYPE_SET_SSL(type);
  TYPE_SET_ZLIB(type);

#ifdef AF_INET6
  if (ipfam == -1) {
    aflog(0, "Conflicting types of ip protocol family... exiting");
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
      aflog(0, "Setting cipher list failed... exiting");
      exit(1);
    }
    if ((temp2 = create_apf_dir())) {
      aflog(1, "Warning: Creating ~/.apf directory failed (%d)", temp2);
    }
    if ((temp2 = generate_rsa_key(&keys))) {
      aflog(1, "Warning: Something bad happened when generating rsa keys... (%d)", temp2);
    }
    if (SSL_CTX_use_RSAPrivateKey_file(ctx, keys, SSL_FILETYPE_PEM) != 1) {
      aflog(0, "Setting rsa key failed (%s)... exiting", keys);
      exit(1);
    }
    
    if (remote) {
      temp2 = -1;
      if (despor) {
        if (ip_listen(&n, desnam, despor, &addrlen, ipfam)) {
#ifdef AF_INET6
          aflog(0, "tcp_listen_%s error for %s, %s",
              (ipfam & 0x02)?"ipv4":(ipfam & 0x04)?"ipv6":"unspec", desnam, despor);
#else
          aflog(0, "tcp_listen error for %s, %s", desnam, despor);
#endif
          exit(1);
        }
        if (!verbose)
          daemon(0, 0);
        cliaddr = malloc(addrlen);
        temp2 = accept(n, cliaddr, &addrlen);
      }
    }
    
    if (ip_connect(&(master.commfd), name, manage, ipfam)) {
#ifdef AF_INET6
      aflog(0, "tcp_connect_%s error for %s, %s",
          (ipfam & 0x02)?"ipv4":(ipfam & 0x04)?"ipv6":"unspec", name, manage);
#else
      aflog(0, "tcp_connect error for %s, %s", name, manage);
#endif
      exit(1);
    }
    master.ssl = SSL_new(ctx);
    if (SSL_set_fd(master.ssl, master.commfd) != 1) {
      aflog(0, "Problem with initializing ssl... exiting");
      exit(1);
    }

    aflog(1, "Trying SSL_connect");
    if ((n = SSL_connect(master.ssl)) == 1) {
      aflog(1, "SSL_connect successfull");
    }
    else {
      aflog(0, "SSL_connect has failed (%d)... exiting", n);
      exit(1);
    }

    buff[0] = AF_S_LOGIN;
    buff[1] = pass[0];
    buff[2] = pass[1];
    buff[3] = pass[2];
    buff[4] = pass[3];
    
    if (remote) {
      return client_admin(type, master, buff, temp2, id);
    }
    
    send_message(type, master, buff, 5);
    buff[0] = 0;
    get_message(type, master, buff, -5);

    if ( buff[0] == 0 ) {
      aflog(0, "Wrong password");
      exit(1);
    }
    if ( buff[0] == AF_S_CANT_OPEN ) {
      aflog(0, "Server is full");
      exit(1);
    }
    if ( buff[0] != AF_S_LOGIN ) {
      aflog(0, "Incompatible server type or server full");
      exit(1);
    }

    type = buff[3];
    usernum = buff[1];
    usernum = usernum << 8;
    usernum += buff[2];
  } /* !reverse */
  else {
    usernum = 1;
    if (ip_connect(&(master.commfd), name, manage, ipfam)) {
#ifdef AF_INET6
      aflog(0, "tcp_connect_%s error for %s, %s",
          (ipfam & 0x02)?"ipv4":(ipfam & 0x04)?"ipv6":"unspec", name, manage);
#else
      aflog(0, "tcp_connect error for %s, %s", name, manage);
#endif
      exit(1);
    }
    master.ssl = NULL;
  }

  contable = calloc( usernum, sizeof(ConnectuserT));
  if (contable == NULL) {
    aflog(0, "Calloc error - unable to succesfully communicate with server");
    exit(1);
  }
	
  len = 4;
  if (getsockopt(master.commfd, SOL_SOCKET, SO_SNDBUF, &buflength, &len) == -1) {
    aflog(0, "Can't get socket send buffer size - exiting...");
    exit(1);
  }
	
  if (!verbose)
    daemon(0, 0);
	
  FD_ZERO(&allset);
  FD_ZERO(&wset);
	
  FD_SET(master.commfd, &allset);
  maxfdp1 = master.commfd + 1;

  /* UDP REVERSE MODE */
  
  if (reverse) {
    ipfam = 0;
#ifdef AF_INET6
    if (TYPE_IS_IPV4(type)) {
      ipfam |= 0x02;
    }
    else if (TYPE_IS_IPV6(type)) {
      ipfam |= 0x04;
    }
#endif
    if (ip_listen(&(contable[0].connfd), desnam, despor, &addrlen, ipfam)) {
#ifdef AF_INET6
      aflog(0, "udp_listen_%s error for %s, %s",
		      (ipfam & 0x02)?"ipv4":(ipfam & 0x04)?"ipv6":"unspec", desnam, despor);
#else
      aflog(0, "udp_listen error for %s, %s", desnam, despor);
#endif
      exit(1);
    }
    cliaddr = malloc(addrlen);
    maxfdp1 = (maxfdp1>contable[0].connfd+1) ? maxfdp1 : contable[0].connfd+1;
    FD_SET(contable[0].connfd, &allset);
    aflog(1, "CLIENT STARTED mode: udp reverse");
    for ( ; ; ) {
      len = 4;
      if (getsockopt(master.commfd, SOL_SOCKET, SO_SNDBUF, &temp2, &len) != -1) {
        if (temp2 != buflength) {
          buflength = temp2;
          aflog(2, "Send buffer size changed...");
        }
      }
      len = addrlen;
      rset = allset;
      aflog(3, ">select");
      select(maxfdp1, &rset, NULL, NULL, NULL);
      aflog(3, " >>after select...");
      
      if (FD_ISSET(contable[0].connfd, &rset)) { /* FD_ISSET   CONTABLE[0].CONNFD   RSET*/
        n = recvfrom(contable[0].connfd, &buff[5], 8091, 0, cliaddr, &len);
#ifdef HAVE_LINUX_SOCKIOS_H
# ifdef SIOCOUTQ
        if (ioctl(master.commfd, SIOCOUTQ, &notsent)) {
          aflog(0, "ioctl error -> exiting...");
          exit(1);
        }
        if (buflength <= notsent + n + 5) { /* when we can't do this */
          aflog(2, "drop: size:%d, buf:%d, w:%d/%d", n, buflength, notsent, buflength);
# else
        if (ioctl(master.commfd, TIOCOUTQ, &notsent)) {
          aflog(0, "ioctl error -> exiting...");
          exit(1);
        }
        if (notsent <= n + 5) { /* when we can't do this */
          aflog(2, "drop: size:%d, buf:%d, w:%d/%d", n, buflength, buflength - notsent, buflength);
# endif
	}
        else {
#endif
          if (n > 0) {
#ifdef HAVE_LINUX_SOCKIOS_H
            aflog(2, "Sending %d bytes to service (w:%d/%d) (FROM:%s)", n,
# ifdef SIOCOUTQ
			notsent
# else
			buflength - notsent
# endif
			, buflength, sock_ntop(cliaddr, len, NULL, NULL, 0));
#else
            aflog(2, "Sending %d bytes to service (FROM:%s)", n, sock_ntop(cliaddr, len, NULL, NULL, 0));
#endif
            buff[0] = AF_S_MESSAGE;
            buff[1] = AF_S_LOGIN;
            buff[2] = AF_S_MESSAGE;
            buff[3] = n >> 8;
            buff[4] = n;
            writen(master.commfd, buff, n + 5);
          }
#ifdef HAVE_LINUX_SOCKIOS_H
        }
#endif
      } /* - FD_ISSET   CONTABLE[0].CONNFD   RSET */
        
      if (FD_ISSET(master.commfd, &rset)) { /* FD_ISSET   MASTER.COMMFD   RSET */
        n = readn(master.commfd, buff, 5);
        if (n == 5) {
          if ((buff[0] != AF_S_MESSAGE) || (buff[1] != AF_S_LOGIN) || (buff[2] != AF_S_MESSAGE)) {
            aflog(0, "Incompatible server type (not udp?) or data corruption -> exiting...");
            exit(1);
          }
          length = buff[3];
          length = length << 8;
          length += buff[4]; /* this is length of message */
          n = readn(master.commfd, buff, length);
        }
        else {
          n = 0;
        }
        if (n == 0) { /* server quits -> we do the same... */
          aflog(0, "premature quit of the server -> exiting...");
          exit(1);
        }
        aflog(2, "Sending %d bytes to user (TO:%s)", n, sock_ntop(cliaddr, addrlen, NULL, NULL, 0));
        sendto(contable[0].connfd, buff, n, 0, cliaddr, addrlen);
      } /* - FD_ISSET   MASTER.COMMFD   RSET */
    }
    exit(0); /* we shouldn't get here */
  }

  /* NORMAL MODE */
	
  aflog(1, "CLIENT STARTED mode: %s", (udp)?"udp":"tcp");
  aflog(1, "SERVER SSL: %s, ZLIB: %s, MODE: %s", (TYPE_IS_SSL(type))?"yes":"no",
		  (TYPE_IS_ZLIB(type))?"yes":"no", (TYPE_IS_TCP(type))?"tcp":"udp");
  aflog(2, "CIPHER: %s VER: %s", SSL_get_cipher_name(master.ssl), SSL_get_cipher_version(master.ssl));
#ifdef HAVE_LIBDL
  if (ismloaded(&module)) {
    aflog(1, "LOADED MODULE: %s INFO: %s", module.name, module.info());
  }
  if (ismloaded(&secmodule)) {
    aflog(1, "LOADED MODULE (ser): %s INFO: %s", secmodule.name, secmodule.info());
  }
#endif
	if (id != NULL) {
    buff[0] = AF_S_LOGIN;
    buff[1] = buff[2] = 0;
    n = strlen(id);
    memcpy(&buff[5], id, n);
    buff[3] = n >> 8;	/* high bits of message length */
    buff[4] = n;		/* low bits of message length */
    send_message(type, master, buff, n+5);
    aflog(1, "ID SENT: %s", id);
  }
    
  for ( ; ; ) {
    rset = allset;
    tmpset = wset;
    aflog(3, ">select");
    select(maxfdp1, &rset, &tmpset, NULL, NULL);
    aflog(3, " >>after select...");

    for (i = 0; i < usernum; ++i) {
      if ((contable[i].state == S_STATE_OPEN)||(contable[i].state == S_STATE_STOPPED)) {
        if (FD_ISSET(contable[i].connfd, &rset)) { /* FD_ISSET   CONTABLE[i].CONNFD   RSET */
          aflog(3, " user[%d]: FD_ISSET", i);
          n = read(contable[i].connfd, &buff[5], 8091);
          if (n == -1) {
            aflog(0, "  error (%d): while reading from service", n);
            n = 0;
          }
#ifdef HAVE_LINUX_SOCKIOS_H
# ifdef SIOCOUTQ
          if (ioctl(master.commfd, SIOCOUTQ, &notsent)) {
            aflog(0, "ioctl error -> exiting...");
            exit(1);
          }
          if (udp) {
            len = 4;
            if (getsockopt(master.commfd, SOL_SOCKET, SO_SNDBUF, &temp2, &len) != -1) {
              if (temp2 != buflength) {
                buflength = temp2;
                aflog(2, "Send buffer size changed...");
              }
            }
            if (buflength <= notsent + n + 5) { /* when we can't send this */
              aflog(2, " user[%d]: DROP size:%d, buf:%d, w:%d/%d", i, n+5, buflength, notsent, buflength);
# else
          if (ioctl(master.commfd, TIOCOUTQ, &notsent)) {
            aflog(0, "ioctl error -> exiting...");
            exit(1);
          }
          if (udp) {
            len = 4;
            if (getsockopt(master.commfd, SOL_SOCKET, SO_SNDBUF, &temp2, &len) != -1) {
              if (temp2 != buflength) {
                buflength = temp2;
                aflog(2, "Send buffer size changed...");
              }
            }
            if (notsent <= n + 5) { /* when we can't send this */
              aflog(2, " user[%d]: DROP size:%d, buf:%d, w:%d/%d", 
			      i, n+5, buflength, buflength-notsent, buflength);
# endif
              continue; /* drop this packet */
            }
          }
#endif
          if (n) {
#ifdef HAVE_LIBDL
              if (ismloaded(&secmodule)) {
                switch ((temp2 = secmodule.filter(contable[i].namebuf, &buff[5], &n))) {
                  case 1: case 4: {
                    aflog(3, "  user[%d] (by ser): PACKET IGNORED BY MODULE", i);
		    if (temp2 == 4) {
                      aflog(1, "RELEASED MODULE (ser): %s INFO: %s", secmodule.name, secmodule.info());
		      releasemodule(&secmodule);
		    }
                    continue;
                    break;
                  }
                  case 2: case 5: {
                    aflog(2, "  user[%d] (by ser): DROPPED BY MODULE", i);
                    close(contable[i].connfd);
                    FD_CLR(contable[i].connfd, &allset);
                    FD_CLR(contable[i].connfd, &wset);
                    contable[i].state = S_STATE_CLOSING;
                    freebuflist(&contable[i].head);
                    buff[0] = AF_S_CONCLOSED; /* closing connection */
                    buff[1] = i >> 8;	/* high bits of user number */
                    buff[2] = i;		/* low bits of user number */
                    send_message(type, master, buff, 5);
		    if (temp2 == 5) {
                      aflog(1, "RELEASED MODULE (ser): %s INFO: %s", secmodule.name, secmodule.info());
		      releasemodule(&secmodule);
		    }
		    continue;
                    break;
                  }
                  case 3: {
                    aflog(1, "RELEASED MODULE (ser): %s INFO: %s", secmodule.name, secmodule.info());
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
            aflog(2, "  user[%d]: TO msglen: %d [%d/%d]", i, n,
# ifdef SIOCOUTQ
			notsent
# else
			buflength - notsent
# endif
			, buflength);
#else
            aflog(2, "  user[%d]: TO msglen: %d", i, n);
#endif
            send_message(type, master, buff, n+5);
          }
          else if (!udp) {
            aflog(2, "  user[%d]: CLOSING", i);
            close(contable[i].connfd);
            FD_CLR(contable[i].connfd, &allset);
            FD_CLR(contable[i].connfd, &wset);
            contable[i].state = S_STATE_CLOSING;
            freebuflist(&contable[i].head);
            buff[0] = AF_S_CONCLOSED; /* closing connection */
            buff[1] = i >> 8;	/* high bits of user number */
            buff[2] = i;		/* low bits of user number */
            send_message(type, master, buff, 5);
          }
        } /* - FD_ISSET   CONTABLE[i].CONNFD   RSET */
      }
    }
    for (i = 0; i < usernum; ++i) {
      if (contable[i].state == S_STATE_STOPPED) {
        if (FD_ISSET(contable[i].connfd, &tmpset)) { /* FD_ISSET   CONTABLE[i].CONNFD   TMPSET */
          aflog(3, " user[%d]: FD_ISSET - WRITE", i);
          n = contable[i].head->msglen - contable[i].head->actptr;
          temp2 = write(contable[i].connfd, &(contable[i].head->buff[contable[i].head->actptr]), n);
          if ((temp2 > 0) && (temp2 != n)) {
            contable[i].head->actptr+=temp2;
          }
          else if ((temp2 == -1) && (errno == EAGAIN)) {
            aflog(3, " user[%d]: Couldn't write?", i);
          }
          else if (temp2 == -1) {
            close(contable[i].connfd);
            FD_CLR(contable[i].connfd, &allset);
            FD_CLR(contable[i].connfd, &wset);
            contable[i].state = S_STATE_CLOSING;
            buff[0] = AF_S_CONCLOSED; /* closing connection */
            buff[1] = i >> 8;	/* high bits of user number */
            buff[2] = i;		/* low bits of user number */
            send_message(type, master, buff, 5);
          }
          else {
            deleteblnode(&contable[i].head);
            if (contable[i].head == NULL) {
              contable[i].state = S_STATE_OPEN;
              FD_CLR(contable[i].connfd, &wset);
              buff[0] = AF_S_CAN_SEND; /* stopping transfer */
              buff[1] = i >> 8;       /* high bits of user number */
              buff[2] = i;            /* low bits of user number */
              aflog(3, "  FROM user[%d]: BUFFERING MESSAGE ENDED", i);
              send_message(type, master, buff, 5);
            }
          }
        } /* - FD_ISSET   CONTABLE[i].CONNFD   TMPSET */
      }
    }
    if (FD_ISSET(master.commfd, &rset)) { /* FD_ISSET   MASTER.COMMFD   RSET */
      aflog(3, " masterfd: FD_ISSET");
      n = get_message(type, master, buff, 5);
      if (n != 5) {
        aflog(2, "  FATAL ERROR! (%d)", n);
        if (n == -1) {
          if (TYPE_IS_SSL(type)) {
            get_ssl_error(&master, "FE", n);
            continue; /* what happened? */
          }
        }
        if (n != 0)
          exit(1);
      }
      if (n == 0) { /* server quits -> we do the same... */
        aflog(0, "  SERVER: premature quit -> exiting...");
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
              aflog(4, "  user[%d]: AF_S_CONCLOSED", numofcon);
          if ((numofcon>=0) && (numofcon<=usernum)) {
            usercon--;
            if (contable[numofcon].state == S_STATE_CLOSING) {
              contable[numofcon].state = S_STATE_CLEAR;
              aflog(1, "  user[%d]: CLOSED", numofcon);
            }
            else if ((contable[numofcon].state==S_STATE_OPEN) || (contable[numofcon].state==S_STATE_STOPPED)){
              aflog(1, "  user[%d]: CLOSED", numofcon);
              close(contable[numofcon].connfd);
              FD_CLR(contable[numofcon].connfd, &allset);
              FD_CLR(contable[numofcon].connfd, &wset);
              contable[numofcon].state = S_STATE_CLEAR;
              freebuflist(&contable[numofcon].head);
              buff[0] = AF_S_CONCLOSED; /* closing connection */
              buff[1] = numofcon >> 8;		/* high bits of user number */
              buff[2] = numofcon;		/* low bits of user number */
              send_message(type, master, buff, 5);
            }
          }
          break;
        }
        case AF_S_CONOPEN : {
              aflog(4, "  user[%d]: AF_S_CONOPEN", numofcon);
          if ((numofcon>=0) && (numofcon<=usernum)) {
            usercon++;
            if (contable[numofcon].state == S_STATE_CLEAR) {
              n = get_message(type, master, buff, length);
              memcpy(contable[numofcon].namebuf, buff, 128);
              memcpy(contable[numofcon].portbuf,&buff[128],7);
              aflog(2, "  user[%d]: OPENING", numofcon);
              aflog(1, "user[%d]: IP:%s PORT:%s", numofcon,
              contable[numofcon].namebuf, contable[numofcon].portbuf);
#ifdef HAVE_LIBDL
              if (ismloaded(&module) && module.allow(contable[numofcon].namebuf, contable[numofcon].portbuf)) {
                aflog(2, "   IT'S NOT ALLOWED - DROPPING", numofcon);
                buff[0] = AF_S_CANT_OPEN; /* not opening connection */
                buff[1] = numofcon >> 8;		/* high bits of user number */
                buff[2] = numofcon;		/* low bits of user number */
                send_message(type, master, buff, 5);
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
              if (ip_connect(&(contable[numofcon].connfd), desnam, despor, ipfam)) {
                aflog(2, "   CAN'T OPEN - DROPPING", numofcon);
                buff[0] = AF_S_CANT_OPEN; /* not opening connection */
                buff[1] = numofcon >> 8;		/* high bits of user number */
                buff[2] = numofcon;		/* low bits of user number */
                send_message(type, master, buff, 5);
                usercon--;
                continue;
              }
              temp2 = fcntl(contable[numofcon].connfd, F_GETFL, 0);
              fcntl(contable[numofcon].connfd, F_SETFL, temp2 | O_NONBLOCK);
              FD_SET(contable[numofcon].connfd, &allset);
              maxfdp1 = (maxfdp1 > (contable[numofcon].connfd+1)) ? maxfdp1 : (contable[numofcon].connfd+1);
              buff[0] = AF_S_CONOPEN; /* opening connection */
              buff[1] = numofcon >> 8;		/* high bits of user number */
              buff[2] = numofcon; 		/* low bits of user number */
              send_message(type, master, buff, 5);
              contable[numofcon].state = S_STATE_OPEN;
            }
          }
          break;
        }
        case AF_S_MESSAGE : {
              aflog(4, "  user[%d]: AF_S_MESSAGE", numofcon);
          aflog(2, "  user[%d]: FROM msglen: %d", numofcon, length);
          n = get_message(type, master, buff, length);
          if ((numofcon>=0) && (numofcon<=usernum)) {
            if (contable[numofcon].state == S_STATE_OPEN) {
#ifdef HAVE_LIBDL
              if (ismloaded(&module)) {
                switch ((temp2 = module.filter(contable[numofcon].namebuf, buff, &n))) {
                  case 1: case 4:{
                    aflog(3, "  user[%d]: PACKET IGNORED BY MODULE", numofcon);
		    if (temp2 == 4) {
                      aflog(1, "RELEASED MODULE: %s INFO: %s", module.name, module.info());
		      releasemodule(&module);
		    }
                    continue;
                    break;
                  }
                  case 2: case 5:{
                    aflog(2, "  user[%d]: DROPPED BY MODULE", numofcon);
                    close(contable[numofcon].connfd);
                    FD_CLR(contable[numofcon].connfd, &allset);
                    FD_CLR(contable[numofcon].connfd, &wset);
                    contable[numofcon].state = S_STATE_CLOSING;
                    freebuflist(&contable[numofcon].head);
                    buff[0] = AF_S_CONCLOSED; /* closing connection */
                    buff[1] = numofcon >> 8;	/* high bits of user number */
                    buff[2] = numofcon;		/* low bits of user number */
                    send_message(type, master, buff, 5);
		    if (temp2 == 5) {
                      aflog(1, "RELEASED MODULE: %s INFO: %s", module.name, module.info());
		      releasemodule(&module);
		    }
		    continue;
                    break;
                  }
                  case 3: {
                    aflog(1, "RELEASED MODULE: %s INFO: %s", module.name, module.info());
		    releasemodule(&module);
                    break;
                  }
                }
              }
#endif
              aflog(2, "  user[%d]: FROM msglen: %d SENT", numofcon, n);
              temp2 = write(contable[numofcon].connfd, buff, n);
              if ((temp2 > 0) && (temp2 != n)) {
                insertblnode(&(contable[numofcon].head), temp2, n, buff);
                contable[numofcon].state = S_STATE_STOPPED;
                FD_SET(contable[numofcon].connfd, &wset);
                buff[0] = AF_S_DONT_SEND; /* stopping transfer */
                buff[1] = numofcon >> 8;        /* high bits of user number */
                buff[2] = numofcon;             /* low bits of user number */
                aflog(3, "   FROM user[%d]: BUFFERING MESSAGE STARTED", numofcon);
                send_message(type, master, buff, 5);
              }
              else if ((temp2 == -1) && (errno == EAGAIN)) {
                insertblnode(&(contable[numofcon].head), 0, n, buff);
                contable[numofcon].state = S_STATE_STOPPED;
                FD_SET(contable[numofcon].connfd, &wset);
                buff[0] = AF_S_DONT_SEND; /* stopping transfer */
                buff[1] = numofcon >> 8;        /* high bits of user number */
                buff[2] = numofcon;             /* low bits of user number */
                aflog(3, "   FROM user[%d]: BUFFERING MESSAGE STARTED", numofcon);
                send_message(type, master, buff, 5);
              }
              else if (temp2 == -1) {
                close(contable[numofcon].connfd);
                FD_CLR(contable[numofcon].connfd, &allset);
                FD_CLR(contable[numofcon].connfd, &wset);
                contable[numofcon].state = S_STATE_CLOSING;
                freebuflist(&contable[numofcon].head);
                buff[0] = AF_S_CONCLOSED; /* closing connection */
                buff[1] = numofcon >> 8;	/* high bits of user number */
                buff[2] = numofcon;		/* low bits of user number */
                send_message(type, master, buff, 5);
              }
            }
            else if (contable[numofcon].state == S_STATE_STOPPED) {
              aflog(3, "   FROM user[%d]: BUFFERING MESSAGE", numofcon);
              insertblnode(&(contable[numofcon].head), 0, n, buff);
            }
          }
          break;
        }
        case AF_S_CLOSING : { /* server shut down -> exiting... */
          aflog(0, "  SERVER: CLOSED -> exiting... cg: %ld bytes", getcg());
          exit(1);
          break;
        }
        case AF_S_DONT_SEND: {
              aflog(4, "  user[%d]: AF_S_DONT_SEND", numofcon);
          FD_CLR(contable[numofcon].connfd, &allset);
          break;
        }
        case AF_S_CAN_SEND: {
              aflog(4, "  user[%d]: AF_S_CAN_SEND", numofcon);
          FD_SET(contable[numofcon].connfd, &allset);
          break;
        }
        default : { /* unrecognized type of message -> exiting... */
          aflog(0, "  SERVER: unrecognized message -> exiting... cg: %ld bytes", getcg());
          exit(1);
          break;
        }
      }
    } /* - FD_ISSET   MASTER.COMMFD   RSET */
  }
}

static void
usage(char* info)
{
  printf("\n%s\n\n\n", info);
  printf(" Basic options:\n\n");
  printf("  -n, --servername    - where the second part of the active\n");
  printf("                        port forwarder is running (required)\n");
  printf("  -m, --manageport    - manage port number - server must be\n");
  printf("                        listening on it (default: 50126)\n");
  printf("  -d, --hostname      - the name of this host/remote host - the final\n");
  printf("                        destination of the packets (default: the name\n");
  printf("                        returned by hostname function)\n");
  printf("  -p, --portnum       - the port we are forwarding connection to (required)\n");
  printf("  -h, --help          - prints this help\n\n");
  printf(" Authorization:\n\n");
  printf("  -i, --id            - sends the id string to afserver\n");
  printf("  --pass              - set the password used for client identification\n");
  printf("                        (default: no password)\n\n");
  printf(" Configuration:\n\n");
  printf("  -k, --keyfile       - the name of the file with RSA key (default: client.rsa)\n");
  printf("  -D, --dateformat    - format of the date printed in logs (see 'man strftime'\n");
  printf("                        for details) (default: %%d.%%m.%%Y %%H:%%M:%%S)\n\n");
  printf(" Modes:\n\n");
  printf("  -u, --udpmode       - udp mode - client will use udp protocol to\n");
  printf("                        communicate with the hostname:portnum (-p)\n");
  printf("  -U, --reverseudp    - reverse udp forwarding. Udp packets will be forwarded\n");
  printf("                        from hostname:portnum (-p) to the server name:portnum\n");
  printf("                        (-m)\n");
  printf("  -r, --remoteadmin   - remote administration mode. (using '-p #port' will\n");
  printf("                        force afclient to use port rather then stdin-stdout)\n\n");
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
#ifdef HAVE_LIBDL
  printf(" Modules:\n\n");
  printf("  -l, --load          - load a module for user's packets filtering\n");
  printf("  -L, --Load          - load a module for service's packets filtering\n\n");
#endif

  exit(0);
}

static void
sig_int(int signo)
{
  aflog(1, "CLIENT CLOSED cg: %ld bytes", getcg());
  exit(0);
}

