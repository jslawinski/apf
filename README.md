
# GRAY-WORLD.NET / Active Port Forwarder

  The Active Port Forwarder program is  part  of  the  Gray-World.net  projects.

  Our Gray-World Team presents on the http://gray-world.net website the projects
  and publications we are working on which are  related  to  the  NACS  (Network
  Access Control System) bypassing  research  field  and  to  the  computer  and
  network security topics.


## SUMMARY

INTRO

1. INSTALLATION
  * 1.1 Instructions
  * 1.2 Required libs
  * 1.3 Tested platforms
2. USAGE
  * 2.1 afserver
  * 2.2 afclient
3. REMOTE ADMINISTRATION
  * 3.1 Usage
  * 3.2 Commands
  * 3.3 States
    * 3.3.1 Users
    * 3.3.2 Clients
  * 3.4 Relay mode
4. LOGGING
5. MODULES
6. MULTI TUNNELS
7. EXAMPLES
  * 7.1 tcp mode
  * 7.2 reverse udp mode
8. BUGS/PROBLEMS

NOTES

THANKS


## INTRO

Active  port  forwarder  is  a  software  tool  for  secure   port   forwarding.
It uses ssl to increase security of communication between a server and a client.
Originally, it was developed to forward data point to point.  However, the  need
for bypassing firewalls in order to  connect  to  internally  located  computers
influenced the further development of the project.

AF is dedicated for people, who don't have an external ip  number  and  want  to
make some services available across the net.

Moreover, zlib is used to compress the transferred data.

Using one, permanent data/control channel with flow control /  packet  buffering
provides good performance and reasonably small latency.

Multiple clients allow to create more sophisticated tunneling scheme.


## 1. INSTALLATION

### 1.1 Instructions

1. Download the compressed sources from http://www.gray-world.net/pr_af.shtml
2. Unpack them with tar zxvf
3. Type "./configure"
4. Type "make"
5. Type "make install" while logged as root
6. If something goes wrong - mail the author or post a message on
   http://gray-world.net/board/

### 1.2 Required libs

1. openssl   -   http://www.openssl.org/
2. zlib      -   http://www.gzip.org/zlib/

### 1.3 Tested platforms
  
1. Linux:
  Gentoo, Slackware, Mandrake - built without any problems
2. Windows:
  win32 - cygwin version is available on the project homepage
  

## 2. USAGE

  2.1 afserver
  ------------

 Basic options:
```
  -n, --hostname      - it's used when creating listening sockets
                        (default: '')
  -l, --listenport    - listening [host:]port - users connect to it
                        (default: 50127)
  -m, --manageport    - manage [host:]port - afclient connects to it
                        (default: 50126)
  -V, --version       - display version number
  -h, --help          - prints this help
```

 Authorization:

```
  --pass              - set the password used for client identification
                        (default: no password)
```

 Configuration:

```
  -c, --cerfile       - the name of the file with certificate
                        (default: server-cert.pem)
  -A, --cacerfile     - the name of the file with CA certificates
                        (if used, require clients to have valid certificates)
  -d, --cerdepth      - the maximum depth of valid certificate-chains
  -k, --keyfile       - the name of the file with RSA key (default: server.rsa)
  -f, --cfgfile       - the name of the file with the configuration for the
                        active forwarder (server)
  -D, --dateformat    - format of the date printed in logs (see 'man strftime'
                        for details) (default: %d.%m.%Y %H:%M:%S)
  -t, --timeout       - the timeout value for the client's connection
                        (default: 5)
  --maxidle           - the maximum idle time for the client's connection
                        (default: disabled)
  -u, --users         - the amount of users allowed to use this server
                        (default: 5)
  -C, --clients       - the number of allowed clients to use this server
                        (default: 1)
  -r, --realm         - set the realm name (default: none)
  -R, --raclients     - the number of allowed clients in remote administration
                        mode to use this server (default: 1)
  -U, --usrpcli       - the number of allowed users per client (default: $users)
  -M, --climode       - strategy used to connect users with clients (default: 1)
                      Available strategies:
                        1. fill first client before go to next

  -p, --proto         - type of server (tcp|udp) - what protocol it will be
                        operating for (default: tcp)
  -b, --baseport      - listenports are temporary and differ for each client
  -a, --audit         - additional information about connections are logged
  --nossl             - ssl is not used to transfer data (but it's still used
                        to establish a connection) (default: ssl is used)
  --nozlib            - zlib is not used to compress data (default: zlib is
                        used)
  --dnslookups        - try to obtain dns names of the computers rather than
                        their numeric IP
```

 Logging:

```
  -o, --log           - log choosen information to file/socket
  -v, --verbose       - to be verbose - program won't enter the daemon mode
                        (use several times for greater effect)
```

 IP family:

```
  -4, --ipv4          - use ipv4 only
  -6, --ipv6          - use ipv6 only
```

  2.2 afclient
  ------------

 Basic options:

```
  -n, --servername    - where the second part of the active
                        port forwarder is running (required)
  -m, --manageport    - manage port number - server must be
                        listening on it (default: 50126)
  -d, --hostname      - the name of this host/remote host - the final
                        destination of the packets (default: the name
                        returned by hostname function)
  -p, --portnum       - the port we are forwarding connection to (required)
  --localname         - local machine name for connection with afserver
                        (used to bind socket to different interfaces)
  --localport         - local port name for connection with afserver
                        (used to bind socket to different addressees)
  --localdesname      - local machine name for connections with destination
                        application (used to bind socket to different interfaces)
  -V, --version       - display version number
  -h, --help          - prints this help
```

 Authorization:

```
  -i, --id            - sends the id string to afserver
  --pass              - set the password used for client identification
                        (default: no password)
  --ignorepkeys       - ignore invalid server's public keys
```

 Configuration:

```
  -k, --keyfile       - the name of the file with RSA key (default: client.rsa)
  -c, --cerfile       - the name of the file with certificate
                        (default: no certificate used)
  -f, --cfgfile       - the name of the file with the configuration for the
                        active forwarder (client)
  -s, --storefile     - the name of the file with stored public keys
                        (default: known_hosts)
  -D, --dateformat    - format of the date printed in logs (see 'man strftime'
                        for details) (default: %d.%m.%Y %H:%M:%S)
  -K, --keep-alive N  - send keepalive packets every N seconds
                        (default: not send keepalive packets)
```

 Auto-reconnection:

```
  --ar-start          - enable auto-reconnection when afserver is not
                        reachable on start (default: disabled)
  --ar-quit           - enable auto-reconnection after normal afserver quit
                        (default: disabled)
  --noar              - disable auto-reconnection after premature afserver
                        quit (default: enabled)
  -A, --ar-tries N    - try N times to reconnect (default: unlimited)
  -T, --ar-delay N    - wait N seconds between reconnect tries (default: 5)
```

 Modes:

```
  -u, --udpmode       - udp mode - client will use udp protocol to
                        communicate with the hostname:portnum
  -U, --reverseudp    - reverse udp forwarding. Udp packets will be forwarded
                        from hostname:portnum to the server name:manageport
  -r, --remoteadmin   - remote administration mode. (using '-p #port' will
                        force afclient to use port rather than stdin-stdout)
```

 Logging:

```
  -o, --log           - log choosen information to file/socket
  -v, --verbose       - to be verbose - program won't enter the daemon mode
                        (use several times for greater effect)
```

 IP family:

```
  -4, --ipv4          - use ipv4 only
  -6, --ipv6          - use ipv6 only
```

 Modules:

```
  -l, --load          - load a module for user's packets filtering
  -L, --Load          - load a module for service's packets filtering
```

================================================================================

========================
3. REMOTE ADMINISTRATION
========================

  3.1 Usage
  ---------
  
Afclient can be started in remote administration  mode  by  '-r,  --remoteadmin'
option. Required option: '-n, --servername NAME'.

After successful authorization stdin/stdout is used to  communicate  with  user.
All the commands parsing is done by afserver.

  3.2 Commands
  ------------
  
Currently available commands are:
```
       help
         display help

       lcmd
         lists available commands

       info
         prints info about server

       rshow
         display realms

       cshow X
         display clients in X realm

       ushow X
         display users in X realm

       quit
         quit connection

       timeout N X
         set timeout value in X realm

       audit {0|1} X
         set audit mode in X realm

       dnslookups {0|1} X
         set dnslookups mode in X realm

       dateformat S
         set dateformat

       kuser S
         kick user named S

       kclient N
         kick client with number N
```

  3.3 States
  ----------
  
    3.3.1 Users
    -----------
    
    Connected users can be in several states:
```
       running
         user is properly connected and can send/receive data
         
       opening
         user is connected to afserver, but afclient hasn't confirmed connection
         with the destination. There is no traffic allowed in this situation.
         
       opening (closed)
         user was in 'opening' state, but 'kuser' command has been used and it's
         now queued for closing as soon as afclient will be ready to confirm
         this
         
       stopped
         user wasn't responsible, so all the packets addressed to it are queued.
         Afclient is informed to not receive any packets for this user.
         
       closing
         connection with user has been lost. Afclient has to confirm user
         deletion
         
       unknown
         probably afserver internal state has been corrupted.
```

    3.3.2 Clients
    -------------

    Connected clients can be in several states:

```
       running
         client is properly connected and can serve user's requests
         
       ssl handshake
         connection with client has been initialized and now ssl routines are
         negotiating all the details needed to establish secure tunnel. This
         stage with 'authorization' must not exceed the time set by 'timeout'
         option.
         
       authorization
         ssl tunnel is ready and afclient has to authorize itself to the
         afserver. This stage with 'ssl handshake' must not exceed the time set
         by 'timeout' option.
         
       unknown
         probably afserver internal state has been corrupted.
```

  3.4 Relay mode
  --------------

Afclient with '-p, --portnum PORT' option listens for connection  from  user  at
NAME:PORT.  NAME is set by '-d, --hostname' option or hostname() function,  when
the option is missing.

When user quits (close the connection or send 'quit' command),  afclient  exits.

================================================================================

==========
4. LOGGING
==========

Logging can be enabled by '-o, --log' option. The argument to this option must
be in the form:
  target,description,msgdesc

Where
  target is file or sock
  description is filename or host,port
  msgdesc is the subset of:
```
    LOG_T_ALL,
    LOG_T_USER,
    LOG_T_CLIENT,
    LOG_T_INIT,
    LOG_T_MANAGE,
    LOG_T_MAIN,
    LOG_I_ALL,
    LOG_I_CRIT,
    LOG_I_DEBUG,
    LOG_I_DDEBUG,
    LOG_I_INFO,
    LOG_I_NOTICE,
    LOG_I_WARNING,
    LOG_I_ERR
```
written without spaces.


  Example:
```
  file,filename,LOG_T_MANAGE,LOG_I_ALL
```

================================================================================

==========
5. MODULES
==========

Afclient can use external modules for user's packets  filtering  ('-l,  --load')
and service's packets filtering ('-L, --Load'). Module file has to declare three
functions:
```C
char* info(void);
```  
  info() return values:
  - info about module

  Example:
```C
  char*
  info(void)
  {
    return "Module tester v0.1";
  }
```

```C
int allow(char* host, char* port);
```
  allow() return values:
  0 - allow to connect
  !0 - drop the connection

  Example:

```C
  int
  allow(char* host, char* port)
  {
    return 0; /* allow to connect */
  }

int filter(char* host, unsigned char* message, int* length);
```
  filter() return values:
  0 - allow to transfer
  1 - drop the packet
  2 - drop the connection
  3 - release the module
  4 - drop the packet and release the module
  5 - drop the connection and release the module


  Example:
```C
  int
  filter(char* host, unsigned char* message, int* length)
  {
    int i;
    for (i = 1; i < *length; ++i) {
      if (message[i-1] == 'M') {
        if (message[i] == '1') {
          return 1; /* ignored */
        }
        if (message[i] == '2') {
          return 2; /* dropped */
        }
        if (message[i] == '3') {
          return 3; /* release */
        }
        if (message[i] == '4') {
          return 4; /* ignored + release */
        }
        if (message[i] == '5') {
          return 5; /* dropped + release */
        }
      }
    }
    return 0; /* allow to transfer */
  }
```
Modules have to be compiled with '-fPIC -shared' options.

================================================================================

================
6. MULTI TUNNELS
================

Since version 0.8  it's  possible  to  transfer  multiple  tunnels  in  the  one
`afclient <-> afserver` connection.

On the afserver we have to specify multiple listen ports with  the  same  manage
port.

When we set several '-p' options on the afclient, the new user connections  will
be distributed according  to  the  sequence  of  the  options,  i.e.   new  user
connecting to the second UsrCli pair  (with  the  same  manage  ports)  will  be
transferred to the destination pointed by the second '-p' option.

================================================================================

===========
7. EXAMPLES
===========

  7.1 tcp mode
  ------------

```
                    local network   |FireWall|   Internet
                                        ||
                                        ||                           User 1
                                        ||                           /(tcp)
             AF Client <---Encrypted/Compressed channel---> AF Server
             /                          ||                    |      \(tcp)
            /(tcp)                      ||               (tcp)|       User 2
           /                            ||                     \
    Http server                         ||                      User 3
                                        ||
```

The use of it is extremely simple. Let's suppose we want to create a http server
on our computer and we are behind a masquerade or a firewall:

1) We have to find some machine on the net with  an  external  ip  and  a  shell
   account.
   
2) Use "make" to compile everything on that machine. (you can freely remove the
   afclient and client.rsa files)

3) You can edit the config file or just type from the console (to use the config
   type -f `<cfgfile>`) :
```
        $ ./afserver
```
   This will work, if you want to use default values:
   - hostname will be taken from hostname function  (it  would  be  ideally,  if
     there is appropriate registration in /etc/hosts)
   - server will be listening for users on port 50127
   - server will be listening for client on port 50126
   - server will be for maximum 5 users
   - server will forward tcp packets
   - there will be no logging and no verbose messages
   - there will be no password identification
   - ip protocol family will be unspecified

4) We use "make" on our machine (we can delete everything apart from afclient
   and client.rsa)

5) We are typing from the console:
```
        $ ./afclient -n <name of the server> -p 80
```
   Where `<name of the server>`  is  a  string  like  :  'bastion.univ.gda.pl'  or
   '153.19.7.200'

6) We can now enter with a web-browser to: `<name of  the  server>:50127`  and  we
   will enter to our computer in the fact.

  7.2 reverse udp mode
  --------------------

```
                    local network   |FireWall|   Internet
                                        ||                     (udp)
                                        ||              User 1-------AF Client
                                        ||                           /(tcp)
             AF Client <---Encrypted/Compressed channel---> AF Server
             /                          ||                    |      
            /(udp)                      ||               (tcp)|       
           /                            ||                   /
    Game server                         ||               AF Client-------User 2
                                        ||                         (udp)
```

Let's see how to use af to forward udp packets. Suppose we want to create a game
server on our computer (udp port 27960 on our machine):

1) - 4)  is  the  same  like  in  example  1.  (but  we  add  option:  -p  udp)

5) We are typing from the console:
```
  $ ./afclient -u -n <name of the server> -p 27960
```
   Where `<name of the server>` is a name (or ip) of a host where  our  server  is
   running.

6) Connecting to our game is more complicated. The user must use afclient to do
   this.  He has to specify the server he is connecting to and the  port,  which
   his program will be listening on:
```
       $ ./afclient -U -d <hostname> -p <portnum> -n <name of the server>  \
         -m <server port>
```
   Where `<hostname>` is the name of the user machine (who wants to connect to our
   game). `<portnum>` is the port he will be connecting to. `<name of the server>`
   is the name of the host where our server is running.  `<server  port>`  is  the
   port on which the server is listening for users.  In order to connect to  our
   game, the user has to connect to `<hostname>:<portnum>`.

================================================================================

================
8. BUGS/PROBLEMS
================

There are no known/open bugs at the moment.

================================================================================

=====
NOTES
=====

Active port forwarder is still under development, so please sent  any  comments,
bugs notices and suggestions about it to `<jeremian [at] poczta.fm>`

If you have some problems or want to share your opinions with others, feel  free
to post a message at http://gray-world.net/board/

================================================================================

======
THANKS
======

 Big thanks to the GW Team:

 to Alex `<alex [at] gray-world.net>`
 and Simon `<scastro [at] entreelibre.com>` for testing AF and a lot of advices.

 Thanks to Ilia Perevezentsev `<iliaper [at] mail.ru>` who read and corrected the
README file.

 Thanks to Marco Solari `<marco.solari [at] koinesistemi.it>` for a lot of
requests, suggestions and ideas.

 Thanks to Joshua Judson Rosen `<rozzin [at] geekspace.com>` for the patch adding
certificate-based authentication to the APF.

 And thanks for using this software!

LICENSE
-------

  Active Port Forwarder is distributed  under  the  terms  of  the  GNU  General
  Public License v2.0  and is copyright (C)  2003-2007  jeremian  `<jeremian
  [at] poczta.fm>`. See the file COPYING for details.

  In addition, as a special exception, the copyright holders give permission  to
  link the code of portions of this  program  with  the  OpenSSL  library  under
  certain conditions as described in each individual source file, and distribute
  linked combinations including the two.
