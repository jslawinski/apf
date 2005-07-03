bin_PROGRAMS = afserver afclient
afserver_SOURCES = afserver.c network.c file.c stats.c buflist.c remoteadmin.c \
									 server_check.c server_set.c server_eval.c server_find.c server_remove.c \
									 make_ssl_handshake.c first_run.c inet_ntop.c realmnames.c clientnames.c usernames.c \
									 http_proxy_functions.c http_proxy_server.c server_get.c thread_management.c \
									 server_signals.c usage.c logging.c audit.c daemon.c
afclient_LDFLAGS = ${USE_RDYNAMIC} ${LINKED_LDLIB}
afclient_SOURCES = afclient.c network.c stats.c buflist.c modules.c remoteadmin.c \
								 make_ssl_handshake.c first_run.c inet_ntop.c realmnames.c clientnames.c usernames.c \
								 http_proxy_functions.c http_proxy_client.c thread_management.c \
								 client_reverse_udp.c server_check.c client_initialization.c client_shutdown.c \
								 client_signals.c usage.c logging.c audit.c daemon.c base64.c ssl_routines.c
