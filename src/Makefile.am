bin_PROGRAMS = afserver afclient
afserver_SOURCES = afserver.c network.c file.c stats.c buf_list_node_struct.c buf_list_struct.c \
									 server_remoteadmin.c server_check.c server_set.c server_eval.c server_find.c \
									 server_remove.c make_ssl_handshake.c first_run.c inet_ntop.c realmnames.c \
									 clientnames.c usernames.c server_get.c \
									 server_signals.c usage.c logging.c daemon.c ssl_fd_struct.c \
									 user_stats_struct.c usr_cli_struct.c connect_user_struct.c string_functions.c \
									 audit_list_node_struct.c audit_list_struct.c connect_client_struct.c timeval_functions.c \
									 header_buffer_struct.c server_realm_struct.c server_configuration_struct.c file_server.c \
									 task_struct.c task_list_node_struct.c task_scheduler_struct.c remove_client_task.c
afclient_LDFLAGS = ${USE_RDYNAMIC}
afclient_SOURCES = afclient.c network.c file.c stats.c buf_list_node_struct.c buf_list_struct.c \
									 module_struct.c client_remoteadmin.c make_ssl_handshake.c first_run.c inet_ntop.c \
									 client_reverse_udp.c server_check.c client_initialization.c \
									 client_shutdown.c client_signals.c usage.c logging.c daemon.c base64.c ssl_routines.c \
									 connect_user_struct.c user_stats_struct.c string_functions.c ar_options_struct.c \
									 audit_list_node_struct.c audit_list_struct.c ssl_fd_struct.c timeval_functions.c \
									 usr_cli_struct.c header_buffer_struct.c client_configuration_struct.c file_client.c \
									 client_realm_struct.c port_list_node_struct.c port_list_struct.c
