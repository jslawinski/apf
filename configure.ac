#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([Active port forwarder], [0.6], [jeremian@poczta.fm], [apf])
AM_INIT_AUTOMAKE([apf], [0.6])
AC_COPYRIGHT([
Copyright (C) 2003,2004,2005 jeremian - <jeremian [[at]] poczta.fm>
===================

================================================================================

GRAY-WORLD.NET / Active Port Forwarder
==========================

  The Active Port Forwarder program is  part  of  the  Gray-World.net  projects.

  Our Gray-World Team presents on the http://gray-world.net website the projects
  and publications we are working on which are  related  to  the  NACS  (Network
  Access Control System) bypassing  research  field  and  to  the  computer  and
  network security topics.

================================================================================
])
AC_CONFIG_SRCDIR([src/afserver.c])
AM_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile
                 modules/Makefile
                 src/Makefile])

CFLAGS="-pedantic -Wall -O2"

# Checks for programs.
AC_PROG_CC
AC_PROG_GCC_TRADITIONAL
AC_CHECK_PROGS(HAVE_OPENSSL, [openssl])

# Checks for libraries.
AC_CHECK_LIB([ssl], [SSL_library_init], [],
             [
              AC_ERROR("lib ssl not found!")
              ])
AC_CHECK_LIB([z], [compress], [],
             [
              AC_ERROR("zlib not found!")
              ])
AC_CHECK_LIB([dl], [dlopen],
             [
              LINKED_LDLIB="-ldl"
              USE_RDYNAMIC="-rdynamic"
              AC_DEFINE(HAVE_LIBDL, 1, [Define to 1 if you have the `dl' library (-ldl).])
              ],
              [
               LINKED_LDLIB=""
               USE_RDYNAMIC=""
               ])
AC_SUBST(LINKED_LDLIB)
AC_SUBST(USE_RDYNAMIC)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/ioctl.h sys/socket.h sys/time.h unistd.h sys/types.h pwd.h linux/sockios.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([bzero gethostname gettimeofday memset select socket strtol getaddrinfo])
AC_CHECK_FUNCS([SSL_library_init SSL_get_cipher_name SSL_get_cipher_version ERR_error_string ERR_get_error SSL_CTX_new SSL_CTX_set_cipher_list SSL_CTX_use_RSAPrivateKey_file SSL_CTX_use_certificate_file SSL_new SSL_clear SSL_write SSL_read SSL_accept SSL_set_fd SSL_connect SSL_load_error_strings SSL_get_error])
AC_CHECK_FUNCS([compress uncompress])
AC_CHECK_FUNCS([dlopen dlsym dlclose])
AC_CHECK_FUNCS([getpwnam])
AC_CHECK_FUNCS([inet_ntop getnameinfo])

AC_OUTPUT
