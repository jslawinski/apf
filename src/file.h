/*
 * active port forwarder - software for secure forwarding
 * Copyright (C) 2003-2006 jeremian <jeremian [at] poczta.fm>
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

#include "activefor.h"
#include "network.h"
#include "server_configuration_struct.h"
#include "client_configuration_struct.h"
#include <openssl/ssl.h>

#ifndef _JS_FILE_H
#define _JS_FILE_H

#define  F_UNKNOWN  1
#define  F_IGNORE   2
#define  F_ROPTION  3
#define  F_RVALUE   4
#define  F_MIDDLE   5

int parse_line(char* buff, char* tab1, char* tab2); /* parse one line of the file */
ServerConfiguration* parsefile(char*, int*); /* parse the cfg file */
ClientConfiguration* cparsefile(char*, int*); /* parse the client's cfg file */

#endif

