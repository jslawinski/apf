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

#define SSL_PUBLIC_KEY_INVALID 0
#define SSL_PUBLIC_KEY_VALID 1
#define SSL_PUBLIC_KEY_NOT_KNOWN 2

#ifndef _JS_SSL_ROUTINES_H
#define _JS_SSL_ROUTINES_H

/* check if hostname and keyhash is known */
int check_public_key(char* filename, char* hostname, char* keyhash);
/* add hostname and keyhash to known_hosts file */
void add_public_key(char* filename, char* hostname, char* keyhash);

#endif

