/*
 * active port forwarder - software for secure forwarding
 * Copyright (C) 2003,2004 jeremian <jeremian [at] poczta.fm>
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

/* This example module put IP of the connected user into a body of the message */
#include <string.h>
/* There is no required headers for module to work.
 * We just need string.h for memcpy and strlen functions.
 */

/* info
 * return values:
 * info about module
 */

char*
info(void)
{
	return "An example module";
}

/* allow
 * return values:
 * 0 - allow to connect
 * !=0 - drop the connection
 */

int
allow(char* host, char* port)
{
	return 0; /* allow to connect */
}

/* filter
 * return values:
 * 0 - allow to transfer
 * 1 - drop the packet
 * 2 - drop the connection
 */

int
filter(char* host, unsigned char* message, int* length)
{
	int n;
	n = strlen(host);
	message[*length] = '|';
	memcpy(&message[*length+1], host, n);
	*length += n+1;
	return 0; /* allow to transfer */
}
