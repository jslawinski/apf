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

/* This example module scan the message for specified string and perform
 * appropriate action
 */

/* info
 * return values:
 * info about module
 */

char*
info(void)
{
	return "Module tester v0.1";
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
 * 3 - release the module
 * 4 - drop the packet and release the module
 * 5 - drop the connection and release the module
 */

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
