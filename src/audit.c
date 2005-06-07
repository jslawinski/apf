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

#include <stdlib.h>
#include <string.h>

#include "audit.h"

int
insertalnode(alnodeT** headRef, int uid, char* nbuf, char* pbuf, time_t ctime, time_t dur)
{
  alnodeT* newnode, *lastnode;
	lastnode = newnode = *headRef;
	while (newnode) {
		lastnode = newnode;
		newnode = newnode->next;
	}
  newnode = calloc(1, sizeof(alnodeT));
  newnode->userid = uid;
  memcpy(newnode->namebuf, nbuf, 128);
  memcpy(newnode->portbuf, pbuf, 7);
  newnode->connecttime = ctime;
  newnode->duration = dur;
  newnode->next = NULL;
	if (lastnode)
		lastnode->next = newnode;
	else
		*headRef = newnode;
	return 0;
}

int
deletealnode(alnodeT** headRef)
{
	alnodeT* node = *headRef;
	if (*headRef == NULL)
		return 1;
  *headRef = node->next;
  free(node);
	return 0;
}

int
freeauditlist(alnodeT** headRef)
{
	while (*headRef) {
		deletealnode(headRef);
	}
	return 0;
}
