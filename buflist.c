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

#include <stdlib.h>
#include <string.h>

#include "buflist.h"

int
insertblnode(blnodeT** headRef, int actptr, int msglen, unsigned char* buff)
{
        blnodeT* newnode, *lastnode;
	lastnode = newnode = *headRef;
	while (newnode) {
		lastnode = newnode;
		newnode = newnode->next;
	}
        newnode = calloc(1, sizeof(blnodeT));
        newnode->next = NULL;
	newnode->actptr = 0;
	newnode->msglen = msglen - actptr;
	newnode->buff = calloc(1, newnode->msglen);
	if (newnode->buff == NULL)
		return 1;
	strncpy(newnode->buff, buff, newnode->msglen);
	if (lastnode)
		lastnode->next = newnode;
	else
		*headRef = newnode;
	return 0;
}

int
deleteblnode(blnodeT** headRef)
{
	blnodeT* node = *headRef;
	if (*headRef == NULL)
		return 1;
        *headRef = node->next;
        free(node->buff);
        free(node);
	return 0;
}

int
freebuflist(blnodeT** headRef)
{
	while (*headRef) {
		deleteblnode(headRef);
	}
	return 0;
}
