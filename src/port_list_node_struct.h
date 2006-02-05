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

#ifndef _JS_PORT_LIST_NODE_STRUCT_H
#define _JS_PORT_LIST_NODE_STRUCT_H

typedef struct plnode {
  char* portName;
  struct plnode* nextNode;
} PortListNode;

/* 'constructor' */
PortListNode* PortListNode_new(char* portName);
/* 'destructor' */
void PortListNode_free(PortListNode** pln);
/* setters */
void PortListNode_set_portName(PortListNode* pln, char* portName);
void PortListNode_set_nextNode(PortListNode* pln, PortListNode* nextNode);
/* getters */
char* PortListNode_get_portName(PortListNode* pln);
PortListNode* PortListNode_get_nextNode(PortListNode* pln);

#endif
