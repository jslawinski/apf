/*
 * active port forwarder - software for secure forwarding
 * Copyright (C) 2003-2007 jeremian <jeremian [at] poczta.fm>
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

#ifndef _JS_PORT_LIST_STRUCT_H
#define _JS_PORT_LIST_STRUCT_H

#include "port_list_node_struct.h"

typedef struct portlist {
  int size;
  PortListNode* head;
  PortListNode* tail;
} PortList;

/* 'constructor' */
PortList* PortList_new();
/* 'destructor' */
void PortList_free(PortList** pl);
/* other */
void PortList_insert_back(PortList* pl, PortListNode* pln);
PortListNode* PortList_get_nth(PortList* pl, int n);
int PortList_get_size(PortList* pl);
void PortList_clear(PortList* pl);

#endif
