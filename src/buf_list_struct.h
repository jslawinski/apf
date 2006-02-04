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

#ifndef _JS_BUF_LIST_STRUCT_H
#define _JS_BUF_LIST_STRUCT_H

#include "buf_list_node_struct.h"

typedef struct buflist {
  BufListNode* head;
  BufListNode* tail;
} BufList;

/* 'constructor' */
BufList* BufList_new();
/* 'destructor' */
void BufList_free(BufList** bl);
/* other */
void BufList_insert_back(BufList* bl, BufListNode* bln);
BufListNode* BufList_get_first(BufList* bl);
void BufList_delete_first(BufList* bl);
void BufList_clear(BufList* bl);

#endif
