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

#ifndef _JS_BUF_LIST_NODE_STRUCT_H
#define _JS_BUF_LIST_NODE_STRUCT_H

typedef struct blnode {
  int actPtr;
  int msgLen;
  unsigned char* message;
  struct blnode* nextNode;
} BufListNode;

/* 'constructors' */
BufListNode* BufListNode_new();
BufListNode* BufListNode_new_message(int actPtr, int msgLen, unsigned char* message);
/* 'destructor' */
void BufListNode_free(BufListNode** bln);
/* setters */
void BufListNode_set_actPtr(BufListNode* bln, int actPtr);
void BufListNode_set_msgLen(BufListNode* bln, int msgLen);
void BufListNode_set_message(BufListNode* bln, unsigned char* message, int msgLen);
void BufListNode_set_nextNode(BufListNode* bln, BufListNode* nextNode);
/* getters */
int BufListNode_get_actPtr(BufListNode* bln);
int BufListNode_get_msgLen(BufListNode* bln);
unsigned char* BufListNode_get_message(BufListNode* bln);
BufListNode* BufListNode_get_nextNode(BufListNode* bln);
/* other methods */
unsigned char* BufListNode_readMessage(BufListNode* bln);
int BufListNode_readMessageLength(BufListNode* bln);

#endif
