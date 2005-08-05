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

#include "buf_list_node_struct.h"

/*
 * Function name: BufListNode_new
 * Description: Create and initialize new BufListNode structure.
 * Returns: Newly created BufListNode structure.
 */

BufListNode*
BufListNode_new()
{
  BufListNode* tmp = calloc(1, sizeof(BufListNode));
  if (tmp == NULL) {
    return NULL;
  }
  return tmp;
}

/*
 * Function name: BufListNode_new_message
 * Description: Create and initialize new BufListNode structure from given message
 *              with actual buffer pointer and message length.
 * Arguments: actPtr - actual buffer pointer
 *            msgLen - length of the message
 *            message - message to be stored
 * Returns: Newly created and initialized BufListNode structure.
 */

BufListNode*
BufListNode_new_message(int actPtr, int msgLen, unsigned char* message)
{
  BufListNode* tmp = calloc(1, sizeof(BufListNode));
  if (tmp == NULL) {
    return NULL;
  }
  BufListNode_set_message(tmp, message, msgLen);
  BufListNode_set_actPtr(tmp, actPtr);
  return tmp;
}

/*
 * Function name: BufListNode_free
 * Description: Free the memory allocated for BufListNode structure.
 * Arguments: bln - pointer to pointer to BufListNode structure
 */

void
BufListNode_free(BufListNode** bln)
{
  if (bln == NULL) {
    return;
  }
  if ((*bln) == NULL) {
    return;
  }
  if ((*bln)->message) {
    free((*bln)->message);
    (*bln)->message = NULL;
  }
  free((*bln));
  (*bln) = NULL;
}

/*
 * Function name: BufListNode_set_actPtr
 * Description: Set actual buffer pointer.
 * Arguments: bln - pointer to BufListNode structure
 *            actPtr - actual buffer pointer
 */

void
BufListNode_set_actPtr(BufListNode* bln, int actPtr)
{
  if (bln == NULL) {
    return;
  }
  bln->actPtr = actPtr;
}

/*
 * Function name: BufListNode_set_msgLen
 * Description: Set length of the message.
 * Arguments: bln - pointer to BufListNode structure
 *            msgLen - length of the message
 */

void
BufListNode_set_msgLen(BufListNode* bln, int msgLen)
{
  if (bln == NULL) {
    return;
  }
  bln->msgLen = msgLen;
}

/*
 * Function name: BufListNode_set_message
 * Description: Set message to be stored.
 * Arguments: bln - pointer to BufListNode structure
 *            message - message to be stored
 *            msgLen - length of the message
 */

void
BufListNode_set_message(BufListNode* bln, unsigned char* message, int msgLen)
{
  if (bln == NULL) {
    return;
  }
  if (bln->message) {
    free(bln->message);
    bln->message = NULL;
  }
  BufListNode_set_actPtr(bln, 0);
  BufListNode_set_msgLen(bln, 0);
  if (message == NULL) {
    return;
  }
  bln->message = calloc(1, msgLen);
  if (bln->message == NULL) {
    return;
  }
  memcpy(bln->message, message, msgLen);
  BufListNode_set_msgLen(bln, msgLen);
}

/*
 * Function name: BufListNode_set_nextNode
 * Description: Set next node pointer.
 * Arguments: bln - pointer to BufListNode structure
 *            nextNode - next node pointer
 */

void
BufListNode_set_nextNode(BufListNode* bln, BufListNode* nextNode)
{
  if (bln == NULL) {
    return;
  }
  bln->nextNode = nextNode;
}

/*
 * Function name: BufListNode_get_actPtr
 * Description: Get actual buffer pointer.
 * Aguments: bln - pointer to BufListNode structure
 * Returns: Actual buffer pointer.
 */

int
BufListNode_get_actPtr(BufListNode* bln)
{
  if (bln == NULL) {
    return -1;
  }
  return bln->actPtr;
}

/*
 * Function name: BufListNode_get_msgLen
 * Description: Get length of the message.
 * Arguments: bln - pointer to BufListNode structure
 * Returns: Length of the message.
 */

int
BufListNode_get_msgLen(BufListNode* bln)
{
  if (bln == NULL) {
    return -1;
  }
  return bln->msgLen;
}

/*
 * Function name: BufListNode_get_message
 * Description: Get stored message.
 * Arguments: bln - pointer to BufListNode structure
 * Returns: Stored message.
 */

unsigned char*
BufListNode_get_message(BufListNode* bln)
{
  if (bln == NULL) {
    return NULL;
  }
  return bln->message;
}

/*
 * Function name: BufListNode_get_nextNode
 * Description: Get next node pointer.
 * Arguments: bln - pointer to BufListNode structure
 * Returns: Next BufListNode structure pointer or NULL, if there is no next one.
 */

BufListNode*
BufListNode_get_nextNode(BufListNode* bln)
{
  if (bln == NULL) {
    return NULL;
  }
  return bln->nextNode;
}

/*
 * Function name: BufListNode_readMessage
 * Description: Reads the message from actual buffer pointer.
 * Arguments: bln - pointer to BufListNode structure
 * Returns: Tail of the message from actual buffer pointer.
 */

unsigned char*
BufListNode_readMessage(BufListNode* bln)
{
  if (bln == NULL) {
    return NULL;
  }
  return (&bln->message[BufListNode_get_actPtr(bln)]);
}

/*
 * Function name: BufListNode_readMessageLength
 * Description: Get the amount of unread bytes in the message.
 * Arguments: bln - pointer to BufListNode structure
 * Returns: The amount of unread bytes in the message.
 */

int
BufListNode_readMessageLength(BufListNode* bln)
{
  int tmp = 0;
  if (bln == NULL) {
    return -1;
  }
  if (BufListNode_get_message(bln) == NULL) {
    return -1;
  }
  tmp = BufListNode_get_msgLen(bln) - BufListNode_get_actPtr(bln);
  if (tmp < 0) {
    return 0;
  }
  return tmp;
}
