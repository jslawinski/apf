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

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "buf_list_struct.h"

/*
 * Function name: BufList_new
 * Description: Creates and initializes new BufList structure.
 * Returns: Newly created BufList structure.
 */

BufList*
BufList_new()
{
  BufList* tmp = calloc(1, sizeof(BufList));
  assert(tmp != NULL);
  if (tmp == NULL) {
    return NULL;
  }
  return tmp;
}

/*
 * Function name: BufList_free
 * Description: Frees the memory allocated for BufList structure.
 * Arguments: bl - pointer to pointer to BufList structure.
 */

void
BufList_free(BufList** bl)
{
  assert(bl != NULL);
  if (bl == NULL) {
    return;
  }
  assert((*bl) != NULL);
  if ((*bl) == NULL) {
    return;
  }
  BufList_clear((*bl));
  free((*bl));
  (*bl) = NULL;
}

/*
 * Function name: BufList_insert_back
 * Description: Inserts new node at the end of the list.
 * Arguments: bl - pointer to BufList structure
 *            bln - pointer to BufListNode structure
 */

void
BufList_insert_back(BufList* bl, BufListNode* bln)
{
  assert(bl != NULL);
  if (bl == NULL) {
    return;
  }
  assert(bln != NULL);
  if (bln == NULL) {
    return;
  }
  if (bl->tail) {
    bl->tail->nextNode = bln;
  }
  else {
    bl->head = bln;
  }
  bl->tail = bln;
  bln->nextNode = NULL;
}

/*
 * Function name: BufList_get_first
 * Description: Get first node from the beginning of the list.
 * Arguments: bl - pointer to BufList structure
 * Returns: First node from the beginning of the list.
 */

BufListNode*
BufList_get_first(BufList* bl)
{
  assert(bl != NULL);
  if (bl == NULL) {
    return NULL;
  }
  return bl->head;
}

/*
 * Function name: BufList_delete_first
 * Description: Deletes first node from the beginning of the list.
 * Arguments: bl - pointer to BufList structure
 */

void
BufList_delete_first(BufList* bl)
{
  BufListNode* tmp = BufList_get_first(bl);
  assert(tmp != NULL);
  if (tmp == NULL) {
    return;
  }
  if (tmp == bl->tail) { /* this is the last node in the list */
    bl->head = bl->tail = NULL;
  }
  else { /* there are other nodes*/
    bl->head = BufListNode_get_nextNode(tmp);
  }
  BufListNode_free(&tmp);
}

/*
 * Function name: BufList_clear
 * Description: Deletes all nodes from the list.
 * Arguments: bl - pointer to BufList structure
 */

void
BufList_clear(BufList* bl)
{
  assert(bl != NULL);
  if (bl == NULL) {
    return;
  }
  while (BufList_get_first(bl)) {
    BufList_delete_first(bl);
  }
}
