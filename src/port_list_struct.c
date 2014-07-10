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

#include <config.h>

#include <stdlib.h>
#include <assert.h>

#include "port_list_struct.h"

/*
 * Function name: PortList_new
 * Description: Creates and initialies new PortList structure.
 * Returns: Newly created PortList structure.
 */

PortList*
PortList_new()
{
  PortList* tmp = calloc(1, sizeof(PortList));
  assert(tmp != NULL);
  if (tmp == NULL) {
    return NULL;
  }
  return tmp;
}

/*
 * Function name: PortList_free
 * Description: Frees the memory allocated for PortList structure.
 * Arguments: pl - pointer to pointer to PortList structure
 */

void
PortList_free(PortList** pl)
{
  assert(pl != NULL);
  if (pl == NULL) {
    return;
  }
  assert((*pl) != NULL);
  if ((*pl) == NULL) {
    return;
  }
  PortList_clear((*pl));
  free((*pl));
  (*pl) = NULL;
}

/*
 * Function name: PortList_insert_back
 * Description: Inserts new node at the end of the list.
 * Arguments: pl - pointer to PortList structure
 *            pln - pointer to PortListNode structure
 */

void
PortList_insert_back(PortList* pl, PortListNode* pln)
{
  assert(pl != NULL);
  if (pl == NULL) {
    return;
  }
  assert(pln != NULL);
  if (pln == NULL) {
    return;
  }
  if (pl->tail) {
    pl->tail->nextNode = pln;
  }
  else {
    pl->head = pln;
  }
  pl->tail = pln;
  pln->nextNode = NULL;
  pl->size += 1;
}

/*
 * Function name: PortList_get_nth
 * Description: Get the nth node from the beginning of the list.
 * Arguments: pl - pointer to PortList structure
 *            n - the number of the node
 * Returns: Nth node from the beginning of the list.
 */

PortListNode*
PortList_get_nth(PortList* pl, int n)
{
  PortListNode* tmp;
  assert(pl != NULL);
  if (pl == NULL) {
    return NULL;
  }
  assert(n >= 0);
  assert(n < PortList_get_size(pl));
  tmp = pl->head;
  while (tmp) {
    if (n <= 0) {
      return tmp;
    }
    n -= 1;
    tmp = PortListNode_get_nextNode(tmp);
  }
  return NULL;
}

/*
 * Function name: PortList_get_size
 * Description: Returns the size of the list.
 * Arguments: pl - pointer to PortList structure
 * Returns: The size of the list.
 */

int
PortList_get_size(PortList* pl)
{
  assert(pl != NULL);
  if (pl == NULL) {
    return -1;
  }
  return pl->size;
}

/*
 * Function name: PortList_clear
 * Description: Deletes all nodes from the list.
 * Arguments: pl - pointer to PortList structure
 */

void
PortList_clear(PortList* pl)
{
  PortListNode* tmp;
  assert(pl != NULL);
  if (pl == NULL) {
    return;
  }
  while (pl->head) {
    tmp = pl->head;
    if (tmp == pl->tail) {
      pl->head = pl->tail = NULL;
    }
    else {
      pl->head = PortListNode_get_nextNode(pl->head);
    }
    PortListNode_free(&tmp);
  }
  pl->size = 0;
}
