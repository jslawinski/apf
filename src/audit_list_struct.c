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

#include "audit_list_struct.h"

/*
 * Function name: AuditList_new
 * Description: Create and initialize new AuditList structure.
 * Returns: Newly created AuditList structure.
 */

AuditList*
AuditList_new()
{
  AuditList* tmp = calloc(1, sizeof(AuditList));
  if (tmp == NULL) {
    return NULL;
  }
  return tmp;
}

/*
 * Function name: AuditList_free
 * Description: Free the memory allocated for AuditList structure.
 * Arguments: al - pointer to pointer to AuditList structure.
 */

void
AuditList_free(AuditList** al)
{
  if (al == NULL) {
    return;
  }
  if ((*al) == NULL) {
    return;
  }
  AuditList_clear((*al));
  free((*al));
  (*al) = NULL;
}

/*
 * Function name: AuditList_insert_back
 * Description: Insert new node at the end of the list.
 * Arguments: al - pointer to AuditList structure
 *            aln - pointer to AuditListNode structure
 */

void
AuditList_insert_back(AuditList* al, AuditListNode* aln)
{
  if (al == NULL) {
    return;
  }
  if (aln == NULL) {
    return;
  }
  if (al->tail) {
    al->tail->nextNode = aln;
  }
  else {
    al->head = aln;
  }
  al->tail = aln;
  aln->nextNode = NULL;
}

/*
 * Function name: AuditList_get_first
 * Description: Get first node from the beginning of the list.
 * Arguments: al - pointer to AuditList structure
 * Returns: First node from the beginning of the list.
 */

AuditListNode*
AuditList_get_first(AuditList* al)
{
  if (al == NULL) {
    return NULL;
  }
  return al->head;
}

/*
 * Function name: AuditList_delete_first
 * Description: Deletes first node from the beginning of the list.
 * Arguments: al - pointer to AuditList structure
 */

void
AuditList_delete_first(AuditList* al)
{
  AuditListNode* tmp = AuditList_get_first(al);
  if (tmp == NULL) {
    return;
  }
  if (tmp == al->tail) { /* this is the last node in the list */
    al->head = al->tail = NULL;
  }
  else { /* there are other nodes*/
    al->head = AuditListNode_get_nextNode(tmp);
  }
  AuditListNode_free(&tmp);
}

/*
 * Function name: AuditList_clear
 * Description: Deletes all nodes from the list.
 * Arguments: al - pointer to AuditList structure
 */

void
AuditList_clear(AuditList* al)
{
  while (AuditList_get_first(al)) {
    AuditList_delete_first(al);
  }
}
