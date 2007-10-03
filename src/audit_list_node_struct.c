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
#include <string.h>
#include <assert.h>

#include "audit_list_node_struct.h"

/*
 * Function name: AuditListNode_new
 * Description: Create and initialize new AuditListNode structure.
 * Returns: Newly created AuditListNode structure.
 */

AuditListNode*
AuditListNode_new()
{
  AuditListNode* tmp = calloc(1, sizeof(AuditListNode));
  assert(tmp != NULL);
  if (tmp == NULL) {
    return NULL;
  }
  return tmp;
}

/*
 * Function name: AuditListNode_new_entry
 * Description: Create and initialize new AuditListNode structure from given arguments.
 * Arguments: userId - identification number of the user
 *            nameBuf - name of the user
 *            portBuf - port from which user is connected
 *            connectTime - start time of the connection
 *            duration - duration of the connection
 * Returns: Newly created and initialized AuditListNode structure.
 */

AuditListNode*
AuditListNode_new_entry(int userId, char* nameBuf, char* portBuf,
        time_t connectTime, time_t duration)
{
  AuditListNode* tmp = calloc(1, sizeof(AuditListNode));
  assert(tmp != NULL);
  if (tmp == NULL) {
    return NULL;
  }
  AuditListNode_set_userId(tmp, userId);
  AuditListNode_set_nameBuf(tmp, nameBuf);
  AuditListNode_set_portBuf(tmp, portBuf);
  AuditListNode_set_connectTime(tmp, connectTime);
  AuditListNode_set_duration(tmp, duration);
  return tmp;
}

/*
 * Function name: AuditListNode_free
 * Description: Free the memory allocated for AuditListNode structure.
 * Arguments: aln - pointer to pointer to AuditListNode structure
 */

void
AuditListNode_free(AuditListNode** aln)
{
  assert(aln != NULL);
  if (aln == NULL) {
    return;
  }
  assert((*aln) != NULL);
  if ((*aln) == NULL) {
    return;
  }
  free((*aln));
  (*aln) = NULL;
}

/*
 * Function name: AuditListNode_set_userId
 * Description: Set user identification number.
 * Arguments: aln - pointer to AuditListNode structure
 *            userId - user identification number
 */

void
AuditListNode_set_userId(AuditListNode* aln, int userId)
{
  assert(aln != NULL);
  if (aln == NULL) {
    return;
  }
  aln->userId = userId;
}

/*
 * Function name: AuditListNode_set_nameBuf
 * Description: Set user name.
 * Arguments: aln - pointer to AuditListNode structure
 *            nameBuf - user name
 */

void
AuditListNode_set_nameBuf(AuditListNode* aln, char* nameBuf)
{
  assert(aln != NULL);
  if (aln == NULL) {
    return;
  }
  memset(aln->nameBuf, 0, 7);
  strncpy(aln->nameBuf, nameBuf, 6);
}

/*
 * Function name: AuditListNode_set_portBuf
 * Description: Set port from which user is connected.
 * Arguments: aln - pointer to AuditListNode structure
 *            portBuf - port from which user is connected
 */

void
AuditListNode_set_portBuf(AuditListNode* aln, char* portBuf)
{
  assert(aln != NULL);
  if (aln == NULL) {
    return;
  }
  memset(aln->portBuf, 0, 7);
  strncpy(aln->portBuf, portBuf, 6);
}

/*
 * Function name: AuditListNode_set_connectTime
 * Description: Set start time of the connection.
 * Arguments: aln - pointer to AuditListNode structure
 *            connectTime - start time of the connection
 */

void
AuditListNode_set_connectTime(AuditListNode* aln, time_t connectTime)
{
  assert(aln != NULL);
  if (aln == NULL) {
    return;
  }
  aln->connectTime = connectTime;
}

/*
 * Function name: AuditListNode_set_duration
 * Description: Set duration of the connection.
 * Arguments: aln - pointer to AuditListNode structure
 *            duration - duration of the connection
 */

void
AuditListNode_set_duration(AuditListNode* aln, time_t duration)
{
  assert(aln != NULL);
  if (aln == NULL) {
    return;
  }
  aln->duration = duration;
}

/*
 * Function name: AuditListNode_set_nextNode
 * Description: Set next node pointer.
 * Arguments: aln - pointer to AuditListNode structure
 *            nextNode - next node pointer
 */

void
AuditListNode_set_nextNode(AuditListNode* aln, AuditListNode* nextNode)
{
  assert(aln != NULL);
  if (aln == NULL) {
    return;
  }
  aln->nextNode = nextNode;
}

/*
 * Function name: AuditListNode_get_userId
 * Description: Get user identification number.
 * Arguments: aln - pointer to AuditListNode structure
 * Returns: User identification number.
 */

int
AuditListNode_get_userId(AuditListNode* aln)
{
  assert(aln != NULL);
  if (aln == NULL) {
    return -1;
  }
  return aln->userId;
}

/*
 * Function name: AuditListNode_get_nameBuf
 * Description: Get user name.
 * Arguments: aln - pointer to AuditListNode structure
 * Returns: User name.
 */

char*
AuditListNode_get_nameBuf(AuditListNode* aln)
{
  assert(aln != NULL);
  if (aln == NULL) {
    return NULL;
  }
  return aln->nameBuf;
}

/*
 * Function name: AuditListNode_get_portBuf
 * Description: Get port from which user is connected.
 * Arguments: aln - pointer to AuditListNode structure
 * Returns: Port from which user is connected.
 */

char*
AuditListNode_get_portBuf(AuditListNode* aln)
{
  assert(aln != NULL);
  if (aln == NULL) {
    return NULL;
  }
  return aln->portBuf;
}

/*
 * Function name: AuditListNode_get_connectTime
 * Description: Get start time of the connection.
 * Arguments: aln - pointer to AuditListNode structure
 * Returns: Start time of the connection.
 */

time_t
AuditListNode_get_connectTime(AuditListNode* aln)
{
  assert(aln != NULL);
  if (aln == NULL) {
    return 0;
  }
  return aln->connectTime;
}

/*
 * Function name: AuditListNode_get_duration
 * Description: Get duration of the connection.
 * Arguments: aln - pointer to AuditListNode structure
 * Returns: Duration of the connection.
 */

time_t
AuditListNode_get_duration(AuditListNode* aln)
{
  assert(aln != NULL);
  if (aln == NULL) {
    return 0;
  }
  return aln->duration;
}

/*
 * Function name: AuditListNode_get_nextNode
 * Description: Get next node pointer.
 * Arguments: aln - pointer to AuditListNode structure
 * Returns: Next node pointer.
 */

AuditListNode*
AuditListNode_get_nextNode(AuditListNode* aln)
{
  assert(aln != NULL);
  if (aln == NULL) {
    return NULL;
  }
  return aln->nextNode;
}

/*
 * Function name: AuditListNode_get_connectTimep
 * Description: Get pointer to time_t variable holding start time of the connection.
 * Arguments: aln - pointer to AuditListNode structure
 * Returns: Pointer to time_t variable holding start time of the connection.
 */

time_t*
AuditListNode_get_connectTimep(AuditListNode* aln)
{
  assert(aln != NULL);
  if (aln == NULL) {
    return 0;
  }
  return (&(aln->connectTime));
}
