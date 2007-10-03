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

#include "port_list_node_struct.h"
#include "string_functions.h"

/*
 * Function name: PortListNode_new
 * Description: Creates and initializes new PortListNode structure from the
 *              given port name.
 * Arguments: portName - the port name
 * Returns: Newly created PortListNode structure.
 */

PortListNode*
PortListNode_new(char* portName)
{
  PortListNode* tmp = calloc(1, sizeof(PortListNode));
  assert(tmp != NULL);
  if (tmp == NULL) {
    return NULL;
  }
  PortListNode_set_portName(tmp, portName);
  return tmp;
}

/*
 * Function name: PortListNode_free
 * Description: Frees the memory allocated for PortListNode structure.
 * Arguments: pln - pointer to pointer to PortListNode structure
 */

void
PortListNode_free(PortListNode** pln)
{
  assert(pln != NULL);
  if (pln == NULL) {
    return;
  }
  assert((*pln) != NULL);
  if ((*pln) == NULL) {
    return;
  }
  if ((*pln)->portName) {
    free((*pln)->portName);
    (*pln)->portName = NULL;
  }
  free((*pln));
  (*pln) = NULL;
}

/*
 * Function name: PortListNode_set_portName
 * Description: Sets the port name.
 * Arguments: pln - pointer to PortListNode structure
 *            portName - the port name
 */

void
PortListNode_set_portName(PortListNode* pln, char* portName)
{
  assert(pln != NULL);
  if (pln == NULL) {
    return;
  }
  string_cp(&(pln->portName), portName);
}

/*
 * Function name: PortListNode_set_nextNode
 * Description: Sets next node pointer.
 * Arguments: pln - pointer to PortListNode structure
 *            nextNode - next node pointer
 */

void
PortListNode_set_nextNode(PortListNode* pln, PortListNode* nextNode)
{
  assert(pln != NULL);
  if (pln == NULL) {
    return;
  }
  pln->nextNode = nextNode;
}

/*
 * Function name: PortListNode_get_portName
 * Description: Gets the port name.
 * Arguments: pln - pointer to PortListNode structure
 * Returns: The port name.
 */

char*
PortListNode_get_portName(PortListNode* pln)
{
  assert(pln != NULL);
  if (pln == NULL) {
    return NULL;
  }
  return pln->portName;
}

/*
 * Function name: PortListNode_get_nextNode
 * Description: Gets next node pointer.
 * Arguments: pln - pointer to PortListNode structure
 * Returns: Next PortListNode structure pointer or NULL, if there is no next one.
 */

PortListNode*
PortListNode_get_nextNode(PortListNode* pln)
{
  assert(pln != NULL);
  if (pln == NULL) {
    return NULL;
  }
  return pln->nextNode;
}
