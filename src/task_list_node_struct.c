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
#include <assert.h>

#include "task_list_node_struct.h"

/*
 * Function name: TaskListNode_new
 * Description: Creates and initializes new task list node. The task must point
 *              at previously allocated Task structure.
 * Arguments: task - pointer to Task structure, which must be previously initialized
 * Returns: Pointer to newly created TaskListNode structure.
 */

TaskListNode*
TaskListNode_new(Task* task)
{
  TaskListNode* tmp = calloc(1, sizeof(TaskListNode));
  assert(task != NULL);
  if (task == NULL) {
    return NULL;
  }
  assert(tmp != NULL);
  if (tmp == NULL) {
    return NULL;
  }
  tmp->task = task;

  return tmp;
}

/*
 * Function name: TaskListNode_free
 * Description: Frees the memory allocated for TaskListNode structure.
 * Arguments: node - pointer to pointer to TaskListNode structure
 */

void
TaskListNode_free(TaskListNode** node)
{
  assert(node != NULL);
  if (node == NULL) {
    return;
  }
  assert((*node) != NULL);
  if ((*node) == NULL) {
    return;
  }
  
  free((*node));
  (*node) = NULL;
}

/*
 * Function name: TaskListNode_set_next
 * Description: Sets the next pointer of the task list node.
 * Arguments: node - pointer to TaskListNode structure
 *            next - the new next pointer
 */

void
TaskListNode_set_next(TaskListNode* node, TaskListNode* next)
{
  assert(node != NULL);
  if (node == NULL) {
    return;
  }
  node->next = next;
}

/*
 * Function name: TaskListNode_set_previous
 * Description: Sets the previous pointer of the task list node.
 * Arguments: node - pointer to TaskListNode structure
 *            next - the new previous pointer
 */

void
TaskListNode_set_previous(TaskListNode* node, TaskListNode* previous)
{
  assert(node != NULL);
  if (node == NULL) {
    return;
  }
  node->previous = previous;
}

/*
 * Function name: TaskListNode_get_task
 * Description: Returns the task contained in this node.
 * Arguments: node - pointer to TaskListNode structure
 * Returns: The task contained in this node.
 */

Task*
TaskListNode_get_task(TaskListNode* node)
{
  assert(node != NULL);
  if (node == NULL) {
    return NULL;
  }
  return node->task;
}
