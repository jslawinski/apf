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

#include "task_struct.h"

/*
 * Function name: Task_new
 * Description: Creates and initializes new task. User is responsible for
 *              allocating/freeing memory pointed by the pointers.
 * Arguments: timerp - pointer to timeval structure used to counte time (required)
 *            function - pointer to function executed when the time is out (optional)
 *            data - pointer to data passed to function executed when the time is out (optional)
 *            clean - pointer to function that frees the data
 * Returns: Pointer to newly created Task structure.
 */

Task*
Task_new(struct timeval* timerp, void (*function)(void*), void* data, void (*clean)(void**))
{
  Task* tmp;
  assert(timerp != NULL);
  if (timerp == NULL) {
    return NULL;
  }
  tmp = calloc(1, sizeof(Task));
  assert(tmp != NULL);
  if (tmp == NULL) {
    return NULL;
  }
  tmp->timerp = timerp;
  tmp->function = function;
  tmp->data = data;
  tmp->clean = clean;

  return tmp;
}

/*
 * Function name: Task_free
 * Description: Frees the memory allocated for Task structure. User has to free the memory at the
 *              pointers by his own.
 * Arguments: task - pointer to pointer to Task structure
 */

void
Task_free(Task** task)
{
  assert(task != NULL);
  if (task == NULL) {
    return;
  }
  assert((*task) != NULL);
  if ((*task) == NULL) {
    return;
  }

  if ((*task)->clean) {
    if ((*task)->data) {
      (*task)->clean(&((*task)->data));
    }
  }
  
  free((*task));
  (*task) = NULL;
}

/*
 * Function name: Task_get_timer
 * Description: Returns the timer of the task.
 * Arguments: task - pointer to Task structure
 * Returns: The timer of the task.
 */

struct timeval*
Task_get_timer(Task* task)
{
  assert(task != NULL);
  if (task == NULL) {
    return NULL;
  }
  return task->timerp;
}

/*
 * Function name: Task_exec
 * Description: Executes the function encapsulated in the task.
 * Arguments: task - pointer to Task structure
 */

void
Task_exec(Task* task)
{
  assert(task != NULL);
  if (task == NULL) {
    return;
  }
  if (task->function) {
    task->function(task->data);
  }
}
