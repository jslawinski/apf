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

#include "timeval_functions.h"
#include "task_scheduler_struct.h"

/*
 * Function name: TaskScheduler_new
 * Description: Creates and initializes task scheduler.
 * Returns: Pointer to newly created TaskScheduler structure.
 */

TaskScheduler*
TaskScheduler_new()
{
  TaskScheduler* tmp = calloc(1, sizeof(TaskScheduler));
  assert(tmp != NULL);
  if (tmp == NULL) {
    return NULL;
  }

  return tmp;
}

/*
 * Function name: TaskScheduler_free
 * Description: Frees the memory allocated for TaskScheduler structure.
 * Arguments: scheduler - pointer to pointer to TaskScheduler structure
 */

void
TaskScheduler_free(TaskScheduler** scheduler)
{
  assert(scheduler != NULL);
  if (scheduler == NULL) {
    return;
  }
  assert((*scheduler) != NULL);
  if ((*scheduler) == NULL) {
    return;
  }

  while ((*scheduler)->head) {
    TaskScheduler_removeTask((*scheduler), TaskListNode_get_task((*scheduler)->head));
  }
  
  free((*scheduler));
  (*scheduler) = NULL;
}

/*
 * Function name: TaskScheduler_get_actualTimer
 * Description: Returns the smallest timeval structure in the scheduler.
 * Arguments: scheduler - pointer to TaskScheduler structure
 * Returns: The smallest timeval structure in the scheduler.
 */

struct timeval*
TaskScheduler_get_actualTimer(TaskScheduler* scheduler)
{
  assert(scheduler != NULL);
  if (scheduler == NULL) {
    return NULL;
  }
  return Task_get_timer(TaskListNode_get_task(scheduler->actualTask));
}

/*
 * Function name: TaskScheduler_hasMoreTasks
 * Description: Checks if there is more tasks in the scheduler.
 * Arguments: scheduler - pointer to TaskScheduler structure
 * Returns: 0 - there is no more tasks in the scheduler,
 *          n>0 - there is more (n) tasks in the scheduler.
 */

int
TaskScheduler_hasMoreTasks(TaskScheduler* scheduler)
{
  assert(scheduler != NULL);
  if (scheduler == NULL) {
    return 0;
  }
  return scheduler->numberOfTasks;
}

/*
 * Function name: TaskScheduler_addTask
 * Description: Adds the task to the scheduler.
 * Arguments: scheduler - pointer to TaskScheduler structure
 *            task - the task to add to the scheduler
 * Returns: 0 - the task has been added successfully,
 *          1 - the task has NOT been added.
 */

int
TaskScheduler_addTask(TaskScheduler* scheduler, Task* task)
{
  TaskListNode* tmp;
  assert(scheduler != NULL);
  if (scheduler == NULL) {
    return 1;
  }
  assert(task != NULL);
  if (task == NULL) {
    return 1;
  }
  tmp = TaskListNode_new(task);
  assert(tmp != NULL);
  if (tmp == NULL) {
    return 1;
  }
  if (scheduler->head) {
    TaskListNode_set_next(tmp, scheduler->head);
    TaskListNode_set_previous(scheduler->head, tmp);
  }
  scheduler->head = tmp;
  scheduler->numberOfTasks += 1;
  if (scheduler->actualTask) {
    if (timeval_compare(TaskScheduler_get_actualTimer(scheduler), Task_get_timer(task)) > 0) {
      scheduler->actualTask = tmp;
    }
  }
  else {
    scheduler->actualTask = tmp;
  }
  return 0;
}

/*
 * Function name: find_tasknode_with_minimal_timer
 * Description: Finds the task list node with minimal timer.
 * Arguments: scheduler - pointer to TaskScheduler structure
 * Returns: The task list node with minimal timer.
 */
static TaskListNode*
find_tasknode_with_minimal_timer(TaskScheduler* scheduler)
{
  TaskListNode* iterator;
  TaskListNode* candidate;
  assert(scheduler != NULL);
  if (scheduler == NULL) {
    return NULL;
  }
  if (scheduler->head == NULL) {
    return NULL;
  }
  candidate = scheduler->head;
  iterator = scheduler->head;
  iterator = iterator->next;
  while (iterator) {
    if (timeval_compare(Task_get_timer(TaskListNode_get_task(iterator)),
          Task_get_timer(TaskListNode_get_task(candidate))) == -1) {
      candidate = iterator;
    }
    iterator = iterator->next;
  }
  return candidate;
}

/*
 * Function name: TaskScheduler_removeTask
 * Description: Removes the task from the scheduler.
 * Arguments: scheduler - pointer to TaskScheduler structure
 *            task - the task to remove from the scheduler
 * Returns: 0 - the task has been removed successfully,
 *          1 - the task has NOT been removed (probably there was no such task in the scheduler).
 */

int
TaskScheduler_removeTask(TaskScheduler* scheduler, Task* task)
{
  TaskListNode* iterator;
  Task* tmp;
  assert(scheduler != NULL);
  if (scheduler == NULL) {
    return 1;
  }
  assert(task != NULL);
  if (task == NULL) {
    return 1;
  }
  iterator = scheduler->head;
  while (iterator) {
    tmp = TaskListNode_get_task(iterator);
    if (tmp == task) {
      if (iterator->previous) {
        TaskListNode_set_next(iterator->previous, iterator->next);
      }
      if (iterator->next) {
        TaskListNode_set_previous(iterator->next, iterator->previous);
      }
      if (iterator == scheduler->head) {
        scheduler->head = iterator->next;
      }
      if (iterator == scheduler->actualTask) {
        scheduler->actualTask = find_tasknode_with_minimal_timer(scheduler);
      }
      scheduler->numberOfTasks -= 1;
      TaskListNode_free(&iterator);
      return 0;
    }
    iterator = iterator->next;
  }
  return 1;
}

/*
 * Function name: TaskScheduler_startWatching
 * Description: Starts counting the time for the actual timer.
 * Arguments: scheduler - pointer to TaskScheduler structure
 * Returns: 0 - success,
 *          1 - failure.
 */

int
TaskScheduler_startWatching(TaskScheduler* scheduler)
{
  struct timeval* tmp;
  assert(scheduler != NULL);
  if (scheduler == NULL) {
    return 1;
  }
  tmp = TaskScheduler_get_actualTimer(scheduler);
  assert(tmp != NULL);
  if (tmp == NULL) {
    return 1;
  }
  scheduler->delta = *tmp;
  return 0;
}

/*
 * Function name: TaskScheduler_stopWatching
 * Description: Stops counting the time for the actual timer.
 *              Updates all the timers and destroys them if needed.
 * Arguments: scheduler - pointer to TaskScheduler structure
 * Returns: 0 - success,
 *          1 - failure.
 */

int
TaskScheduler_stopWatching(TaskScheduler* scheduler)
{
  TaskListNode* iterator;
  TaskListNode* actualTask;
  Task* backup;
  struct timeval* tmp;
  int result;
  assert(scheduler != NULL);
  if (scheduler == NULL) {
    return 1;
  }
  tmp = TaskScheduler_get_actualTimer(scheduler);
  assert(tmp != NULL);
  if (tmp == NULL) {
    return 1;
  }
  if (timeval_subtract(&(scheduler->delta), tmp)) {
    return 1;
  }
  actualTask = scheduler->actualTask;
  assert(scheduler->actualTask != NULL);
  iterator = scheduler->head;
  while (iterator) {
    if (iterator != actualTask) {
      result = timeval_subtract(Task_get_timer(TaskListNode_get_task(iterator)), &(scheduler->delta));
      assert(result == 0);
    }
    if (timeval_lq_zero(Task_get_timer(TaskListNode_get_task(iterator)))) {
      Task_exec(TaskListNode_get_task(iterator));
      backup = TaskListNode_get_task(iterator);
      iterator = iterator->next;
      TaskScheduler_removeTask(scheduler, backup);
      continue;
    }
    iterator = iterator->next;
  }
  TaskScheduler_update(scheduler);
  return 0;
}

/*
 * Function name: TaskScheduler_update
 * Description: Updates the actual timer.
 * Arguments: scheduler - pointer to TaskScheduler structure
 * Returns: 0 - success,
 *          1 - failure.
 */

int
TaskScheduler_update(TaskScheduler* scheduler)
{
  assert(scheduler != NULL);
  if (scheduler == NULL) {
    return 1;
  }
  scheduler->actualTask = find_tasknode_with_minimal_timer(scheduler);
  return 0;
}
