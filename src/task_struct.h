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

#ifndef _JS_TASK_STRUCT_H
#define _JS_TASK_STRUCT_H

typedef struct {
  struct timeval* timerp;
  void (*function)(void*);
  void* data;
  void (*clean)(void**);
} Task;

/* 'constructor' */
Task* Task_new(struct timeval*, void (*function)(void*), void*, void (*clean)(void**));
/* 'destructor' */
void Task_free(Task** task);
/* getters */
struct timeval* Task_get_timer(Task* task);
void Task_exec(Task* task);

#endif
