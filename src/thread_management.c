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

#include "thread_management.h"

#ifdef HAVE_LIBPTHREAD

static pthread_t mainthread;
static pthread_mutex_t mainmutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t maincond = PTHREAD_COND_INITIALIZER;

/*
 * Function name: remember_mainthread
 * Description: Remembers the current thread as a main thread.
 */

void
remember_mainthread(void)
{
  mainthread = pthread_self();
}

/*
 * Function name: is_this_a_mainthread
 * Description: Checks, if the current thread is a main thread.
 * Returns: 0 - this is not a main thread,
 *          1 - this is a main thread.
 */

int
is_this_a_mainthread(void)
{
  if (pthread_self() == mainthread) {
    return 1;
  }
  return 0;
}

/*
 * Function name: start_critical_section
 * Description: Starts the critical section of the code by locking the mutex.
 */

void
start_critical_section(void)
{
  pthread_mutex_lock( &mainmutex);
}

/*
 * Function name: end_critical_section
 * Description: Ends the critical section of the code by unlocking the mutex.
 */

void
end_critical_section(void)
{
  pthread_mutex_unlock( &mainmutex);
}

/*
 * Function name: wait_for_condition
 * Description: Starts waiting for the condition.
 */

void
wait_for_condition(void)
{
  pthread_cond_wait(&maincond, &mainmutex);
}

/*
 * Function name: broadcast_condition
 * Description: Broadcast the met of the condition.
 */

void
broadcast_condition(void)
{
  pthread_cond_broadcast(&maincond);
}

#endif
