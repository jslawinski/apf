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

#include "timeval_functions.h"

/*
 * Function name: timeval_create
 * Description: Initialize and return timeval structure.
 * Arguments: tv_sec - seconds
 *            tv_usec - microseconds
 * Returns: Initialized timeval structure.
 */

struct timeval
timeval_create(long tv_sec, long tv_usec)
{
  struct timeval tmp;
  tmp.tv_sec = tv_sec;
  tmp.tv_usec = tv_usec;
  return tmp;
}

/*
 * Function name: timeval_compare
 * Description: Compares two pointers to timeval structures.
 * Arguments: first - the first timeval structure to compare
 *            second - the second timeval structure to compare
 * Returns: -1 - the second structure is bigger
 *           0 - structures are equals
 *           1 - the first structure is bigger
 */

int
timeval_compare(struct timeval* first, struct timeval* second)
{
  if (first == NULL) {
    if (second == NULL) {
      return 0;
    }
    else {
      return -1;
    }
  }
  if (second == NULL) {
    return 1;
  }
  if (first->tv_sec < second->tv_sec) {
    return -1;
  }
  if (first->tv_sec > second->tv_sec) {
    return 1;
  }
  if (first->tv_usec < second->tv_usec) {
    return -1;
  }
  if (first->tv_usec > second->tv_usec) {
    return 1;
  }
  return 0;
}

/*
 * Function name: timeval_subtract
 * Description: Substracts second timeval structure from the first, updating the latter one.
 * Arguments: first - the first timeval structure to subtract operation
 *            second - the second timeval structure to subtract operation
 * Returns: 0 - success,
 *          1 - failure.
 */

int
timeval_subtract(struct timeval* first, struct timeval* second)
{
  assert(first != NULL);
  assert(second != NULL);
  if ((first == NULL) || (second == NULL)) {
    return 1;
  }
  if (first->tv_usec < second->tv_usec) {
    first->tv_sec -= 1;
    first->tv_usec = 1000000 - second->tv_usec + first->tv_usec;
  }
  else {
    first->tv_usec -= second->tv_usec;
  }
  first->tv_sec -= second->tv_sec;
  return 0;
}

/*
 * Function name: timeval_lq_zero
 * Description: Checks if the timer is less or equiv zero.
 * Arguments: timer - the timeval structure to check
 * Returns: 1 - the timer is less or equiv zero,
 *          0 - the timer is bigger than zero.
 */

int
timeval_lq_zero(struct timeval* timer)
{
  assert(timer != NULL);
  if (timer == NULL) {
    return 0;
  }
  if (timer->tv_sec < 0) {
    return 1;
  }
  if ((timer->tv_sec == 0) && (timer->tv_usec == 0)) {
    return 1;
  }
  return 0;
}
