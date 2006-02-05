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

#include "stats.h"

static signed long compressgained;

/*
 * Function name: timeperiod
 * Description: Returns the formatted time period string.
 * Arguments: period - the time period
 * Returns: The formatted time period string.
 */

char*
timeperiod(time_t period)
{
  int hours, minutes, seconds;
  static char timeper[41];
  memset(timeper, 0, 41);

  hours = period/3600;
  minutes = (period/60)%60;
  seconds = period%60;

  if (hours) {
    sprintf(timeper, "%d:%02d:%02d", hours, minutes, seconds);
  }
  else {
    sprintf(timeper, "%d:%02d", minutes, seconds);
  }
  return timeper;
}

/*
 * Function name: addtocg
 * Description: Adds the given number to the bytes gained by the use of compression.
 * Arguments: amount - the number to add
 */

void
addtocg(int amount)
{
	compressgained += amount;
}

/*
 * Function name: getcg
 * Description: Returns the number of bytes gained by the use of compression.
 * Returns: The number of bytes gained by the use of compression.
 */

signed long
getcg(void)
{
	return compressgained;
}

/*
 * Function name: resetcg
 * Description: Resets the counter of bytes gained by the use of compression.
 */

void
resetcg(void)
{
	compressgained = 0;
}
