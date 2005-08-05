/*
 * active port forwarder - software for secure forwarding
 * Copyright (C) 2003,2004,2005 jeremian <jeremian [at] poczta.fm>
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
#include <time.h>

#include "user_stats_struct.h"

/*
 * Function name: UserStats_new
 * Descriotion: Create and initialize new UserStats structure.
 * Returns: Pointer to newly created UserStats structure.
 */

UserStats*
UserStats_new()
{
  UserStats* tmp = calloc(1, sizeof(UserStats));
  if (tmp == NULL) {
    return NULL;
  }
  return tmp;
}

/*
 * Function name: UserStats_free
 * Description: Free the memory allocated for UserStats structure.
 * Arguments: us - pointer to pointer to UserStats structure
 */

void
UserStats_free(UserStats** us)
{
  if (us == NULL) {
    return;
  }
  if ((*us) == NULL) {
    return;
  }
  free((*us));
  (*us) = NULL;
}

/*
 * Function name: UserStats_set_lastActivity
 * Description: Set time of the last user activity (upload or download).
 * Arguments: us - pointer to UserStats structure
 *            lastActivity - time of the last user activity
 */

void
UserStats_set_lastActivity(UserStats* us, time_t lastActivity)
{
  if (us == NULL) {
    return;
  }
  us->lastActivity = lastActivity;
}

/*
 * Function name: UserStats_set_totalDownloadedBytes
 * Description: Set total amount of downloaded bytes by the user.
 * Arguments: us - pointer to UserStats structure
 *            totalDownloadedBytes - total amount of downloaded bytes by the user
 */

void
UserStats_set_totalDownloadedBytes(UserStats* us, int totalDownloadedBytes)
{
  if (us == NULL) {
    return;
  }
  us->totalDownloadedBytes = totalDownloadedBytes;
}

/*
 * Function name: UserStats_set_totalUploadedBytes
 * Description: Set total amount of uploaded byte by the user.
 * Arguments: us - pointer to UserStats structure
 *            totalUploadedBytes - total amount of uploaded bytes by the user
 */

void
UserStats_set_totalUploadedBytes(UserStats* us, int totalUploadedBytes)
{
  if (us == NULL) {
    return;
  }
  us->totalUploadedBytes = totalUploadedBytes;
}

/*
 * Function name: UserStats_get_lastActivity
 * Description: Get time of the last user activity (upload or download).
 * Arguments: us - pointer to UserStats structure
 * Returns: Time of the last user activity.
 */

time_t
UserStats_get_lastActivity(UserStats* us)
{
  if (us == NULL) {
    return 0;
  }
  return us->lastActivity;
}

/*
 * Function name: UserStats_get_totalDownloadedBytes
 * Description: Get total amount of downloaded bytes by the user.
 * Arguments: us - pointer to UserStats structure
 * Returns: Total amount of downloaded bytes by the user.
 */

int
UserStats_get_totalDownloadedBytes(UserStats* us)
{
  if (us == NULL) {
    return 0;
  }
  return us->totalDownloadedBytes;
}

/*
 * Function name: UserStats_get_totalUploadedBytes
 * Description: Get total amount of uploaded bytes by the user.
 * Arguments: us - pointer to UserStats structure
 * Returns: Total amount of uploaded bytes by the user.
 */

int
UserStats_get_totalUploadedBytes(UserStats* us)
{
  if (us == NULL) {
    return 0;
  }
  return us->totalUploadedBytes;
}

/*
 * Function name: UserStats_add_download
 * Description: Add bytes to the totalDownloadedBytes, update the lastActivity
 *              and downloadSpeed.
 * Arguments: us - pointer to UserStats structure
 *            bytes - amount of bytes to add
 */

void
UserStats_add_download(UserStats* us, int bytes)
{
  time_t now;
  if (us == NULL) {
    return;
  }
  
  /* get the current time */
  time(&now);
  
  /* update counters */
  switch (now - us->lastDSQChange) {
    case 0: {
      us->downloadSpeedQueue[us->downloadSQP] += bytes;
      break;
    }
    case 2: {
      us->downloadSQP = (us->downloadSQP + 1) % 3;
      us->downloadSpeedQueue[us->downloadSQP] = 0;
    }
    case 1: {
      us->downloadSQP = (us->downloadSQP + 1) % 3;
      us->downloadSpeedQueue[us->downloadSQP] = bytes;
      break;
    }
    default: {
      us->downloadSpeedQueue[0] = us->downloadSpeedQueue[1] = us->downloadSpeedQueue[2] = 0;
      us->downloadSpeedQueue[us->downloadSQP] = bytes;
    }
  }
  
  /* update total upload */
  us->totalDownloadedBytes += bytes;
  
  /* update last activity */
  us->lastActivity = now;
  
  /* update last speed queue change */
  us->lastDSQChange = now;
}

/*
 * Function name: UserStats_add_upload
 * Description: Add bytes to the totalUploadedBytes, update the lastActivity
 *              and uploadSpeed.
 * Arguments: us - pointer to UserStats structure
 *            bytes - amount of bytes to add
 */

void
UserStats_add_upload(UserStats* us, int bytes)
{
  time_t now;
  if (us == NULL) {
    return;
  }
  
  /* get the current time */
  time(&now);
  
  /* update counters */
  switch (now - us->lastUSQChange) {
    case 0: {
      us->uploadSpeedQueue[us->uploadSQP] += bytes;
      break;
    }
    case 2: {
      us->uploadSQP = (us->uploadSQP + 1) % 3;
      us->uploadSpeedQueue[us->uploadSQP] = 0;
    }
    case 1: {
      us->uploadSQP = (us->uploadSQP + 1) % 3;
      us->uploadSpeedQueue[us->uploadSQP] = bytes;
      break;
    }
    default: {
      us->uploadSpeedQueue[0] = us->uploadSpeedQueue[1] = us->uploadSpeedQueue[2] = 0;
      us->uploadSpeedQueue[us->uploadSQP] = bytes;
    }
  }
  
  /* update total upload */
  us->totalUploadedBytes += bytes;
  
  /* update last activity */
  us->lastActivity = now;
  
  /* update last speed queue change */
  us->lastUSQChange = now;
}

/*
 * Function name: UserStats_get_downloadSpeed
 * Description: Get the average download speed from the last three seconds.
 * Arguments: us - pointer to UserStats structure
 * Returns: The average download speed from the last three seconds.
 */

double
UserStats_get_downloadSpeed(UserStats* us)
{
  time_t now;
  if (us == NULL) {
    return 0.0;
  }
  
  /* get the current time */
  time(&now);
  
  /* update pointer */
  switch (now - us->lastDSQChange) {
    case 0: {
      break;
    }
    case 2: {
      us->downloadSQP = (us->downloadSQP + 1) % 3;
      us->downloadSpeedQueue[us->downloadSQP] = 0;
    }
    case 1: {
      us->downloadSQP = (us->downloadSQP + 1) % 3;
      us->downloadSpeedQueue[us->downloadSQP] = 0;
      break;
    }
    default: {
      us->downloadSpeedQueue[0] = us->downloadSpeedQueue[1] = us->downloadSpeedQueue[2] = 0;
    }
  }
  
  /* update last speed queue change */
  us->lastDSQChange = now;
  
  /* return current download speed */
  return (((double)(us->downloadSpeedQueue[0] + us->downloadSpeedQueue[1] + us->downloadSpeedQueue[2])) / 3.0);
}

/*
 * Function name: UserStats_get_uploadSpeed
 * Description: Get the average upload speed from the last three seconds.
 * Arguments: us - pointer to UserStats structure
 * Returns: The average upload speed from the last three seconds.
 */

double
UserStats_get_uploadSpeed(UserStats* us)
{
  time_t now;
  if (us == NULL) {
    return 0.0;
  }
  
  /* get the current time */
  time(&now);
  
  /* update pointer */
  switch (now - us->lastUSQChange) {
    case 0: {
      break;
    }
    case 2: {
      us->uploadSQP = (us->uploadSQP + 1) % 3;
      us->uploadSpeedQueue[us->uploadSQP] = 0;
    }
    case 1: {
      us->uploadSQP = (us->uploadSQP + 1) % 3;
      us->uploadSpeedQueue[us->uploadSQP] = 0;
      break;
    }
    default: {
      us->uploadSpeedQueue[0] = us->uploadSpeedQueue[1] = us->uploadSpeedQueue[2] = 0;
    }
  }
  
  /* update last speed queue change */
  us->lastUSQChange = now;
  
  /* return current download speed */
  return (((double)(us->uploadSpeedQueue[0] + us->uploadSpeedQueue[1] + us->uploadSpeedQueue[2])) / 3.0);
}

/*
 * Function name: UserStats_clear
 * Description: Clear the UserStats structure. Set all variables to default values.
 * Arguments: us - pointer to UserStats structure
 */

void
UserStats_clear(UserStats* us)
{
  if (us == NULL) {
    return;
  }
  us->lastActivity = 0;
  us->lastUSQChange = 0;
  us->lastDSQChange = 0;
  us->totalDownloadedBytes = 0;
  us->totalUploadedBytes = 0;
  us->uploadSQP = 0;
  us->uploadSpeedQueue[0] = us->uploadSpeedQueue[1] = us->uploadSpeedQueue[2] = 0;
  us->downloadSQP = 0;
  us->downloadSpeedQueue[0] = us->downloadSpeedQueue[1] = us->downloadSpeedQueue[2] = 0;
}
