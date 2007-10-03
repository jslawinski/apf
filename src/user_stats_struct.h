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


#ifndef _JS_USER_STATS_STRUCT_H
#define _JS_USER_STATS_STRUCT_H

#include <sys/types.h>

typedef struct {
  time_t lastActivity;
  time_t lastUSQChange;
  time_t lastDSQChange;
  int totalDownloadedBytes;
  int totalUploadedBytes;
  int uploadSQP;
  int uploadSpeedQueue[3];
  int downloadSQP;
  int downloadSpeedQueue[3];
} UserStats;

/* 'constructor' */
UserStats* UserStats_new();
/* 'destructor' */
void UserStats_free(UserStats** us);
/* setters */
void UserStats_set_lastActivity(UserStats* us, time_t lastActivity);
void UserStats_set_totalDownloadedBytes(UserStats* us, int totalDownloadedBytes);
void UserStats_set_totalUploadedBytes(UserStats* us, int totalUploadedBytes);
/* getters */
time_t UserStats_get_lastActivity(UserStats* us);
int UserStats_get_totalDownloadedBytes(UserStats* us);
int UserStats_get_totalUploadedBytes(UserStats* us);
/* other methods */
void UserStats_add_download(UserStats* us, int bytes);
void UserStats_add_upload(UserStats* us, int bytes);
double UserStats_get_downloadSpeed(UserStats* us);
double UserStats_get_uploadSpeed(UserStats* us);
/* other */
void UserStats_clear(UserStats* us);

#endif
