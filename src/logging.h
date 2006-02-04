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

#include <stdio.h>
#include <time.h>

#ifndef _JS_LOGGING_H
#define _JS_LOGGING_H

/* some constants for logging functions */
   /* type of the message */

#define LOG_T_ALL     (LOG_T_USER | LOG_T_CLIENT | LOG_T_INIT | LOG_T_MANAGE | LOG_T_MAIN)
#define LOG_T_USER    1
#define LOG_T_CLIENT  2
#define LOG_T_INIT    4
#define LOG_T_MANAGE  8
#define LOG_T_MAIN    16

   /* importance of the message */

#define LOG_I_ALL     (LOG_I_CRIT | LOG_I_DEBUG | LOG_I_DDEBUG | LOG_I_INFO | LOG_I_NOTICE | LOG_I_WARNING | LOG_I_ERR)
#define LOG_I_CRIT    1
#define LOG_I_DEBUG   2
#define LOG_I_DDEBUG  4
#define LOG_I_INFO    8
#define LOG_I_NOTICE  16
#define LOG_I_WARNING 32
#define LOG_I_ERR     64

   /* type of the logging target */

#define LOG_L_FILE    1
#define LOG_L_SOCK    2

/* a structure that keeps information about logging target */
typedef struct llnode {
  char* cmdline;
  char msgtype;
  char importance;
  FILE* logfd;
  struct llnode* next;
} llnodeT;

  /* set dateformat */
void setdateformat(char* dateformat);
  /* get dateformat */
char* getdateformat();
  /* get llnodeT head */
llnodeT* getloglisthead();
  /* add logging target */
void addlogtarget(char* cmdline);
  /* initialize logging routine */
void initializelogging(char verlev, char* dateformat);
  /* log to a file or|and screen */
void aflog(char type, char importance, const char* format, ...); 
  /* get text representation of the date */
char* localdate(time_t* sec);

#endif

