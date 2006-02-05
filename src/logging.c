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

#include "logging.h"
#include "network.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>

static llnodeT* head = NULL;
static char verlev;
static char format[51] = "%Y-%m-%d %H:%M:%S";

/*
 * Function name: setdateformat
 * Description: Sets the new date format based on the given string.
 * Arguments: dateformat - the new date format
 */

void
setdateformat(char* dateformat)
{
  if (dateformat) {
    strncpy(format, dateformat, 50);
  }
}

/*
 * Function name: getdateformat
 * Description: Returns the date format.
 * Returns: The date format.
 */

char*
getdateformat()
{
  return format;
}

/*
 * Function name: localdate
 * Description: Returns the formatted date string.
 * Arguments: sec - the date in seconds
 * Returns: The formatted date.
 */

char*
localdate(time_t* sec)
{ 
  struct tm* tm;
  static char localdat[31];
  tm = localtime(sec);
  memset(localdat, 0, 31);
  strftime(localdat, 30, format, tm);
  return localdat;
}

/*
 * Function name: datum
 * Description: Returns the formatted date string.
 * Returns: The formatted date.
 */

char*
datum(void)
{
	time_t sec;
	struct tm* tm;
	static char timedat[31];
	time(&sec);
	tm = localtime(&sec);
	memset(timedat, 0, 31);
	strftime(timedat, 30, format, tm);
	return timedat;
}

/*
 * Function name: getloglisthead
 * Description: Returns the head of the log targets list.
 * Returns: The head of the log targets list.
 */

llnodeT*
getloglisthead()
{
  return head;
}

/*
 * Function name: checkmsgti
 * Description: Adds the given msgtype/importance to the log target.
 * Arguments: target - the log target
 *            tab - the name of the msttype/importance
 * Returns: 0 - success,
 *          1 - failure.
 */

int
checkmsgti(llnodeT* target, char* tab)
{
  if (strcmp(tab, "LOG_T_ALL") == 0) {
    target->msgtype |= LOG_T_ALL;
  }
  else if (strcmp(tab, "LOG_T_USER") == 0) {
    target->msgtype |= LOG_T_USER;
  }
  else if (strcmp(tab, "LOG_T_CLIENT") == 0) {
    target->msgtype |= LOG_T_CLIENT;
  }
  else if (strcmp(tab, "LOG_T_INIT") == 0) {
    target->msgtype |= LOG_T_INIT;
  }
  else if (strcmp(tab, "LOG_T_MANAGE") == 0) {
    target->msgtype |= LOG_T_MANAGE;
  }
  else if (strcmp(tab, "LOG_T_MAIN") == 0) {
    target->msgtype |= LOG_T_MAIN;
  }
  else if (strcmp(tab, "LOG_I_ALL") == 0) {
    target->importance |= LOG_I_ALL;
  }
  else if (strcmp(tab, "LOG_I_CRIT") == 0) {
    target->importance |= LOG_I_CRIT;
  }
  else if (strcmp(tab, "LOG_I_DEBUG") == 0) {
    target->importance |= LOG_I_DEBUG;
  }
  else if (strcmp(tab, "LOG_I_INFO") == 0) {
    target->importance |= LOG_I_INFO;
  }
  else if (strcmp(tab, "LOG_I_NOTICE") == 0) {
    target->importance |= LOG_I_NOTICE;
  }
  else if (strcmp(tab, "LOG_I_WARNING") == 0) {
    target->importance |= LOG_I_WARNING;
  }
  else if (strcmp(tab, "LOG_I_ERR") == 0) {
    target->importance |= LOG_I_ERR;
  }
  else {
    return 1; /* unknown msgtype/importance */
  }
  return 0;
}

/*
 * Function name: checklogtarget
 * Description: Parses the command line and sets all the options.
 * Arguments: target - the log target
 * Returns 0 - success,
 *         !0 - failure.
 */

int
checklogtarget(llnodeT* target)
{
  char* ptr;
  char desc[100];
  char type = 0;
  char tab[100];
  int tmpfd;
  int state, i;
  if ((target == NULL) || (target->cmdline == NULL)) {
    return 1; /* some of the important data is NULL */
  }
  state = 0; /* we are at the beginning of the cmdline */
  memset(tab, 0, 100);
  i = 0;
  ptr = target->cmdline;
  while ((*ptr) != 0) {
    switch (state) {
      /* beginning of the cmdline */
      case 0: {
                if ((*ptr) == ',') {
                  tab[i] = 0;
                  if (strcmp(tab, "file") == 0) {
                    type = LOG_L_FILE;
                  }
                  else if (strcmp(tab, "sock") == 0) {
                    type = LOG_L_SOCK;
                  }
                  else {
                    return 2; /* unknown type of the target */
                  }
                  state = 1; /* we are at the beginning of the file/sock description */
                  memset(tab, 0, 100);
                  memset(desc, 0, 100);
                  i = 0;
                  break;
                }
                if (i == 98) {
                  return 2; /* unknown type of the target (name too long) */
                }
                tab[i] = (*ptr);
                ++i;
                break;
              }
      /* beginning of the file/sock description */
      case 1: {
                if ((*ptr) == ',') {
                  tab[i] = 0;
                  switch (type) {
                    case LOG_L_FILE: {
                                       target->logfd = fopen(tab, "a");
                                       if (target->logfd == NULL) {
                                         return 4; /* logging to a non-opened file? */
                                       }
                                       state = 3; /* we want to read msgtype and importance */
                                       break;
                                     }
                    case LOG_L_SOCK: {
                                       strncpy(desc, tab, 99);
                                       state = 2; /* we want to open a socket (read port first) */
                                       break;
                                     }
                    default: {
                               return 2; /* unknown type of the target */
                             }
                  }
                  memset(tab, 0, 100);
                  i = 0;
                  break;
                }
                if (i == 98) {
                  return 3; /* wrong file/sock description (name too long) */
                }
                tab[i] = (*ptr);
                ++i;
                break;
              }
      /* beginning of the sock port description */
      case 2: {
                if ((*ptr) == ',') {
                  tab[i] = 0;
                  if (ip_connect(&tmpfd, desc, tab, 1, NULL, NULL)) {
                    return 5; /* can't connect to host:port */
                  }
                  target->logfd = fdopen(tmpfd, "a");
                  if (target->logfd == NULL) {
                    return 4; /* can't create FILE* to log to */
                  }
                  state = 3; /* we want to read msgtype and importance */
                  memset(tab, 0, 100);
                  i = 0;
                  break;
                }
                if (i == 98) {
                  return 3; /* wrong file/sock description (name too long) */
                }
                tab[i] = (*ptr);
                ++i;
                break;
              }
      /* beginning of the msgtype and importance section */
      case 3: {
                if ((*ptr) == ',') {
                  tab[i] = 0;
                  if (checkmsgti(target, tab)) {
                    return 6;
                  }
                  memset(tab, 0, 100);
                  i = 0;
                  break;
                }
                if (i == 98) {
                  return 6; /* wrong msgtype/importance description (name too long) */
                }
                tab[i] = (*ptr);
                ++i;
                break;
              }
    }
    ++ptr;
  }
  if (i != 0) {
    if (state == 3) {
      tab[i] = 0;
      if (checkmsgti(target, tab)) {
        return 6;
      }
    }
    else {
      return 1;
    }
  }
  return 0;
}

/*
 * Function name: addlogtarget
 * Description: Adds the new non-initialized log target with the specified command line.
 * Arguments: cmdline - the command line
 */

void
addlogtarget(char* cmdline)
{
  llnodeT* newnode = calloc(1, sizeof(llnodeT));
  newnode->cmdline = cmdline;
  newnode->next = head;
  head = newnode;
}

/*
 * Function name: loginit
 * Description: Initializes the logging system.
 * Arguments: verl - level of verbosity
 *            dateformat - date format
 * Returns: 0 - success,
 *          !0 - failure.
 */

int
loginit(char verl, char* dateformat)
{
  llnodeT* ptr;
  int n;
  
  verlev = 0;
  if (verl) {
    switch (verl) {
      case 1: {
                verlev = LOG_I_NOTICE | LOG_I_CRIT;
                break;
              }
      case 2: {
                verlev = LOG_I_INFO | LOG_I_NOTICE | LOG_I_CRIT;
                break;
              }
      case 3: {
                verlev = LOG_I_INFO | LOG_I_NOTICE | LOG_I_WARNING | LOG_I_CRIT;
                break;
              }
      case 4: {
                verlev = LOG_I_INFO | LOG_I_NOTICE | LOG_I_WARNING | LOG_I_ERR | LOG_I_CRIT;
                break;
              }
      case 5: {
                verlev = LOG_I_INFO | LOG_I_NOTICE | LOG_I_WARNING | LOG_I_ERR | LOG_I_CRIT | LOG_I_DEBUG;
                break;
              }
      default: {
                verlev = LOG_I_ALL;
                break;
              }
    }
  }

  setdateformat(dateformat);

  ptr = head;
  while (ptr) {
    if ((n = checklogtarget(ptr)) != 0) {
      return n;
    }
    ptr = ptr->next;
  }
  
	return 0;
}

/*
 * Function name: initializelogging
 * Description: The opaque function for loginit. If the logging initialization
 *              failed, it prints the appropriate message and exits.
 * Arguments: verl - level of verbosity
 *            dateformat - date format
 */

void
initializelogging(char verl, char* dateformat)
{
  int k;
  if ((k = loginit(verl, dateformat)) != 0) {
    switch (k) {
      /* wrong format of the logcmd */
      case 1: {
                printf("Wrong format of the logcmd\n");
                break;
              }
      /* unknown type of the logging target */
      case 2: {
                printf("Unknown type of the logging target\n");
                break;
              }
      /* wrong description of the logging target (name too long) */
      case 3: {
                printf("Wrong description of the logging target (name too long)\n");
                break;
              }
      /* can't open file to log to */
      case 4: {
                printf("Can't open file to log to\n");
                break;
              }
      /* can't connect to target host */
      case 5: {
                printf("Can't connect to target host\n");
                break;
              }
      /* wrong msgtype/importance description */
      case 6: {
                printf("Wrong msgtype/importance description\n");
                break;
              }
    }
    exit(1);
  }
}

/*
 * Function name: aflog
 * Description: Logs the given message.
 * Arguments: type - the type of the message
 *            importance - the importance of the message
 *            form - the format of the message
 *            ... - the additional arguments
 */

void
aflog(char type, char importance, const char* form, ...)
{
  llnodeT* ptr;
	va_list ap;

  if (verlev & importance) {
    if (format[0] != 0) {
      printf("[%s] ", datum());
    }
    va_start(ap, form);
    vfprintf(stdout, form, ap);
    va_end(ap);
    printf("\n");
  }
  
  ptr = head;
  while (ptr) {
		if ((type & ptr->msgtype) && (importance & ptr->importance)) {
      if (format[0] != 0) {
  			fprintf(ptr->logfd, "[%s] ", datum());
      }
    	va_start(ap, form);
			vfprintf(ptr->logfd, form, ap);
    	va_end(ap);
			fprintf(ptr->logfd, "\n");
			fflush(ptr->logfd);
		}
    ptr = ptr->next;
  }
}

