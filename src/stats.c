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

#include "stats.h"
#include "network.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>

static char verlev;
static char loglev;
static char logsocklev;
static FILE* logfd;
static FILE* logsockfd;
static signed long compressgained;
static char* format = "%d.%m.%Y %H:%M:%S";

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

int
loginit(char verl, char logl, char logsl, const char* logfname, const char* port, char* dateformat) {
  int tmpfd;
	verlev = loglev = 0;
	if (logfd)
		fclose(logfd);
	logfd = NULL;
  logsockfd = NULL;
	verlev = verl;
	loglev = logl;
  logsocklev = logsl;
  if (dateformat)
    format = dateformat;
	if (loglev) {
		logfd = fopen(logfname, "a");
		if (logfd == NULL)
			return 1; /* logging to a non-opened file? */
	}
  if (logsocklev) {
    if (ip_connect(&tmpfd, "localhost", port, 1))
      return 2; /* can't connect to localhost:port */
    logsockfd = fdopen(tmpfd, "a");
    if (logsockfd == NULL)
      return 3; /* can't create FILE* to log to */
  }
	return 0;
}

void
aflog(char type, const char* format, ...)
{
	va_list ap;
  
	if ((verlev) || (!type))
		if (type <= verlev) {
			printf("[%s] ", datum());
    	va_start(ap, format);
			vfprintf(stdout, format, ap);
    	va_end(ap);
			printf("\n");
		}
	if (loglev)
		if (type <= loglev) {
			fprintf(logfd, "[%s] ", datum());
    	va_start(ap, format);
			vfprintf(logfd, format, ap);
    	va_end(ap);
			fprintf(logfd, "\n");
			fflush(logfd);
		}
	if (logsocklev)
		if (type <= logsocklev) {
			fprintf(logsockfd, "[%s] ", datum());
    	va_start(ap, format);
			vfprintf(logsockfd, format, ap);
    	va_end(ap);
			fprintf(logsockfd, "\n");
			fflush(logsockfd);
		}

}

void
addtocg(int amount)
{
	compressgained += amount;
}

signed long
getcg(void)
{
	return compressgained;
}

void
resetcg(void)
{
	compressgained = 0;
}
