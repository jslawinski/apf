/*
 * active port forwarder - software for secure forwarding
 * Copyright (C) 2003 jeremian <jeremian@poczta.fm>
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
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>

static char verlev;
static char loglev;
static FILE* logfd;

char*
datum(void)
{
	time_t sec;
	struct tm* tm;
	static char timedat[20];
	time(&sec);
	tm = localtime(&sec);
	memset(timedat, 0, 20);
	strftime(timedat, 20, "%d.%m.%Y %H:%M:%S", tm);
	return timedat;
}

int
loginit(char verl, char logl, const char* logfname) {
	verlev = loglev = 0;
	if (logfd)
		fclose(logfd);
	logfd = NULL;
	verlev = verl;
	loglev = logl;
	if (loglev) {
		logfd = fopen(logfname, "a");
		if (logfd == NULL)
			return 1; /* logging to a non-opened file? */
	}
	return 0;
}

void
aflog(char type, const char* format, ...)
{
	va_list ap;
	va_start(ap, format);
	if (verlev)
		if (type <= verlev) {
			printf("[%s] ", datum());
			vfprintf(stdout, format, ap);
			printf("\n");
		}
	if (loglev)
		if (type <= loglev) {
			fprintf(logfd, "[%s] ", datum());
			vfprintf(logfd, format, ap);
			fprintf(logfd, "\n");
			fflush(logfd);
		}
	va_end(ap);
}
