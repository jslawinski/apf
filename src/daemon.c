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

#include "daemon.h"

#ifndef HAVE_DAEMON

#ifndef HAVE_THIS_DAEMON
#define HAVE_THIS_DAEMON

/*
 * Function name: daemon
 * Description: Enters into daemon mode. It's the emulation of the daemon
 *              function from the system.
 * Arguments: nochdir - when 0, the directory will be changed to /, otherwise
 *                      the directory will be unchanged
 *            noclose - when 0, the standard streams will be closed, otherwise
 *                      the streams will be unchanged
 * Returns: 0 - success,
 *          -1 - failure.
 */

int
daemon(int nochdir, int noclose)
{
  int retval;
  if ((retval = fork()) == 0) {
    /* child process */
    setsid();
    if (nochdir == 0) {
      chdir("/");
    }
    if (noclose == 0) {
      retval = open("/dev/null", O_RDWR);
      if (retval == -1) {
        return retval;
      }
      dup2(retval, STDIN_FILENO);
      dup2(retval, STDOUT_FILENO);
      dup2(retval, STDERR_FILENO);
      close(retval);
    }
  }
  else {
    /* parent process */
    if (retval == -1) {
      return retval;
    }
    _exit(0);
  }
  return 0;
}

#endif

#endif
