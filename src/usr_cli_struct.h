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


#ifndef _JS_USR_CLI_STRUCT_H
#define _JS_USR_CLI_STRUCT_H

typedef struct {
  char* listenHostName;
  char* manageHostName;
  char* listenPortName;
  char* managePortName;
  int listenFd;
  int manageFd;
} UsrCli;

/* 'constructor' */
UsrCli* UsrCli_new();
/* 'destructor' */
void UsrCli_free(UsrCli** uc);
/* setters */
void UsrCli_set_listenPortName(UsrCli* uc, char* listenPortName);
void UsrCli_set_managePortName(UsrCli* uc, char* managePortName);
void UsrCli_set_listenFd(UsrCli* uc, int listenFd);
void UsrCli_set_manageFd(UsrCli* uc, int manageFd);
/* getters */
char* UsrCli_get_listenPortName(UsrCli* uc);
char* UsrCli_get_managePortName(UsrCli* uc);
int UsrCli_get_listenFd(UsrCli* uc);
int UsrCli_get_manageFd(UsrCli* uc);
char* UsrCli_get_listenHostName(UsrCli* uc);
char* UsrCli_get_manageHostName(UsrCli* uc);

#endif
