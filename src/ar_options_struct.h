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


#ifndef _JS_AR_OPTIONS_STRUCT_H
#define _JS_AR_OPTIONS_STRUCT_H

#define AR_OPTION_DISABLED 0
#define AR_OPTION_ENABLED 1

typedef struct {
  char* artries;
  int tries;
  char* ardelay;
  int delay;
  char start;
  char quit;
  char premature;
} ArOptions;

/* 'constructor' */
ArOptions* ArOptions_new();
/* 'destructor' */
void ArOptions_free(ArOptions** ao);
/* setters */
void ArOptions_set_arTries(ArOptions* ao, int tries);
void ArOptions_set_s_arTries(ArOptions* ao, char* tries);
void ArOptions_set_arDelay(ArOptions* ao, int delay);
void ArOptions_set_s_arDelay(ArOptions* ao, char* delay);
void ArOptions_set_arStart(ArOptions* ao, char start);
void ArOptions_set_arQuit(ArOptions* ao, char quit);
void ArOptions_set_arPremature(ArOptions* ao, char premature);
/* getters */
int ArOptions_get_arTries(ArOptions* ao);
int ArOptions_get_arDelay(ArOptions* ao);
char ArOptions_get_arStart(ArOptions* ao);
char ArOptions_get_arQuit(ArOptions* ao);
char ArOptions_get_arPremature(ArOptions* ao);
/* other */
void ArOptions_evaluate_values(ArOptions* ao);

#endif
