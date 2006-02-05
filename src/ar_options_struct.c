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

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ar_options_struct.h"
#include "string_functions.h"
#include "server_check.h"

/*
 * Function name: ArOptions_new
 * Description: Create and initialize new ArOptions structure.
 * Returns: Pointer to newly created ArOptions structure.
 */

ArOptions*
ArOptions_new()
{
  ArOptions* tmp = calloc(1, sizeof(ArOptions));
  assert(tmp != NULL);
  if (tmp == NULL) {
    return NULL;
  }
  tmp->premature = AR_OPTION_ENABLED;
  tmp->delay = 5;
  tmp->tries = -1;
  return tmp;
}

/*
 * Function name: ArOptions_free
 * Description: Free the memory allocated for ArOptions structure.
 * Arguments: ao - pointer to pointer to ArOptions structure
 */

void
ArOptions_free(ArOptions** ao)
{
  assert(ao != NULL);
  if (ao == NULL) {
    return;
  }
  assert((*ao) != NULL);
  if ((*ao) == NULL) {
    return;
  }
  if ((*ao)->artries) {
    free((*ao)->artries);
    (*ao)->artries = NULL;
  }
  if ((*ao)->ardelay) {
    free((*ao)->ardelay);
    (*ao)->ardelay = NULL;
  }
  free((*ao));
  (*ao) = NULL;
}

/*
 * Function name: ArOptions_set_asTries
 * Description: Set how many times afclient will try to reconnect.
 * Arguments: ao - pointer to ArOptions structure
 *            tries - how many times afclient will try to reconnect
 *                    <0 - unlimited
 *                    0 - disabled
 *                    >0 - exact number
 */

void
ArOptions_set_arTries(ArOptions* ao, int tries)
{
  assert(ao != NULL);
  if (ao == NULL) {
    return;
  }
  ao->tries = tries;
}

/*
 * Function name: ArOptions_set_s_arTries
 * Description: Set string describing how many times afclient will try to reconnect.
 *              This string has to be evaluated later in order to really set arTries value.
 * Arguments: ao - pointer to ArOptions structure
 *            tries - string describing how many times afclient will try to reconnect.
 */

void
ArOptions_set_s_arTries(ArOptions* ao, char* tries)
{
  assert(ao != NULL);
  if (ao == NULL) {
    return;
  }
  string_cp(&(ao->artries), tries);
}

/*
 * Function name: ArOptions_set_arDelay
 * Description: Set how long afclient will wait between reconnect tries.
 * Arguments: ao - pointer to ArOptions structure
 *            delay - how long afclient will wait between reconnect tries
 */

void
ArOptions_set_arDelay(ArOptions* ao, int delay)
{
  assert(ao != NULL);
  if (ao == NULL) {
    return;
  }
  ao->delay = delay;
}

/*
 * Function name: ArOptions_set_s_arDelay
 * Description: Set string describing how long afclient will wait between reconnect tries.
 *              This string has to be evaluated later in order to really set arDelay value.
 * Arguments: ao - pointer to ArOptions structure
 *            delay - string describing how long afclient will wait between reconnect tries.
 */

void
ArOptions_set_s_arDelay(ArOptions* ao, char* delay)
{
  assert(ao != NULL);
  if (ao == NULL) {
    return;
  }
  string_cp(&(ao->ardelay), delay);
}

/*
 * Function name: ArOptions_set_arStart
 * Description: Enable/disable auto-reconnection when afserver is not reachable on start.
 * Arguments: ao - pointer to ArOptions structure
 *            start - value which enable (AR_OPTION_ENABLED) or disable (AR_OPTION_DISABLED)
 *                    auto-reconnection when afserver is not reachable on start
 */

void
ArOptions_set_arStart(ArOptions* ao, char start)
{
  assert(ao != NULL);
  if (ao == NULL) {
    return;
  }
  ao->start = start;
}

/*
 * Function name: ArOptions_set_arQuit
 * Description: Enable/disable auto-reconnection after normal afserver quit.
 * Arguments: ao - pointer to ArOptions structure
 *            quit - value which enable (AR_OPTION_ENABLED) or disable (AR_OPTION_DISABLED)
 *                   auto-reconnection after normal afserver quit
 */

void
ArOptions_set_arQuit(ArOptions* ao, char quit)
{
  assert(ao != NULL);
  if (ao == NULL) {
    return;
  }
  ao->quit = quit;
}

/*
 * Function name: ArOptions_set_arPremature
 * Description: Enable/disable auto-reconnection after premature afserver quit.
 * Arguments: ao - pointer to ArOptions structure
 *            premature - value which enable (AR_OPTION_ENABLED) or disable (AR_OPTION_DISABLED)
 *                        auto-reconnection after premature afserver quit
 */

void
ArOptions_set_arPremature(ArOptions* ao, char premature)
{
  assert(ao != NULL);
  if (ao == NULL) {
    return;
  }
  ao->premature = premature;
}

/*
 * Function name: ArOptions_get_arTries
 * Description: Get how many times afclient will try to reconnect.
 * Arguments: ao - pointer to ArOptions structure
 * Returns: How many times afclient will try to reconnect.
 */

int
ArOptions_get_arTries(ArOptions* ao)
{
  assert(ao != NULL);
  if (ao == NULL) {
    return 0;
  }
  return ao->tries;
}

/*
 * Function name: ArOptions_get_arDelay
 * Description: Get how long afclient will wait between reconnect tries.
 * Arguments: ao - pointer to ArOptions structure
 * Returns: How long afclient will wait between reconnect time.
 */

int
ArOptions_get_arDelay(ArOptions* ao)
{
  assert(ao != NULL);
  if (ao == NULL) {
    return 0;
  }
  return ao->delay;
}

/*
 * Function name: ArOptions_get_arStart
 * Description: Get status of the auto-reconnection when afserver is not reachable on start.
 * Arguments: ao - pointer to ArOptions structure
 * Returns: Status of the auto-reconnection when afserver is not reachable on start.
 */

char
ArOptions_get_arStart(ArOptions* ao)
{
  assert(ao != NULL);
  if (ao == NULL) {
    return AR_OPTION_DISABLED;
  }
  return ao->start;
}

/*
 * Function name: ArOptions_get_arQuit
 * Description: Get status of the auto-reconnection after normal afserver quit.
 * Arguments: ao - pointer to ArOptions structure
 * Returns: Status of the auto-reconnection after normal afserver quit.
 */

char
ArOptions_get_arQuit(ArOptions* ao)
{
  assert(ao != NULL);
  if (ao == NULL) {
    return AR_OPTION_DISABLED;
  }
  return ao->quit;
}

/*
 * Function name: ArOptions_get_arPremature
 * Description: Get status of the auto-reconnection after premature afserver quit.
 * Arguments: ao - pointer to ArOptions structure
 * Returns: Status of the auto-reconnection after premature afserver quit.
 */

char
ArOptions_get_arPremature(ArOptions* ao)
{
  assert(ao != NULL);
  if (ao == NULL) {
    return AR_OPTION_DISABLED;
  }
  return ao->premature;
}

/*
 * Function name: ArOptions_evaluate_values
 * Description: Evaluate arTries and arDelay values. These values are checked, when are not NULL.
 *              arTries have to be an integer, arDelay have to be an integer >0. If any of the
 *              variables is wrong, program terminates abnormally.
 * Arguments: ao - pointer to ArOptions structure
 */

void
ArOptions_evaluate_values(ArOptions* ao)
{
  assert(ao != NULL);
  if (ao == NULL) {
    return;
  }
  if (ao->artries) {
    ao->tries = check_value_liberal(ao->artries, "Invalid ar-tries value");
  }
  if (ao->ardelay) {
    ao->delay = check_value(ao->ardelay, "Invalid ar-delay value");
  }
}
