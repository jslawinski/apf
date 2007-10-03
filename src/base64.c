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

#include <config.h>

#include "base64.h"

/*
 * Copyright (c) 1996, 1998 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 * Portions Copyright (c) 1995 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * To the extent it has a right to do so, IBM grants an immunity from suit
 * under its patents, if any, for the use, sale or manufacture of products to
 * the extent that such products are used for performing Domain Name System
 * dynamic updates in TCP/IP networks by means of the Software.  No immunity is
 * granted for any product per se or for any other function of any product.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
 */

static const char Base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char Pad64 = '=';

int
b64_ntop(uint8_t const *src, size_t srclength, char *target, size_t targsize)
{
  size_t datalength = 0;
  uint8_t input[3];
  uint8_t output[4];
  size_t i;

  while (2 < srclength) {
    input[0] = *src++;
    input[1] = *src++;
    input[2] = *src++;
    srclength -= 3;

    output[0] = input[0] >> 2;
    output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
    output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
    output[3] = input[2] & 0x3f;
    if (output[0] >= 64) return -1;
    if (output[1] >= 64) return -1;
    if (output[2] >= 64) return -1;
    if (output[3] >= 64) return -1;

    if (datalength + 4 > targsize)
      return (-1);
    target[datalength++] = Base64[output[0]];
    target[datalength++] = Base64[output[1]];
    target[datalength++] = Base64[output[2]];
    target[datalength++] = Base64[output[3]];
  }
    
  /* Now we worry about padding. */
  if (0 != srclength) {
    /* Get what's left. */
    input[0] = input[1] = input[2] = (uint8_t) '\0';
    for (i = 0; i < srclength; i++)
      input[i] = *src++;
  
    output[0] = input[0] >> 2;
    output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
    output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
    if (output[0] >= 64) return -1;
    if (output[1] >= 64) return -1;
    if (output[2] >= 64) return -1;

    if (datalength + 4 > targsize)
      return (-1);
    target[datalength++] = Base64[output[0]];
    target[datalength++] = Base64[output[1]];
    if (srclength == 1)
      target[datalength++] = Pad64;
    else
      target[datalength++] = Base64[output[2]];
    target[datalength++] = Pad64;
  }
  if (datalength >= targsize)
    return (-1);
  target[datalength] = '\0';  /* Returned value doesn't count \0. */
  return (int) (datalength);
}

int
b64_pton(char const *src, uint8_t *target, size_t targsize)
{
  int tarindex, state, ch;
  char *pos;

  state = 0;
  tarindex = 0;

  while ((ch = *src++) != '\0') {
    if (isspace((unsigned char)ch))        /* Skip whitespace anywhere. */
      continue;

    if (ch == Pad64)
      break;

    pos = strchr(Base64, ch);
    if (pos == 0) {
      /* A non-base64 character. */
      return (-1);
    }

    switch (state) {
    case 0:
      if (target) {
        if ((size_t)tarindex >= targsize)
          return (-1);
        target[tarindex] = (pos - Base64) << 2;
      }
      state = 1;
      break;
    case 1:
      if (target) {
        if ((size_t)tarindex + 1 >= targsize)
          return (-1);
        target[tarindex]   |=  (pos - Base64) >> 4;
        target[tarindex+1]  = ((pos - Base64) & 0x0f)
              << 4 ;
      }
      tarindex++;
      state = 2;
      break;
    case 2:
      if (target) {
        if ((size_t)tarindex + 1 >= targsize)
          return (-1);
        target[tarindex]   |=  (pos - Base64) >> 2;
        target[tarindex+1]  = ((pos - Base64) & 0x03)
              << 6;
      }
      tarindex++;
      state = 3;
      break;
    case 3:
      if (target) {
        if ((size_t)tarindex >= targsize)
          return (-1);
        target[tarindex] |= (pos - Base64);
      }
      tarindex++;
      state = 0;
      break;
    default:
      abort();
    }
  }

  /*
   * We are done decoding Base-64 chars.  Let's see if we ended
   * on a byte boundary, and/or with erroneous trailing characters.
   */

  if (ch == Pad64) {    /* We got a pad char. */
    ch = *src++;    /* Skip it, get next. */
    switch (state) {
    case 0:   /* Invalid = in first position */
    case 1:   /* Invalid = in second position */
      return (-1);

    case 2:   /* Valid, means one byte of info */
      /* Skip any number of spaces. */
      for ((void)NULL; ch != '\0'; ch = *src++)
        if (!isspace((unsigned char)ch))
          break;
      /* Make sure there is another trailing = sign. */
      if (ch != Pad64)
        return (-1);
      ch = *src++;    /* Skip the = */
      /* Fall through to "single trailing =" case. */
      /* FALLTHROUGH */

    case 3:   /* Valid, means two bytes of info */
      /*
       * We know this char is an =.  Is there anything but
       * whitespace after it?
       */
      for ((void)NULL; ch != '\0'; ch = *src++)
        if (!isspace((unsigned char)ch))
          return (-1);

      /*
       * Now make sure for cases 2 and 3 that the "extra"
       * bits that slopped past the last full byte were
       * zeros.  If we don't check them, they become a
       * subliminal channel.
       */
      if (target && target[tarindex] != 0)
        return (-1);
    }
  } else {
    /*
     * We ended by seeing the end of the string.  Make sure we
     * have no partial bytes lying around.
     */
    if (state != 0)
      return (-1);
  }

  return (tarindex);
}
