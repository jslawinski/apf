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

#ifndef _JS_ACTIVEFOR_H
#define _JS_ACTIVEFOR_H

#define AF_S_CONCLOSED	1
#define	AF_S_CONOPEN	2
#define AF_S_MESSAGE	3
#define AF_S_LOGIN	8

#define S_STATE_CLEAR	0
#define S_STATE_RUNNING	4
#define S_STATE_CLOSING	5
#define	S_STATE_OPENING	6
#define S_STATE_OPEN	7

typedef struct {
	char state;
	int connfd;
} ConnectuserT;

#endif

