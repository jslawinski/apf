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

#ifdef HAVE_LIBDL

#  ifndef _JS_MODULE_STRUCT_H
#  define _JS_MODULE_STRUCT_H

typedef struct {
    char loaded;
    char* fileName;
    void* handle;
    char* (*info)(void);
    int (*allow)(char*, char*);
    int (*filter)(char*, unsigned char*, int*);
} Module;

/* 'constructor' */
Module* Module_new();
/* 'destructor' */
void Module_free(Module** m);
/* setters */
void Module_set_fileName(Module* m, char* fileName);
/* getters */
char* Module_get_fileName(Module* m);
/* other */
int Module_loadModule(Module* m);
int Module_releaseModule(Module* m);
int Module_isModuleLoaded(Module* m);
char* Module_function_info(Module* m);
int Module_function_allow(Module* m, char* host, char* port);
int Module_function_filter(Module* m, char* host, unsigned char* message, int* messageLength);

#  endif

#endif
