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

#include <config.h>

#ifdef HAVE_LIBDL

#include "modules.h"

#include <stdlib.h>
#include <dlfcn.h>

int
loadmodule(moduleT* module)
{
  if (module->name) {
    module->handle = dlopen(module->name, RTLD_NOW);
    if (!module->handle) {
      return 1;
    }
    dlerror();
    *(void**) (&module->info) = dlsym(module->handle, "info");
    *(void**) (&module->allow) = dlsym(module->handle, "allow");
    *(void**) (&module->filter) = dlsym(module->handle, "filter");
    if (dlerror() != NULL) {
      return 2;
    }
    module->loaded = 1;
  }	
  return 0;
}

int
releasemodule(moduleT* module)
{
	if (ismloaded(module)) {
		module->loaded = 0;
		module->info = NULL;
		module->allow = NULL;
		module->filter = NULL;
	return dlclose(module->handle);
	}
	return 0;
}

int
ismloaded(moduleT* module)
{
	return module->loaded;
}

#endif
