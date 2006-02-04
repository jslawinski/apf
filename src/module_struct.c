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

#ifdef HAVE_LIBDL

#include "string_functions.h"
#include "module_struct.h"

#include <stdlib.h>
#include <dlfcn.h>

/*
 * Function name: Module_new
 * Description: Create and initialize new Module structure.
 * Returns: Pointer to newly created Module structure.
 */

Module*
Module_new()
{
  Module* tmp = calloc(1, sizeof(Module));
  if (tmp == NULL) {
    return NULL;
  }
  return tmp;
}

/*
 * Function name: Module_free
 * Description: Free the memory allocated for Module structure.
 * Arguments: m - pointer to pointer to Module structure
 */

void
Module_free(Module** m)
{
  if (m == NULL) {
    return;
  }
  if ((*m) == NULL) {
    return;
  }
  Module_releaseModule(*m);
  if ((*m)->fileName) {
    free((*m)->fileName);
    (*m)->fileName = NULL;
  }
  free((*m));
  (*m) = NULL;
}

/*
 * Function name: Module_set_fileName
 * Description: Set the filename of the module.
 * Arguments: m - pointer to Module structure
 *            fileName - the filename of the module
 */

void
Module_set_fileName(Module* m, char* fileName)
{
  if (m == NULL) {
    return;
  }
  string_cp(&(m->fileName), fileName);
}

/*
 * Function name: Module_get_fileName
 * Description: Get the filename of the module.
 * Arguments: m - pointer to Module structure
 * Returns: The filename of the module.
 */

char*
Module_get_fileName(Module* m)
{
  if (m == NULL) {
    return NULL;
  }
  return m->fileName;
}

/*
 * Function name: Module_loadModule
 * Description: Load the module into the memory.
 * Arguments: m - pointer to Module structure
 * Returns: 0 - successful/filename not set
 *          1/2 - some errors occured.
 */

int
Module_loadModule(Module* m)
{
  if (Module_get_fileName(m)) {
    m->handle = dlopen(Module_get_fileName(m), RTLD_NOW);
    if (!m->handle) {
      return 1;
    }
    dlerror();
    *(void**) (&m->info) = dlsym(m->handle, "info");
    *(void**) (&m->allow) = dlsym(m->handle, "allow");
    *(void**) (&m->filter) = dlsym(m->handle, "filter");
    if (dlerror() != NULL) {
      return 2;
    }
    m->loaded = 1;
  }	
  return 0;
}

/*
 * Function name: Module_releaseModule
 * Description: Unload the module from the memory.
 * Arguments: m - pointer to Module structure
 * Returns: 0 - successful/module was not loaded
 *          !0 - some errors occured.
 */

int
Module_releaseModule(Module* m)
{
	if (Module_isModuleLoaded(m)) {
		m->loaded = 0;
		m->info = NULL;
		m->allow = NULL;
		m->filter = NULL;
	return dlclose(m->handle);
	}
	return 0;
}

/*
 * Function name: Module_isModuleLoaded
 * Description: Check if the module is loaded into the memory.
 * Arguments: m - pointer to Module structure
 * Returns: 0 - module is not loaded
 *          1 - module is loaded.
 */

int
Module_isModuleLoaded(Module* m)
{
  if (m == NULL) {
    return 0;
  }
	return m->loaded;
}

/*
 * Function name: Module_function_info
 * Description: Exec the info function of the module.
 * Arguments: m - pointer to Module structure
 * Returns: Result of the info function of the module.
 */

char*
Module_function_info(Module* m)
{
  if (!Module_isModuleLoaded(m)) {
    return NULL;
  }
  return m->info();
}

/*
 * Function name: Module_function_allow
 * Description: Exec the allow function of the module.
 * Arguments: m - pointer to Module structure
 * Returns: Result of the allow function of the module.
 */

int
Module_function_allow(Module* m, char* host, char* port)
{
  if (!Module_isModuleLoaded(m)) {
    return 0;
  }
  return m->allow(host, port);
}

/*
 * Function name: Module_function_filter
 * Description: Exec the filter function of the module.
 * Arguments: m - pointer to Module structure
 * Returns: Result of the filter function of the module.
 */

int
Module_function_filter(Module* m, char* host, unsigned char* message, int* messageLength)
{
  if (!Module_isModuleLoaded(m)) {
    return 0;
  }
  return m->filter(host, message, messageLength);
}

#endif
