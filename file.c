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

#include "file.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

ConfigurationT
parsefile(char* name, int* status)
{
	static ConfigurationT cfg;
	FILE* file = NULL;
	int state;
	char buff[256];
	char helpbuf1[256];
	char helpbuf2[256];

	*status = 1;

	memset(buff, 0, 256);
	
	cfg.certif = NULL;
	cfg.keys = NULL;
	cfg.size = 0;
	cfg.realmtable = NULL;
	cfg.logging = 0;
	cfg.logfnam = NULL;

	state = F_UNKNOWN;
	
	file = fopen(name, "r");
	if (file == NULL) {
		return cfg;
	}

	while (fgets(buff, 256, file) != NULL) {
		helpbuf1[0] = 0;
		sscanf(buff, "%s", helpbuf1);
		if (strcmp(helpbuf1, "newrealm")==0) {
			++cfg.size;
		}
	}
	rewind(file);
	
	cfg.realmtable = calloc(cfg.size, sizeof(RealmT));
	cfg.size = 0;
	*status = 0;

	while (fgets(buff, 256, file) != NULL) {
		(*status)++;
		state = sscanf(buff, "%s %s", helpbuf1, helpbuf2);
			if (helpbuf1[0] == '#') {
				memset(buff, 0, 256);
				continue;
			}
			if (state == 1) {
				if (strcmp(helpbuf1, "newrealm")==0) {
					++cfg.size;
				}
				else {
					return cfg;
				}
			}
			else if (state == 2) {
				if (strcmp(helpbuf1, "certificate")==0) {
					cfg.certif = calloc(strlen(helpbuf2)+1, sizeof(char));
					strcpy(cfg.certif, helpbuf2);
				}
				else if (strcmp(helpbuf1, "key")==0) {
					cfg.keys = calloc(strlen(helpbuf2)+1, sizeof(char));
					strcpy(cfg.keys, helpbuf2);
				}
				else if (strcmp(helpbuf1, "heavylog")==0) {
					if (cfg.logging)
						return cfg;
					cfg.logging = 2;
					cfg.logfnam = calloc(strlen(helpbuf2)+1, 
							sizeof(char));
					strcpy(cfg.logfnam, helpbuf2);
					
				}
				else if (strcmp(helpbuf1, "lightlog")==0) {
					if (cfg.logging) {
						return cfg;
					}
					cfg.logging = 1;
					cfg.logfnam = calloc(strlen(helpbuf2)+1, 
							sizeof(char));
					strcpy(cfg.logfnam, helpbuf2);
				}
				else if (cfg.size == 0) {
					return cfg;
				}
				else if (strcmp(helpbuf1, "hostname")==0) {
					cfg.realmtable[cfg.size-1].hostname = calloc(strlen(helpbuf2)+1, 
							sizeof(char));
					strcpy(cfg.realmtable[cfg.size-1].hostname, helpbuf2);
				}
				else if (strcmp(helpbuf1, "listen")==0) {
					cfg.realmtable[cfg.size-1].lisportnum = calloc(strlen(helpbuf2)+1, 
							sizeof(char));
					strcpy(cfg.realmtable[cfg.size-1].lisportnum, helpbuf2);
				}
				else if (strcmp(helpbuf1, "manage")==0) {
					cfg.realmtable[cfg.size-1].manportnum = calloc(strlen(helpbuf2)+1, 
							sizeof(char));
					strcpy(cfg.realmtable[cfg.size-1].manportnum, helpbuf2);
				}
				else if (strcmp(helpbuf1, "users")==0) {
					cfg.realmtable[cfg.size-1].users = calloc(strlen(helpbuf2)+1, 
							sizeof(char));
					strcpy(cfg.realmtable[cfg.size-1].users, helpbuf2);
				}
				else if (strcmp(helpbuf1, "type")==0) {
					if (cfg.realmtable[cfg.size-1].type != 0) {
						return cfg;
					}
					if (strcmp(helpbuf2, "tcp")==0) {
						cfg.realmtable[cfg.size-1].type = 1;
					}
					else if (strcmp(helpbuf2, "udp")==0) {
						cfg.realmtable[cfg.size-1].type = 2;
					}
					else {
						return cfg;
					}
				}
				else {
					return cfg;
				}
			}
			memset(buff, 0, 256);
		}

	fclose(file);
	
	*status = 0;
	return cfg;
}

