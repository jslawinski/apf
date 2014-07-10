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

#ifndef _JS_AUDIT_LIST_STRUCT_H
#define _JS_AUDIT_LIST_STRUCT_H

#include "audit_list_node_struct.h"

typedef struct auditlist {
  AuditListNode* head;
  AuditListNode* tail;
} AuditList;

/* 'constructor' */
AuditList* AuditList_new();
/* 'destructor' */
void AuditList_free(AuditList** al);
/* other */
void AuditList_insert_back(AuditList* al, AuditListNode* aln);
AuditListNode* AuditList_get_first(AuditList* al);
void AuditList_delete_first(AuditList* al);
void AuditList_clear(AuditList* al);

#endif
