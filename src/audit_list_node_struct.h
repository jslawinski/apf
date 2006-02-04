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

#include <time.h>

#ifndef _JS_AUDIT_LIST_NODE_STRUCT_H
#define _JS_AUDIT_LIST_NODE_STRUCT_H

typedef struct alnode {
  int userId;
  char nameBuf[128];
  char portBuf[7];
  time_t connectTime;
  time_t duration;
	struct alnode* nextNode;
} AuditListNode;

/* 'constructors' */
AuditListNode* AuditListNode_new();
AuditListNode* AuditListNode_new_entry(int userId, char* nameBuf, char* portBuf,
    time_t connectTime, time_t duration);
/* 'destructor' */
void AuditListNode_free(AuditListNode** aln);
/* setters */
void AuditListNode_set_userId(AuditListNode* aln, int userId);
void AuditListNode_set_nameBuf(AuditListNode* aln, char* nameBuf);
void AuditListNode_set_portBuf(AuditListNode* aln, char* portBuf);
void AuditListNode_set_connectTime(AuditListNode* aln, time_t connectTime);
void AuditListNode_set_duration(AuditListNode* aln, time_t duration);
void AuditListNode_set_nextNode(AuditListNode* aln, AuditListNode* nextNode);
/* getters */
int AuditListNode_get_userId(AuditListNode* aln);
char* AuditListNode_get_nameBuf(AuditListNode* aln);
char* AuditListNode_get_portBuf(AuditListNode* aln);
time_t AuditListNode_get_connectTime(AuditListNode* aln);
time_t AuditListNode_get_duration(AuditListNode* aln);
AuditListNode* AuditListNode_get_nextNode(AuditListNode* aln);
/* other */
time_t* AuditListNode_get_connectTimep(AuditListNode* aln);

#endif
