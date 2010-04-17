/* -----------------------------------------------------------------------------
 * SNMP implementation for Contiki
 *
 * Copyright (C) 2010 Siarhei Kuryla <kurilo@gmail.com>
 *
 * This program is part of free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

/**
 * \file
 *         Utility facilites for the SNMP server
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */

#ifndef __SNMPD_UTILS_H__
#define	__SNMPD_UTILS_H__

#include "snmp-protocol.h"

#define min(a,b) ((a>b) ? b : a)
#define max(a,b) ((a>b) ? a : b)

s8t oid_cmp(oid_t* oid1, oid_t* oid2);

typedef struct u8t_list_t
{
    u8t             value;
    struct u8t_list_t *next_ptr;
} u8t_list_t;

u8t_list_t* u8t_list_append(u8t_list_t* ptr, u8t value);

void u8t_list_free(u8t_list_t* ptr);

varbind_t* varbind_list_append(varbind_t* ptr);

oid_item_t* oid_item_list_append(oid_item_t* ptr, OID_T value);

oid_item_t* oid_item_list_reverse(oid_item_t* ptr);

void oid_item_list_free(oid_item_t* ptr);

oid_t* oid_create();

void oid_free(oid_t* ptr);

oid_t* oid_copy(oid_t* oid_ptr, oid_item_t** last_oid_item);

u8t oid_length(oid_item_t* ptr);

#endif	/* __SNMPD_UTILS_H__ */

