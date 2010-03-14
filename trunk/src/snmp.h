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
 *         Data structures for the SNMPv1 protocol
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */


#ifndef __SNMP_H__
#define __SNMP_H__

#include "snmpd-types.h"
#include "snmpd-conf.h"

/** \brief OID. */
typedef struct {
    u16_t values[OID_LEN];
    u16_t len;
} oid_t;

/** \brief Value of the variable binding. */
typedef struct {
    u8_t buffer[VAR_BIND_VALUE_LEN];
    u8_t len;
} varbind_value_t;

/** \brief Variable binding. */
typedef struct {
    oid_t oid;
    varbind_value_t value;
} varbind_t;

/** \brief NULL value of the variable binding. */
static const varbind_value_t varbind_t_null = {"\x05\x00", 2};

/** \brief Request data structure. */
typedef struct {
    u8_t version;
    u8_t community[COMMUNITY_STRING_LEN];
    u8_t request_type;
    s32_t request_id;
    u8_t error_status;
    u8_t error_index;
    u8_t var_bind_list_len;
    oid_t var_bind_list[VAR_BIND_LEN];
} request_t;

/** \brief Response data structure. */
typedef struct {
    u8_t error_status;
    u8_t error_index;
    u8_t var_bind_list_len;
    varbind_t var_bind_list[VAR_BIND_LEN];
} response_t;


#endif /* __SNMP__ */
