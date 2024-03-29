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
 *         SNMPv1 protocol definitions
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */


#ifndef __SNMP_H__
#define __SNMP_H__

#include "snmpd-types.h"
#include "snmpd-conf.h"

#define SNMP_VERSION_1					0
#define SNMP_VERSION_2C					1

/** \brief OID item. */
typedef struct oid_item_t {
    OID_T               value;
    struct oid_item_t*  next_ptr;
} oid_item_t;

/** \brief OID. */
typedef struct oid_t {
    struct oid_item_t* first_ptr;
    u8t                len;
} oid_t;

/** \brief Value of the variable binding. */
typedef union {
    s32t            i_value;
    u32t            u_value;
    struct {
        u8t*        ptr;
        u16t        len;
    } s_value;
} varbind_value_t;

/** \brief Variable binding. */
typedef struct varbind_t {
    oid_t*              oid_ptr;
    u8t                 value_type;
    varbind_value_t     value;
    struct varbind_t*   next_ptr;
} varbind_t;

/** \brief Request data structure. */
typedef struct {
    u8t         request_type;
    s32t        request_id;
    u8t         error_status;
    u8t         error_index;
    varbind_t*  varbind_first_ptr;
    u8t         varbind_len;
    /* the index of the first varbind byte in the input message */
    u16t        varbind_index;
} pdu_t;

/** \brief Request data structure. */
typedef struct {
    u8t     version;
    u8t*    community;
    pdu_t   pdu;
} message_t;

#define ERROR_STATUS_NO_ERROR                           0
#define ERROR_STATUS_TOO_BIG				1
#define ERROR_STATUS_NO_SUCH_NAME			2
#define ERROR_STATUS_BAD_VALUE				3
#define ERROR_STATUS_READ_ONLY				4
#define ERROR_STATUS_GEN_ERR				5
#define ERROR_STATUS_NO_ACCESS				6
#define ERROR_STATUS_WRONG_TYPE				7
#define ERROR_STATUS_WRONG_LENGTH			8
#define ERROR_STATUS_WRONG_ENCODING			9
#define ERROR_STATUS_WRONG_VALUE			10
#define ERROR_STATUS_NO_CREATION			11
#define ERROR_STATUS_INCONSISTENT_VALUE                 12
#define ERROR_STATUS_RESOURCE_UNAVAILABLE               13
#define ERROR_STATUS_COMMIT_FAILED			14
#define ERROR_STATUS_UNDO_FAILED			15
#define ERROR_STATUS_AUTHORIZATION_ERROR                16
#define ERROR_STATUS_NOT_WRITABLE			17
#define ERROR_STATUS_INCONSISTENT_NAME                  18

#endif /* __SNMP_H__ */
