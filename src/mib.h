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

#ifndef __MIB_H__
#define __MIB_H__

#include "snmp.h"

typedef struct mib_object_t mib_object_t;

/*
 *  Function types to treat tabular structures
 */
typedef s8t (*get_value_t)(mib_object_t* object, oid_item_t* oid_item, u8t len);
typedef oid_item_t* (*get_next_oid_t)(mib_object_t* object, oid_item_t* oid_item, u8t len);
typedef s8t (*set_value_t)(mib_object_t* object, oid_item_t* oid_item, u8t len, varbind_value_t value);

typedef struct mib_object_t
{
    varbind_t varbind;

    /* A pointer to the get value function.
     */
    get_value_t get_fnc_ptr;

    /* A pointer to the get next oid function.
     * If set then the object is tabular.
     */
    get_next_oid_t get_next_oid_fnc_ptr;

    /* A pointer to the get value function.
     */
    set_value_t set_fnc_ptr;

    struct mib_object_t* next_ptr;

} mib_object_type;

s8t mib_init();

mib_object_t* mib_get(varbind_t* req);

mib_object_t* mib_get_next(varbind_t* req);

s8t mib_set(mib_object_t* object, varbind_t* req);
#endif /* __MIB_H__ */
