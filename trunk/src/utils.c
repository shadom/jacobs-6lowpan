/* -----------------------------------------------------------------------------
 * SNMP implementation for Contiki
 *
 * Copyright (C) 2010 Siarhei Kuryla
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

#include <stdlib.h>

#include "utils.h"
#include "logging.h"

s8t oid_cmp(oid_t*  oid1, oid_t* oid2) {
    oid_item_t* oi1 = oid1->first_ptr;
    oid_item_t* oi2 = oid2->first_ptr;
    while (oi1 && oi2) {
        if (oi1->value > oi2->value) {
            return 1;
        } else if (oi1->value < oi2->value) {
            return -1;
        }
        oi1 = oi1->next_ptr;
        oi2 = oi2->next_ptr;
    }
    return 0;
}

/*---------------------------------------------------------*/
/*
 *  u8t list functions.
 */
mib_object_list_t* mib_object_list_append(mib_object_list_t* ptr, mib_object_t* value)
{
    mib_object_list_t* new_el_ptr = malloc(sizeof(mib_object_list_t));
    if (!new_el_ptr) return 0;

    new_el_ptr->next_ptr = 0;
    new_el_ptr->value = value;
    if (ptr) {
        ptr->next_ptr = new_el_ptr;
    }
    return new_el_ptr;
}

void mib_object_list_free(mib_object_list_t* ptr)
{
    while (ptr) {
        mib_object_list_t* next = ptr->next_ptr;
        free(ptr);
        ptr = next;
    }
}

/*---------------------------------------------------------*/
/*
 *  Variable binding list functions.
 */
varbind_t* varbind_list_append(varbind_t* ptr)
{
    varbind_t* new_el_ptr = malloc(sizeof(varbind_t));
    if (!new_el_ptr) return 0;
    new_el_ptr->next_ptr = 0;
    if (ptr) {
        ptr->next_ptr = new_el_ptr;
    }
    return new_el_ptr;
}


/*---------------------------------------------------------*/
/*
 *  OID item list functions.
 */
oid_item_t* oid_item_list_append(oid_item_t* ptr, OID_T value)
{
    oid_item_t* new_el_ptr = malloc(sizeof(oid_item_t));
    if (!new_el_ptr) return 0;
    new_el_ptr->next_ptr = 0;
    new_el_ptr->value = value;
    if (ptr) {
        ptr->next_ptr = new_el_ptr;
    }
    return new_el_ptr;
}

oid_item_t* oid_item_list_reverse(oid_item_t* ptr)
{
    oid_item_t* next_ptr, *cur_ptr;
    cur_ptr = ptr->next_ptr;
    ptr->next_ptr = 0;
    
    while (cur_ptr) {
        next_ptr = cur_ptr->next_ptr;
        cur_ptr->next_ptr = ptr;
        ptr = cur_ptr;
        cur_ptr = next_ptr;
    }
    return ptr;
}


void oid_item_list_free(oid_item_t* ptr)
{
    while (ptr) {
        oid_item_t* next = ptr->next_ptr;
        free(ptr);
        ptr = next;
    }
}

/*---------------------------------------------------------*/
/*
 *  OID functions.
 */
oid_t* oid_create()
{
    oid_t* new_el_ptr = malloc(sizeof(oid_t));
    if (!new_el_ptr) return 0;
    new_el_ptr->first_ptr = 0;
    new_el_ptr->len = 0;
    return new_el_ptr;
}

void oid_free(oid_t* ptr)
{
    if (ptr) {
        oid_item_list_free(ptr->first_ptr);
        free(ptr);
    }
}

oid_t* oid_copy(oid_t* oid_ptr, oid_item_t** last_oid_item)
{
    oid_t* ret = oid_create();
    if (!ret) { return 0;}
    ret->len = oid_ptr->len;

    oid_item_t *cur_ptr = oid_ptr->first_ptr,  *prev_ptr = 0;
    while (cur_ptr) {
        if (!ret->first_ptr) {
            prev_ptr = ret->first_ptr = oid_item_list_append(0, cur_ptr->value);
        } else {
            prev_ptr = oid_item_list_append(prev_ptr, cur_ptr->value);
        }
        if (!prev_ptr) { return 0;}
        cur_ptr = cur_ptr->next_ptr;
    }
    if (last_oid_item) {
        *last_oid_item = prev_ptr;
    }
    return ret;
}

u8t oid_length(oid_item_t* ptr)
{
    u8t ret = 0;
    while (ptr) {
        ret++;
        ptr = ptr->next_ptr;
    }
    return ret;
}

/*---------------------------------------------------------*/
/*
 *  MIB object list functions.
 */
mib_object_t* mib_object_create()
{
    mib_object_t* new_el_ptr = malloc(sizeof(mib_object_t));
    if (!new_el_ptr) return 0;
    new_el_ptr->next_ptr = 0;
    return new_el_ptr;
}
