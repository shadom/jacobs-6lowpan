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

s8t oid_cmp(oid_t*  oid1, oid_t* oid2) {
    static u8t j;
    for (j = 0; j < min(oid1->len, oid2->len); j++) {
        if (oid1->values[j] > oid2->values[j]) {
            return 1;
        } else if (oid1->values[j] < oid2->values[j]) {
            return -1;
        }
    }
    return 0;
}

u8t_list_t* u8t_list_append(u8t_list_t* ptr, u8t value)
{
    u8t_list_t* new_el_ptr = malloc(sizeof(u8t_list_t));
    if (!new_el_ptr) return 0;

    new_el_ptr->next_ptr = 0;
    new_el_ptr->value = value;
    if (ptr) {
        ptr->next_ptr = new_el_ptr;
    }
    return new_el_ptr;
}

void u8t_list_free(u8t_list_t* ptr)
{
    while (ptr) {
        u8t_list_t* next = ptr->next_ptr;
        free(ptr);
        ptr = next;
    }
}

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