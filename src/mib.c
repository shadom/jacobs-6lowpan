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
#include <string.h>
#include <stdlib.h>

#include "mib.h"
#include "snmp-protocol.h"
#include "ber.h"
#include "utils.h"
#include "logging.h"

static mib_object_t *mib_head = 0, *mib_tail = 0;

/*-----------------------------------------------------------------------------------*/
/*
 * Create an OID based on the prefix.
 */
static oid_t* create_oid_by_prefix(const OID_T* const prefix, oid_item_t** last_ptr)
{
    oid_t* oid = oid_create();
    CHECK_PTR_U(oid);
    
    const OID_T* cur = prefix;
    oid_item_t* oid_item_ptr = 0;
    while (*cur) {
        if (!oid->first_ptr) {
            oid_item_ptr = oid->first_ptr = oid_item_list_append(0, *cur);
        } else {
            oid_item_ptr = oid_item_list_append(oid_item_ptr, *cur);
        }
        if (!oid_item_ptr) {
            return 0;
        }
        cur = cur + 1;
        oid->len++;
    }
    if (last_ptr) {
        *last_ptr = oid_item_ptr;
    }
    return oid;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Find the element number N in the list.
 */
static oid_item_t* element_n(oid_item_t* first_ptr, u8t n)
{
    while (n > 0 && first_ptr) {
        first_ptr = first_ptr->next_ptr;
        n--;
    }
    return first_ptr;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Adds an object to the MIB.
 * TODO: sort while adding an object 
 */
void mib_add(mib_object_t* object) {
    if (!mib_head) {
        mib_head = object;
        mib_tail = object;
        object->next_ptr = 0;
    } else {
        mib_tail->next_ptr = object;
        object->next_ptr = 0;
        mib_tail = object;
    }
}

/*-----------------------------------------------------------------------------------*/
/*
 * Adds a scalar to the MIB.
 */
s8t add_scalar(const OID_T* const prefix, const OID_T object_id, u8t value_type, const void* const value, get_value_t gfp, set_value_t svfp)
{
    mib_object_t* object = mib_object_create();
    CHECK_PTR(object);
    /* set oid functions */
    object->get_fnc_ptr = gfp;
    object->set_fnc_ptr = svfp;
    object->get_next_oid_fnc_ptr = 0;

    /* set initial value if it's not NULL */
    if (value) {
        switch (value_type) {
            case BER_TYPE_IPADDRESS:
            case BER_TYPE_OCTET_STRING:
                object->varbind.value.s_value.len = strlen((char*)value);
                object->varbind.value.s_value.ptr = (u8t*)malloc(object->varbind.value.s_value.len);
                if (!object->varbind.value.s_value.ptr) {
                    snmp_log("can not allocate memory for a string\n");
                    return -1;
                }
                memcpy(object->varbind.value.s_value.ptr, value, object->varbind.value.s_value.len);
                break;

            case BER_TYPE_INTEGER:
                object->varbind.value.i_value = *((s32t*)value);
                break;

            case BER_TYPE_COUNTER:
            case BER_TYPE_TIME_TICKS:
            case BER_TYPE_GAUGE:
                object->varbind.value.u_value = *((u32t*)value);
                break;

            case BER_TYPE_OPAQUE:
            case BER_TYPE_OID:
                // TODO: implement
                break;

            default:
                break;
        }
    }
    /* construct OID */
    oid_item_t *item_ptr1, *item_ptr2;
    oid_t* oid_ptr = create_oid_by_prefix(prefix, &item_ptr1);

    item_ptr1 = oid_item_list_append(item_ptr1, object_id);
    item_ptr2 = oid_item_list_append(item_ptr1, 0);
    CHECK_PTR(oid_ptr && !item_ptr1 && !item_ptr2);
    oid_ptr->len += 2;
    
    object->varbind.oid_ptr = oid_ptr;

    /* set value type */
    object->varbind.value_type = value_type;

    mib_add(object);

    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Adds a table to the MIB.
 */
s8t add_table(const OID_T* const prefix, get_value_t  gfp, get_next_oid_t gnofp, set_value_t svfp)
{
    mib_object_t* object = mib_object_create();
    CHECK_PTR(object);

    /* copy the oid prefix */
    oid_t* oid_ptr = create_oid_by_prefix(prefix, 0);
    CHECK_PTR(oid_ptr);
    
    object->varbind.oid_ptr = oid_ptr;

    /* set getter functions */
    object->get_fnc_ptr = gfp;
    /* set next oid function */
    object->get_next_oid_fnc_ptr = gnofp;
    /* set set value function */
    object->set_fnc_ptr = svfp;

    /* mark the entry in the MIB as a table */
    object->varbind.value_type = BER_TYPE_NULL;

    mib_add(object);
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Find an object in the MIB corresponding to the oid in the snmp-get request.
 */
mib_object_t* mib_get(varbind_t* req)
{
    mib_object_t* ptr = mib_head;
    while (ptr) {
        // scalar
        if (ptr->varbind.oid_ptr->len == req->oid_ptr->len &&
                !oid_cmp(ptr->varbind.oid_ptr, req->oid_ptr)) {
            break;
        } else if (ptr->get_next_oid_fnc_ptr && ptr->varbind.oid_ptr->len < req->oid_ptr->len &&
                !oid_cmp(ptr->varbind.oid_ptr, req->oid_ptr)) {
            // tabular
            break;
        }
        ptr = ptr->next_ptr;
    }


    if (!ptr) {
        snmp_log("mib object not found\n");
        return 0;
    }

    if (ptr->get_fnc_ptr) {
        if ((ptr->get_fnc_ptr)(ptr, element_n(req->oid_ptr->first_ptr, ptr->varbind.oid_ptr->len), req->oid_ptr->len - ptr->varbind.oid_ptr->len) == -1) {
            snmp_log("can not get the value of the object\n");
            return 0;
        }
    }

    /* copy the value */
    memcpy(&req->value, &ptr->varbind.value, sizeof(varbind_value_t));
    req->value_type = ptr->varbind.value_type;
    return ptr;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Find an object in the MIB that is the lexicographical successor of the given one.
 */
mib_object_t* mib_get_next(varbind_t* req)
{
    s8t cmp;
    mib_object_t* ptr = mib_head;
    while (ptr) {
        // find the object
        cmp = oid_cmp(req->oid_ptr, ptr->varbind.oid_ptr);

        if (!ptr->get_next_oid_fnc_ptr) {
            // handle scalar object
            if (cmp == -1 || (cmp == 0 && req->oid_ptr->len < ptr->varbind.oid_ptr->len)) {
                /* free the request oid list */
                oid_free(req->oid_ptr);
                req->oid_ptr = oid_copy(ptr->varbind.oid_ptr, 0);
                CHECK_PTR_U(req->oid_ptr);
                break;
            }
        } else {
            /* handle tabular object */
            if (cmp == -1 || cmp == 0) {
                /* oid of the first element */
                oid_item_t* tail_ptr;
                if ((tail_ptr = (ptr->get_next_oid_fnc_ptr)(ptr, (cmp == -1 ? 0 : element_n(req->oid_ptr->first_ptr, ptr->varbind.oid_ptr->len)),
                        cmp == -1 ? 0 : req->oid_ptr->len - ptr->varbind.oid_ptr->len)) != 0) {
                    /* copy the mib object's oid */
                    oid_item_t* last_ptr;
                    oid_t* new_oid_ptr = oid_copy(ptr->varbind.oid_ptr, &last_ptr);
                    CHECK_PTR_U(new_oid_ptr);
                    /* attach the tail */
                    last_ptr->next_ptr = tail_ptr;
                    new_oid_ptr->len += oid_length(tail_ptr);
                    /* free the previos oid */
                    oid_free(req->oid_ptr);
                    /* set the new one */
                    req->oid_ptr = new_oid_ptr;
                    break;                    
                }
            }
        }
        ptr = ptr->next_ptr;
    }

    if (!ptr) {
        snmp_log("mib does not contain next object\n");
        return 0;
    }

    if (ptr->get_fnc_ptr) {
        if ((ptr->get_fnc_ptr)(ptr, element_n(req->oid_ptr->first_ptr, ptr->varbind.oid_ptr->len),
                                    req->oid_ptr->len - ptr->varbind.oid_ptr->len) == -1) {
            snmp_log("can not get the value of the object\n");
            return 0;
        }
    }

    /* copy the value */
    memcpy(&req->value, &ptr->varbind.value, sizeof(varbind_value_t));
    req->value_type = ptr->varbind.value_type;
    return ptr;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Set the value for an object in the MIB.
 */
s8t mib_set(mib_object_t* object, varbind_t* req)
{
    if (object->set_fnc_ptr) {
        if ((object->set_fnc_ptr)(object,
                element_n(req->oid_ptr->first_ptr, object->varbind.oid_ptr->len),
                req->oid_ptr->len - object->varbind.oid_ptr->len, req->value) == -1) {
            snmp_log("can not set the value of the object\n");
            return -1;
        }
    } else {
        switch (req->value_type) {
            case BER_TYPE_IPADDRESS:
            case BER_TYPE_OCTET_STRING:
                if (object->varbind.value.s_value.ptr) {
                    free(object->varbind.value.s_value.ptr);
                }
                object->varbind.value.s_value.len = req->value.s_value.len;
                object->varbind.value.s_value.ptr = (u8t*)malloc(req->value.s_value.len);
                if (!object->varbind.value.s_value.ptr) {
                    snmp_log("can not allocate memory for a string\n");
                    return -1;
                }
                memcpy(object->varbind.value.s_value.ptr, req->value.s_value.ptr, object->varbind.value.s_value.len);
                break;

            case BER_TYPE_INTEGER:
                object->varbind.value.i_value = req->value.i_value;
                break;

            case BER_TYPE_COUNTER:
            case BER_TYPE_TIME_TICKS:
            case BER_TYPE_GAUGE:
                object->varbind.value.u_value = req->value.u_value;
                break;

            case BER_TYPE_OPAQUE:
            case BER_TYPE_OID:
                /* TODO: implement */
                return -1;
            default:
                return -1;
        }
    }
    return 0;
}