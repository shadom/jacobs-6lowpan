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

/* common oid prefixes ending with 0 */
static const OID_T oid_system[]         = { 1, 3, 6, 1, 2, 1, 1, 0};
static const OID_T oid_if[]     	= { 1, 3, 6, 1, 2, 1, 2, 0};
static const OID_T oid_if_table[]	= { 1, 3, 6, 1, 2, 1, 2, 2, 1, 0};
static const OID_T oid_test[]           = { 1, 3, 6, 1, 2, 1, 1234, 0};

typedef struct mib_object_t mib_object_t;

#define CHECK_PTR(ptr) if (!ptr) { snmp_log("can not allocate memory, line: %d\n", __LINE__); return -1; }
#define CHECK_PTR_U(ptr) if (!ptr) { snmp_log("can not allocate memory, line: %d\n", __LINE__); return 0; }

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

} mib_object_type;

static mib_object_t mib[MIB_LEN];
static u16t mib_length = 0;

/***************************************************/
s8t getSysDescr(mib_object_t* object, oid_item_t* oid_item, u8t len)
{
    if (!object->varbind.value.s_value.len) {
        object->varbind.value.s_value.ptr = (u8t*)"System Description";
        object->varbind.value.s_value.len = 18;
    }
    return 0;
}

s8t setSysDescr(mib_object_t* object, oid_item_t* oid_item, u8t len, varbind_value_t value)
{
    object->varbind.value.s_value.ptr = (u8t*)"System Description2";
    object->varbind.value.s_value.len = 19;
    return 0;
}

s8t getTimeTicks(mib_object_t* object, oid_item_t* oid_item, u8t len)
{
    object->varbind.value.u_value = 1234;
    return 0;
}

/**** IF-MIB ****************/

#define ifNumber 3

s8t getIfNumber(mib_object_t* object, oid_item_t* oid_item, u8t len)
{
    object->varbind.value.i_value = ifNumber;
    return 0;
}

#define ifIndex 1

s8t getIf(mib_object_t* object, oid_item_t* oid_item, u8t len)
{
    snmp_log("get\n");
    if (len != 2) {
        return -1;
    }
    switch (oid_item->value) {
        case ifIndex:
            object->varbind.value_type = BER_TYPE_INTEGER;
            if (0 < oid_item->next_ptr->value && oid_item->next_ptr->value <= ifNumber) {
                snmp_log("%d %d get2\n", oid_item->next_ptr->value);
                object->varbind.value.i_value = oid_item->next_ptr->value;
            } else {
                return -1;
            }
            break;
        default:
            break;
    }
    return 0;
}

oid_item_t* getNextIfOid(mib_object_t* object, oid_item_t* oid_item, u8t len)
{
    OID_T oid_el1 = (len > 0 ? oid_item->value : 0);
    OID_T oid_el2 = (len > 1 ? oid_item->next_ptr->value : 0);

    oid_item_t* ret, *ptr;
    if (oid_el1 < ifIndex) {
        ret = oid_item_list_append(0, ifIndex);
        CHECK_PTR_U(ret);
        ptr = oid_item_list_append(ret, 1);
        CHECK_PTR_U(ptr);
        return ret;
    }
    
    if (oid_el1 == ifIndex && oid_el2 < ifNumber) {
        ret = oid_item_list_append(0, ifIndex);
        CHECK_PTR_U(ret);
        ptr = oid_item_list_append(ret, oid_el2 + 1);
        CHECK_PTR_U(ptr);
        return ret;
    }
    return 0;
}

/***************************************************/

/*-----------------------------------------------------------------------------------*/
/*
 * Create an OID based on the prefix.
 */
static oid_t* create_oid(const OID_T* const prefix, oid_item_t** last_ptr)
{
    oid_t* oid = oid_create();
    if (!oid) {
        return 0;
    }
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
 * Adds a scalar to the MIB.
 */
s8t add_scalar(const OID_T* const prefix, const OID_T object_id, u8t value_type, const void* const value, get_value_t gfp, set_value_t svfp)
{
    /* MIB is full */
    if (mib_length >= MIB_LEN) {
        snmp_log("can't add a new entry to the mib - it's is already full");
        return -1;
    }
    /* set oid functions */
    mib[mib_length].get_fnc_ptr = gfp;
    mib[mib_length].set_fnc_ptr = svfp;
    mib[mib_length].get_next_oid_fnc_ptr = 0;

    /* set initial value if it's not NULL */
    if (value) {
        switch (value_type) {
            case BER_TYPE_IPADDRESS:
            case BER_TYPE_OCTET_STRING:
                mib[mib_length].varbind.value.s_value.len = strlen((char*)value);
                mib[mib_length].varbind.value.s_value.ptr = (u8t*)malloc(mib[mib_length].varbind.value.s_value.len);
                if (!mib[mib_length].varbind.value.s_value.ptr) {
                    snmp_log("can not allocate memory for a string\n");
                    return -1;
                }
                memcpy(mib[mib_length].varbind.value.s_value.ptr, value, mib[mib_length].varbind.value.s_value.len);
                break;

            case BER_TYPE_INTEGER:
                mib[mib_length].varbind.value.i_value = *((s32t*)value);
                break;

            case BER_TYPE_COUNTER:
            case BER_TYPE_TIME_TICKS:
            case BER_TYPE_GAUGE:
                mib[mib_length].varbind.value.u_value = *((u32t*)value);
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
    oid_t* oid_ptr = create_oid(prefix, &item_ptr1);

    item_ptr1 = oid_item_list_append(item_ptr1, object_id);
    item_ptr2 = oid_item_list_append(item_ptr1, 0);
    CHECK_PTR(oid_ptr && !item_ptr1 && !item_ptr2);
    oid_ptr->len += 2;
    
    mib[mib_length].varbind.oid_ptr = oid_ptr;

    /* set value type */
    mib[mib_length].varbind.value_type = value_type;

    mib_length++;
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Adds a table to the MIB.
 */
s8t add_table(const OID_T* const prefix, get_value_t  gfp, get_next_oid_t gnofp, set_value_t svfp)
{
    /* MIB is full */
    if (mib_length >= MIB_LEN) {
        snmp_log("can't add a new entry to the mib - it's is already full");
        return -1;
    }
    /* copy the oid prefix */
    oid_t* oid_ptr = create_oid(prefix, 0);
    CHECK_PTR(oid_ptr);
    
    mib[mib_length].varbind.oid_ptr = oid_ptr;

    /* set getter functions */
    mib[mib_length].get_fnc_ptr = gfp;
    /* set next oid function */
    mib[mib_length].get_next_oid_fnc_ptr = gnofp;
    /* set set value function */
    mib[mib_length].set_fnc_ptr = svfp;

    /* mark the entry in the MIB as a table */
    mib[mib_length].varbind.value_type = BER_TYPE_NULL;

    mib_length++;
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Find an object in the MIB corresponding to the oid in the snmp-get request.
 */
s8t mib_get(varbind_t* req)
{
    static u8t i;
    for (i = 0; i < mib_length; i++) {
        // scalar
        if (mib[i].varbind.oid_ptr->len == req->oid_ptr->len &&
                !oid_cmp(mib[i].varbind.oid_ptr, req->oid_ptr)) {
            break;
        } else if (mib[i].get_next_oid_fnc_ptr && mib[i].varbind.oid_ptr->len < req->oid_ptr->len &&
                !oid_cmp(mib[i].varbind.oid_ptr, req->oid_ptr)) {
            // tabular
            break;
        }
    }

    if (i == mib_length) {
        snmp_log("mib object not found\n");
        return -1;
    }

    if (mib[i].get_fnc_ptr) {
        if ((mib[i].get_fnc_ptr)(&mib[i], element_n(req->oid_ptr->first_ptr, mib[i].varbind.oid_ptr->len), req->oid_ptr->len - mib[i].varbind.oid_ptr->len) == -1) {
            snmp_log("can not get the value of the object\n");
            return -1;
        }
    }

    /* copy the value */
    memcpy(&req->value, &mib[i].varbind.value, sizeof(varbind_value_t));
    req->value_type = mib[i].varbind.value_type;
    return i;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Find an object in the MIB that is the lexicographical successor of the given one.
 */
s8t mib_get_next(varbind_t* req)
{
    static u8t i;
    static s8t cmp;
    for (i = 0; i < mib_length; i++) {
        // find the object
        cmp = oid_cmp(req->oid_ptr, mib[i].varbind.oid_ptr);

        if (!mib[i].get_next_oid_fnc_ptr) {
            // handle scalar object
            if (cmp == -1 || (cmp == 0 && req->oid_ptr->len < mib[i].varbind.oid_ptr->len)) {
                /* free the request oid list */
                oid_free(req->oid_ptr);
                req->oid_ptr = oid_copy(mib[i].varbind.oid_ptr, 0);
                CHECK_PTR(req->oid_ptr);
                break;
            }
        } else {
            /* handle tabular object */
            if (cmp == -1 || cmp == 0) {
                /* oid of the first element */
                oid_item_t* tail_ptr;
                if ((tail_ptr = (mib[i].get_next_oid_fnc_ptr)(&mib[i], (cmp == -1 ? 0 : element_n(req->oid_ptr->first_ptr, mib[i].varbind.oid_ptr->len)),
                        cmp == -1 ? 0 : req->oid_ptr->len - mib[i].varbind.oid_ptr->len)) != 0) {
                    /* copy the mib object's oid */
                    oid_item_t* last_ptr;
                    oid_t* new_oid_ptr = oid_copy(mib[i].varbind.oid_ptr, &last_ptr);
                    CHECK_PTR(new_oid_ptr);
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
    }

    if (i == mib_length) {
        snmp_log("mib does not contain next object\n");
        return -1;
    }

    if (mib[i].get_fnc_ptr) {
        if ((mib[i].get_fnc_ptr)(&mib[i], element_n(req->oid_ptr->first_ptr, mib[i].varbind.oid_ptr->len),
                                    req->oid_ptr->len - mib[i].varbind.oid_ptr->len) == -1) {
            snmp_log("can not get the value of the object\n");
            return -1;
        }
    }

    /* copy the value */
    memcpy(&req->value, &mib[i].varbind.value, sizeof(varbind_value_t));
    req->value_type = mib[i].varbind.value_type;
    return i;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Set the value for an object in the MIB.
 */
s8t mib_set(u8t index, varbind_t* req)
{
    if (mib[index].set_fnc_ptr) {
        if ((mib[index].set_fnc_ptr)(&mib[index], 
                element_n(req->oid_ptr->first_ptr, mib[index].varbind.oid_ptr->len),
                req->oid_ptr->len - mib[index].varbind.oid_ptr->len, req->value) == -1) {
            snmp_log("can not set the value of the object\n");
            return -1;
        }
    } else {
        switch (req->value_type) {
            case BER_TYPE_IPADDRESS:
            case BER_TYPE_OCTET_STRING:
                if (mib[index].varbind.value.s_value.ptr) {
                    free(mib[index].varbind.value.s_value.ptr);
                }
                mib[index].varbind.value.s_value.len = req->value.s_value.len;
                mib[index].varbind.value.s_value.ptr = (u8t*)malloc(req->value.s_value.len);
                if (!mib[index].varbind.value.s_value.ptr) {
                    snmp_log("can not allocate memory for a string\n");
                    return -1;
                }
                memcpy(mib[index].varbind.value.s_value.ptr, req->value.s_value.ptr, mib[index].varbind.value.s_value.len);
                break;

            case BER_TYPE_INTEGER:
                mib[index].varbind.value.i_value = req->value.i_value;
                break;

            case BER_TYPE_COUNTER:
            case BER_TYPE_TIME_TICKS:
            case BER_TYPE_GAUGE:
                mib[index].varbind.value.u_value = req->value.u_value;
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

/*-----------------------------------------------------------------------------------*/
/*
 * Initialize the MIB.
 */
s8t mib_init()
{
    const u32t tconst = 12345678;
    if (add_scalar(oid_system, 1, BER_TYPE_OCTET_STRING, 0, &getSysDescr, &setSysDescr) == -1 ||
        add_scalar(oid_system, 3, BER_TYPE_TIME_TICKS, 0, &getTimeTicks, 0) == -1  ||
        add_scalar(oid_system, 11, BER_TYPE_OCTET_STRING, "Pointer to a string", 0, 0) == -1 ||
        add_scalar(oid_system, 13, BER_TYPE_TIME_TICKS, &tconst, 0, 0) == -1) {
        return -1;
    }

    if (add_scalar(oid_if, 1, BER_TYPE_INTEGER, 0, &getIfNumber, 0) == -1) {
        return -1;
    }

    if (add_table(oid_if_table, &getIf, &getNextIfOid, 0) == -1) {
        return -1;
    }

    if (add_scalar(oid_test, 1, BER_TYPE_INTEGER, 0, 0, 0) == -1 ||
       add_scalar(oid_test, 2, BER_TYPE_GAUGE, 0, 0, 0) == -1) {
        return -1;
    }

    return 0;
}