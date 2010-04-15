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


static const oid_t oid_system	= { { 1, 3, 6, 1, 2, 1, 1}, 7};
static const oid_t oid_if	= { { 1, 3, 6, 1, 2, 1, 2}, 7};
static const oid_t oid_if_table	= { { 1, 3, 6, 1, 2, 1, 2, 2, 1}, 9};
static const oid_t oid_test	= { { 1, 3, 6, 1, 2, 1, 1234}, 7};

typedef struct mib_object_t mib_object_t;

/*
 *  Function types to treat tabular structures
 */
typedef s8t (*get_value_t)(mib_object_t* object, OID_T* oid, u16t len);
typedef s8t (*get_next_oid_t)(OID_T* oid, u8t len, u16t* res_len);
typedef s8t (*set_value_t)(mib_object_t* object, OID_T* oid, u16t len, varbind_value_t value);

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
s8t getSysDescr(mib_object_t* object, OID_T* oid, u16t len)
{
    if (!object->varbind.value.s_value.len) {
        object->varbind.value.s_value.ptr = (u8t*)"System Description";
        object->varbind.value.s_value.len = 18;
    }
    return 0;
}

s8t setSysDescr(mib_object_t* object, OID_T* oid, u16t len, varbind_value_t value)
{
    object->varbind.value.s_value.ptr = (u8t*)"System Description2";
    object->varbind.value.s_value.len = 19;
    return 0;
}

s8t getTimeTicks(mib_object_t* object, OID_T* oid, u16t len)
{
    object->varbind.value.u_value = 1234;
    return 0;
}

/**** IF-MIB ****************/

#define ifNumber 3

s8t getIfNumber(mib_object_t* object, OID_T* oid, u16t len)
{
    object->varbind.value.i_value = ifNumber;
    return 0;
}

#define ifIndex 1

s8t getIf(mib_object_t* object, OID_T* oid, u16t len)
{
    if (len != 2) {
        return -1;
    }
    switch (oid[0]) {
        case ifIndex:
            object->varbind.value_type = BER_TYPE_INTEGER;
            if (0 < oid[1] && oid[1] <= ifNumber) {
                object->varbind.value.i_value = oid[1];
            } else {
                return -1;
            }
            break;
        default:
            break;
    }
    return 0;
}

s8t getNextIfOid(OID_T* oid, u8t len, u16t* res_len)
{
    OID_T oid_el1 = (len > 0 ? oid[0] : 0);
    OID_T oid_el2 = (len > 1 ? oid[1] : 0);

    if (oid_el1 < ifIndex) {
        *res_len = 2;
        oid[0] = ifIndex;
        oid[1] = 1;
        return 0;
    }
    
    if (oid_el1 == ifIndex && oid_el2 < ifNumber) {
        *res_len = 2;
        oid[0] = ifIndex;
        oid[1] = oid_el2 + 1;
        return 0;
    }
    return -1;
}

/***************************************************/

/*-----------------------------------------------------------------------------------*/
/*
 * Adds a scalar to the MIB
 */
s8t add_scalar(const oid_t* prefix, const OID_T object_id, u8t value_type, const void* const value, get_value_t gfp, set_value_t svfp)
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

            case BER_TYPE_OID:
                // TODO: implement
                break;

            case BER_TYPE_COUNTER:
            case BER_TYPE_TIME_TICKS:
            case BER_TYPE_UINTEGER32:
                mib[mib_length].varbind.value.u_value = *((u32t*)value);
                break;
            default:
                break;
        }
    }
    /* construct OID */
    memcpy(mib[mib_length].varbind.oid.values, prefix->values, prefix->len * sizeof(OID_T));
    mib[mib_length].varbind.oid.values[prefix->len] = object_id;
    mib[mib_length].varbind.oid.values[prefix->len + 1] = 0;
    mib[mib_length].varbind.oid.len = prefix->len + 2;

    /* set value type */
    mib[mib_length].varbind.value_type = value_type;

    mib_length++;
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Adds a table to the MIB.
 */
s8t add_table(const oid_t* prefix, get_value_t  gfp, get_next_oid_t gnofp, set_value_t svfp)
{
    /* MIB is full */
    if (mib_length >= MIB_LEN) {
        snmp_log("can't add a new entry to the mib - it's is already full");
        return -1;
    }
    /* copy the oid prefix */
    memcpy(mib[mib_length].varbind.oid.values, prefix->values, prefix->len * sizeof(OID_T));
    mib[mib_length].varbind.oid.len = prefix->len;

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
        if (mib[i].varbind.oid.len == req->oid.len &&
                !memcmp(mib[i].varbind.oid.values, req->oid.values,
                mib[i].varbind.oid.len * sizeof(OID_T))) {
            break;
        } else if (mib[i].get_next_oid_fnc_ptr && mib[i].varbind.oid.len == req->oid.len &&
                !memcmp(mib[i].varbind.oid.values, req->oid.values, mib[i].varbind.oid.len * sizeof(OID_T))) {
            // tabular
            break;
        }

    }
    if (i == mib_length) {
        snmp_log("mib object not found\n");
        return -1;
    }

    if (mib[i].get_fnc_ptr) {
        if ((mib[i].get_fnc_ptr)(&mib[i], &req->oid.values[mib[i].varbind.oid.len], req->oid.len - mib[i].varbind.oid.len) == -1) {
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
        cmp = oid_cmp(&req->oid, &mib[i].varbind.oid);

        if (!mib[i].get_next_oid_fnc_ptr) {
            // handle scalar object
            if (cmp == -1 || (cmp == 0 && req->oid.len < mib[i].varbind.oid.len)) {
                /* copy the oid */
                memcpy(req->oid.values, mib[i].varbind.oid.values, mib[i].varbind.oid.len * sizeof(OID_T));
                req->oid.len = mib[i].varbind.oid.len;
                break;
            }
        } else {
            /* handle tabular object */
            if (cmp == -1 || cmp == 0) {
                /* oid of the first element */
                if ((mib[i].get_next_oid_fnc_ptr)(&req->oid.values[mib[i].varbind.oid.len],
                        (req->oid.len < mib[i].varbind.oid.len ? 0 : req->oid.len - mib[i].varbind.oid.len), &req->oid.len) != -1) {
                    memcpy(req->oid.values, mib[i].varbind.oid.values, mib[i].varbind.oid.len * sizeof(OID_T));
                    req->oid.len += mib[i].varbind.oid.len;
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
        if ((mib[i].get_fnc_ptr)(&mib[i], &req->oid.values[mib[i].varbind.oid.len], req->oid.len - mib[i].varbind.oid.len) == -1) {
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
                &req->oid.values[mib[index].varbind.oid.len],
                req->oid.len - mib[index].varbind.oid.len, req->value) == -1) {
            snmp_log("can not set the value of the object\n");
            return -1;
        }
    } else {
        switch (req->value_type) {
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

            case BER_TYPE_OID:
                /* TODO: implement */
                return -1;
            case BER_TYPE_COUNTER:
            case BER_TYPE_TIME_TICKS:
            case BER_TYPE_UINTEGER32:
                mib[index].varbind.value.u_value = req->value.u_value;
                break;
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
    if (add_scalar(&oid_system, 1, BER_TYPE_OCTET_STRING, 0, &getSysDescr, &setSysDescr) == -1 ||
        add_scalar(&oid_system, 3, BER_TYPE_TIME_TICKS, 0, &getTimeTicks, 0) == -1  ||
        add_scalar(&oid_system, 11, BER_TYPE_OCTET_STRING, "Pointer to a string", 0, 0) == -1 ||
        add_scalar(&oid_system, 13, BER_TYPE_TIME_TICKS, &tconst, 0, 0) == -1) {
        return -1;
    }

    if (add_scalar(&oid_if, 1, BER_TYPE_INTEGER, 0, &getIfNumber, 0) == -1) {
        return -1;
    }

    if (add_table(&oid_if_table, &getIf, &getNextIfOid, 0) == -1) {
        return -1;
    }

    if (add_scalar(&oid_test, 1, BER_TYPE_INTEGER, 0, 0, 0) == -1 ||
       add_scalar(&oid_test, 2, BER_TYPE_UINTEGER32, 0, 0, 0) == -1) {
        return -1;
    }

    return 0;
}