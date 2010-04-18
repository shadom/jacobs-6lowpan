#include "mib-init.h"
#include "ber.h"
#include "utils.h"
#include "logging.h"

/* common oid prefixes ending with 0 */
static const OID_T oid_system[]         = { 1, 3, 6, 1, 2, 1, 1, 0};
static const OID_T oid_if[]     	= { 1, 3, 6, 1, 2, 1, 2, 0};
static const OID_T oid_if_table[]	= { 1, 3, 6, 1, 2, 1, 2, 2, 1, 0};
static const OID_T oid_test[]           = { 1, 3, 6, 1, 2, 1, 1234, 0};

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
    if (len != 2) {
        return -1;
    }
    switch (oid_item->value) {
        case ifIndex:
            object->varbind.value_type = BER_TYPE_INTEGER;
            if (0 < oid_item->next_ptr->value && oid_item->next_ptr->value <= ifNumber) {
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