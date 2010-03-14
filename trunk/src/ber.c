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
#include <string.h>

#include "ber.h"
#include "logging.h"

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded SNMP message.
 */
s8t ber_decode_type(const u8t* const input, const u16t* const len, u16t* pos, u8t* type)
{
    if (*pos < *len) {
        switch (input[*pos]) {
            case BER_TYPE_BOOLEAN:
            case BER_TYPE_INTEGER:
            case BER_TYPE_BIT_STRING:
            case BER_TYPE_OCTET_STRING:
            case BER_TYPE_NULL:
            case BER_TYPE_OID:
            case BER_TYPE_SEQUENCE:
            case BER_TYPE_IPADDRESS:
            case BER_TYPE_COUNTER:
            case BER_TYPE_GAUGE:
            case BER_TYPE_TIME_TICKS:
            case BER_TYPE_OPAQUE:
            case BER_TYPE_NASAPADDRESS:
            case BER_TYPE_COUNTER64:
            case BER_TYPE_UINTEGER32:
            case BER_TYPE_NO_SUCH_OBJECT:
            case BER_TYPE_NO_SUCH_INSTANCE:
            case BER_TYPE_END_OF_MIB_VIEW:
            case BER_TYPE_SNMP_GET:
            case BER_TYPE_SNMP_GETNEXT:
            case BER_TYPE_SNMP_RESPONSE:
            case BER_TYPE_SNMP_SET:
            case BER_TYPE_SNMP_GETBULK:
            case BER_TYPE_SNMP_INFORM:
            case BER_TYPE_SNMP_TRAP:
                *type = input[*pos];
                *pos = *pos + 1;
                break;
            default:
                snmp_log("unsupported BER type %02X\n", input[*pos]);
                return -1;
        }
    } else {
        snmp_log("unexpected end of the SNMP request (pos=%d, len=%d) [1]\n", *pos, *len);
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded length field.
 */
s8t ber_decode_length(const u8t* const input, const u16t* const len, u16t* pos, u16t* length)
{
    if (*pos < *len) {
        /* length is encoded in a single length byte */
        if (!(input[*pos] & 0x80)) {
            *length = input[*pos];
            *pos = *pos + 1;
        } else {
            /* constructed, definite-length method or indefinite-length method is used */
            u8t size_of_length = input[*pos] & 0x7F;
            *pos = *pos + 1;
            /* the length only up to 2 octets is supported*/
            if (size_of_length > 2) {
                snmp_log("unsupported value of the length field occurs (must be up to 2 bytes)");
                return 1;
            }
            *length = 0;
            while (size_of_length--) {
                if (*pos < *len) {
                    *length = (*length << 8) + input[*pos];
                    *pos = *pos + 1;
                } else {
                    snmp_log("can't fetch length, unexpected end of the SNMP request [2]\n");
                    return -1;
                }
            }
        }
    } else {
        snmp_log("can't fetch length, unexpected end of the SNMP request [3]\n");
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded integer value.
 */
s8t ber_decode_integer_value(const u8t* const input, const u16t* const len, u16t* pos, u16t* field_len, s32t* value)
{
    if (*pos + *field_len - 1 < *len) {
        memset(value, (input[*pos] & 0x80) ? 0xFF : 0x00, sizeof (*value));
        while ((*field_len)--) {
            *value = (*value << 8) + input[*pos];
            *pos = *pos + 1;
        }
    } else {
        snmp_log("can't fetch an integer: unexpected end of the SNMP request\n");
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded unsigned integer value.
 */
s8t ber_decode_string(const u8t* const input, const u16t* const len, u16t* pos, u16t* field_len, u8t* value, u8t value_len)
{
    if (*pos + *field_len - 1 < *len) {
        memcpy(value, &input[*pos], *field_len);
        value[*field_len] = 0;
        *pos = *pos + *field_len;
    } else {
        snmp_log("can't fetch an octet string: unexpected end of the SNMP input\n");
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded OID.
 */
s8t ber_decode_oid(const u8t* const input, const u16t* const len, u16t* pos, u16t* field_len, oid_t* o )
{
    if (*pos + *field_len -1 < *len) {
        o->len = 0;
        /* The first element after the length contains two OID values.
         * The first value can be obtained by dividing this element by 40.
         * The second data element can be obtained by taking the remainder from the previous division.
         */
        if (!(input[*pos] & 0x80)) {
            o->values[o->len++] = input[*pos] / 40;
            o->values[o->len++] = input[*pos] % 40;
            *pos = *pos + 1;
            (*field_len)--;
        } else {
            snmp_log("first bit of the oid must not be set\n");
            return -1;
        }

        while (*field_len) {
            if (o->len < OID_LEN) {
                o->values[o->len] = 0;
            } else {
                snmp_log("oid contains too many elements (max=%d)\n", OID_LEN);
                return -1;
            }
            while ((*field_len)--) {
                /* Check bit 8 to see of there are more octets that make up this element of the OID.
                 * If bit 8 is set, then multiply the octet by 128 and then add the lower bits to the result.
                 */
                o->values[o->len] = (o->values[o->len] << 7) + (input[*pos] & 0x7F);
                if (input[*pos] & 0x80) {
                    if ((*field_len) == 0) {
                        snmp_log("can't fetch an oid: unexpected end of the SNMP input\n");
                        return -1;
                    }
                    *pos = *pos + 1;
                } else {
                    *pos = *pos + 1;
                    break;
                }
            }
            o->len++;
        }
    } else {
        snmp_log("can't fetch an oid: unexpected end of the SNMP request\n");
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded void value.
 */
s8t ber_decode_void(const u8t* const input, const u16t* const len, u16t* pos, u16t* field_len)
{
    if (*pos + *field_len - 1 < *len) {
        *pos = *pos + *field_len;
    } else {
        snmp_log("can't fetch void: unexpected end of the SNMP request\n");
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded length to the buffer
 */
s8t ber_encode_length(u8t* output, s16t* pos, u16t* length)
{
    if (*length > 0xFF) {
        DECN(pos, 3);
        /* first "the length of the length" goes in octets */
        /* the bit 0x80 of the first byte is set to show that the length is composed of multiple octets */
        output[*pos] = 0x82;
        output[*pos + 1] = ((*length) >> 8) & 0xFF;
        output[*pos + 2] = (*length) & 0xFF;
    } else if (*length > 0x7F) {
        DECN(pos, 2);
        output[*pos] = 0x81;
	output[*pos + 1] = (*length) & 0xFF;
    } else {
        DEC(pos);
        output[*pos] = (*length) & 0x7F;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded variable binding to the buffer
 */
s8t ber_encode_type_length(u8t* output, s16t* pos, u8t type, u16t *len)
{
    TRY(ber_encode_length(output, pos, len));
    DEC(pos);
    output[*pos] = type;
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded oid to the buffer
 */
s8t ber_encode_oid(u8t* output, s16t* pos, oid_t* oid)
{
    static u8t length;
    static u8t i;
    static s8t j;
    static u16t oid_length;

    oid_length = 1;

    /* encode oids from the last to the 2nd */
    for (i = oid->len - 1; i >= 2; i--) {
        if (oid->values[i] >= (268435456)) { // 2 ^ 28
            length = 5;
        } else if (oid->values[i] >= (2097152)) { // 2 ^ 21
            length = 4;
        } else if (oid->values[i] >= 16384) { // 2 ^ 14
            length = 3;
        } else if (oid->values[i] >= 128) { // 2 ^ 7
            length = 2;
        } else {
            length = 1;
        }
        oid_length += length;
        DECN(pos,  length);
        for (j = length - 1; j >= 0; j--) {
            if (j) {
                output[*pos + length - j - 1] = ((oid->values[i] >> (7 * j)) & 0x7F) | 0x80;
            } else {
                output[*pos + length - j - 1] = ((oid->values[i] >> (7 * j)) & 0x7F);
            }
        }
    }
    /* the value of the first 2 oid elements are enconded in the first byte as = 40 * 1st + 2nd */
    DEC(pos);
    output[*pos] = oid->values[0] * 40 + oid->values[1];

    /* type and length */
    TRY(ber_encode_type_length(output, pos, BER_TYPE_OID, &oid_length));

    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded variable binding to the buffer
 */
s8t ber_encode_var_bind(u8t* output, s16t* pos, varbind_t* varbind)
{
    /* write the variable binding in the reverse order */
    u16t len_pos = *pos;
    /* value */
    DECN(pos, varbind->value.len);
    memcpy(output + (*pos), varbind->value.buffer, varbind->value.len);

    /* oid */
    TRY(ber_encode_oid(output, pos, &varbind->oid));
    /* sequence header*/
    len_pos -= *pos;
    TRY(ber_encode_type_length(output, pos, BER_TYPE_SEQUENCE, &len_pos));

    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded integer to the buffer
 */
s8t ber_encode_integer(u8t* output, s16t* pos, s32t* value)
{
    s16t init_pos = *pos;
    u16t length;
    s8t j;

    /* get the length of the BER encoded integer value in bytes */
    if (*value < -16777216 || *value > 16777215) {
        length = 4;
    } else if (*value < -32768 || *value > 32767) {
        length = 3;
    } else if (*value < -128 || *value > 127) {
        length = 2;
    } else {
        length = 1;
    }

    /* write integer value */
    DECN(pos, length);
    for (j = length - 1; j >= 0; j--) {
        output[*pos + (length - 1) - j] = (((u32t)*value) >> (8 * j)) & 0xFF;
    }

    /* write type and length */
    length = init_pos - *pos;
    TRY(ber_encode_type_length(output, pos, BER_TYPE_INTEGER, &length));

    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded string value to the buffer
 */
s8t ber_encode_string(u8t* output, s16t* pos, u8t* str_value)
{
    /* string value */
    u16t len = strlen((char*)str_value);
    DECN(pos, len);
    memcpy(output + *pos, str_value, len);

    /* type and length */
    TRY(ber_encode_type_length(output, pos, BER_TYPE_OCTET_STRING, &len));

    return 0;
}
