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
#include <stdlib.h>

#include "ber.h"
#include "logging.h"
#include "utils.h"


#define DECN(pos, value) (*pos) -= value; if (*pos < 0) { snmp_log("too big message: %d\n", __LINE__); return -1;}

#define DEC(pos) DECN(pos, 1)

#define TRY(c) if (c < 0) { snmp_log("exception line: %d\n", __LINE__); return c; }

#define CHECK_PTR(ptr) if (!ptr) { snmp_log("can not allocate memory, line: %d\n", __LINE__); return ERR_MEMORY_ALLOCATION; }

/** \brief ber encoded value. */
typedef struct {
    u8t* buffer;
    u8t len;
} ber_value_t;

/** \brief NULL value of the variable binding. */
static const ber_value_t ber_void_null = {(u8t*)"\x05\x00", 2};

/* static variables shared between functions to save memory. */
static u16t s_length;

static u8t s_type;

static s8t s_ret;

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded SNMP message.
 */
s8t ber_decode_type(const u8t* const input, const u16t len, u16t* pos, u8t* type)
{
    if (*pos < len) {
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
            case BER_TYPE_TIME_TICKS:
            case BER_TYPE_OPAQUE:
            case BER_TYPE_NASAPADDRESS:
            case BER_TYPE_COUNTER64:
            case BER_TYPE_GAUGE:
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
        snmp_log("unexpected end of the SNMP request (pos=%d, len=%d) [1]\n", *pos, len);
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded length field.
 */
s8t ber_decode_length(const u8t* const input, const u16t len, u16t* pos, u16t* length)
{
    if (*pos < len) {
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
                if (*pos < len) {
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
 * Decode BER encoded type and length fields.
 */
s8t ber_decode_type_length(const u8t* const input, const u16t len, u16t* pos, u8t* type, u16t* length)
{
    if (ber_decode_type(input, len, pos, type) == -1 || !ber_decode_length(input, len, pos, length) == -1) {
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode BER encoded sequence header.
 */
s8t ber_decode_sequence(const u8t* const input, const u16t len, u16t* pos, u8t is_last)
{
    TRY(ber_decode_type_length(input, len, pos, &s_type, &s_length));
    if (s_type != BER_TYPE_SEQUENCE || (is_last && s_length != (len - *pos))) {
        snmp_log("bad type or length value for an expected sequence: type %02X length %d\n", s_type, s_length);
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded integer value.
 */
s8t ber_decode_integer(const u8t* const input, const u16t len, u16t* pos, s32t* value)
{
    /* type and length */
    TRY(ber_decode_type_length(input, len, pos, &s_type, &s_length));
    if (s_type != BER_TYPE_INTEGER || s_length < 1) {
        snmp_log("bad type or length value for an expected integer: type %02X length %d\n", s_type, s_length);
        return -1;
    }

    /* value */
    if (*pos + s_length - 1 < len) {
        memset(value, (input[*pos] & 0x80) ? 0xFF : 0x00, sizeof (*value));
        while ((s_length)--) {
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
 * Decode a BER encoded integer value.
 */
s8t ber_decode_unsigned_integer(const u8t* const input, const u16t len, u16t* pos, u32t* value)
{
    /* type and length */
    TRY(ber_decode_type_length(input, len, pos, &s_type, &s_length));
    if (s_type != BER_TYPE_GAUGE || s_length < 1) {
        snmp_log("bad type or length value for an expected integer: type %02X length %d\n", s_type, s_length);
        return -1;
    }

    /* type */
    if (*pos + s_length - 1 < len) {
        *value = 0;
        while (s_length--) {
            *value = (*value << 8) | input[*pos];
            *pos = *pos + 1;
        }
    } else {
        snmp_log("can't fetch an unsigned integer: unexpected end of the SNMP request\n");
        return -1;
    }
    return 0;
}


/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded unsigned integer value.
 */
s8t ber_decode_string(const u8t* const input, const u16t len, u16t* pos, u8t** value, u16t* field_len)
{
    TRY(ber_decode_type_length(input, len, pos, &s_type, field_len));
    if (s_type != BER_TYPE_OCTET_STRING) {
        snmp_log("SNMP string must be of type %02X, byt not %02X\n", BER_TYPE_OCTET_STRING, s_type);
        return -1;
    }
    if (*pos + *field_len - 1 < len) {
        *value = (u8t*)malloc(*field_len + 1);
        CHECK_PTR(*value);
        memcpy(*value, &input[*pos], *field_len);
        (*value)[*field_len] = 0;
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
s8t ber_decode_oid(const u8t* const input, const u16t len, u16t* pos, oid_t* o)
{
    TRY(ber_decode_type_length(input, len, pos, &s_type, &s_length));
    if (s_type != BER_TYPE_OID || s_length < 1) {
        snmp_log("bad type or length of the OID: type %02X length %d\n", s_type, s_length);
        return -1;
    }

    if (*pos - 1 < len) {
        oid_item_t *cur_ptr, *prev_ptr;
        /* The first element after the length contains two OID values.
         * The first value can be obtained by dividing this element by 40.
         * The second data element can be obtained by taking the remainder from the previous division.
         */
        if (!(input[*pos] & 0x80)) {
            o->first_ptr = oid_item_list_append(0, input[*pos] / 40);
            CHECK_PTR(o->first_ptr);
            prev_ptr = oid_item_list_append(o->first_ptr, input[*pos] % 40);
            o->len = 2;
            *pos = *pos + 1;
            (s_length)--;
        } else {
            snmp_log("first bit of the oid must not be set\n");
            return -1;
        }

        while (s_length) {
            cur_ptr = oid_item_list_append(prev_ptr, 0);
            o->len++;
            while ((s_length)--) {
                /* Check bit 8 to see of there are more octets that make up this element of the OID.
                 * If bit 8 is set, then multiply the octet by 128 and then add the lower bits to the result.
                 */
                cur_ptr->value = (cur_ptr->value << 7) + (input[*pos] & 0x7F);
                if (input[*pos] & 0x80) {
                    if ((s_length) == 0) {
                        snmp_log("can't fetch an oid: unexpected end of the SNMP input\n");
                        return -1;
                    }
                    *pos = *pos + 1;
                } else {
                    *pos = *pos + 1;
                    break;
                }
            }
            prev_ptr = cur_ptr;
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
s8t ber_decode_void(const u8t* const input, const u16t len, u16t* pos)
{
    TRY(ber_decode_type_length(input, len, pos, &s_type, &s_length));
    if ((s_type == BER_TYPE_NULL && s_length != 0) || (s_type != BER_TYPE_NULL && s_length == 0)) {
        snmp_log("bad type of length of a void value: type %02X length %d\n", s_type, s_length);
        return -1;
    }
    if (*pos + s_length - 1 < len) {
        *pos = *pos + s_length;
    } else {
        snmp_log("can't fetch void: unexpected end of the SNMP request\n");
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded value.
 */
s8t ber_decode_value(const u8t* const input, const u16t len, u16t* pos, u8t* value_type, varbind_value_t* value) {
    if (*pos < len) {
        *value_type = input[*pos];
        switch (input[*pos]) {
            case BER_TYPE_INTEGER:
                TRY(ber_decode_integer(input, len, pos, &value->i_value));
                break;
            case BER_TYPE_IPADDRESS:
            case BER_TYPE_OCTET_STRING:
                TRY(ber_decode_string(input, len, pos, &(value->s_value.ptr), &(value->s_value.len)));
                break;
            case BER_TYPE_NULL:
                TRY(ber_decode_void(input, len, pos));
                break;
            case BER_TYPE_GAUGE:
            case BER_TYPE_TIME_TICKS:
            case BER_TYPE_COUNTER:
                TRY(ber_decode_unsigned_integer(input, len, pos, &value->u_value));
                break;
            case BER_TYPE_OPAQUE:
            case BER_TYPE_OID:
                return -1;
            default:
                snmp_log("unsupported BER type %02X\n", input[*pos]);
                return -1;
        }
    } else {
        snmp_log("unexpected end of the SNMP request (pos=%d, len=%d) [1]\n", *pos, len);
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Parse a BER encoded SNMP request.
 */
s8t ber_decode_pdu(const u8t* const input, const u16t len, u16t* pos, pdu_t* pdu) {
    /* request PDU */
    static u16t length;
    static s32t tmp;

    /* pdu type */
    TRY(ber_decode_type_length(input, len, pos, &pdu->request_type, &length));
    if (length != (len - *pos)) {
        snmp_log("the length of the PDU should be %d, got %d\n", (len - *pos), length);
        return -1;
    }
    snmp_log("request type: %d\n", pdu->request_type);

    /* request-id */
    TRY(ber_decode_integer(input, len, pos, &pdu->request_id));
    snmp_log("request id: %d\n", pdu->request_id);

    /* error-state */
    TRY(ber_decode_integer(input, len, pos, &tmp));
    pdu->error_status = (u8t)tmp;
    snmp_log("error-status: %d\n", pdu->error_status);

    /* error-index */
    TRY(ber_decode_integer(input, len, pos, &tmp));
    pdu->error_index = (u8t)tmp;
    snmp_log("error-index: %d\n", pdu->error_index);

    /* variable-bindings */
    pdu->varbind_index = *pos;
    snmp_log("varbind index %d\n", *pos);
    TRY(ber_decode_sequence(input, len, pos, 1));

    /* variable binding list */
    pdu->varbind_len = 0;
    pdu->varbind_first_ptr = 0;
    varbind_t* cur_ptr = 0;
    while (*pos < len) {
        /* sequence */
        TRY(ber_decode_sequence(input, len, pos, 0));

        if (!pdu->varbind_first_ptr) {
            cur_ptr = pdu->varbind_first_ptr = varbind_list_append(0);
        } else {
            cur_ptr = varbind_list_append(cur_ptr);
        }
        if (!cur_ptr) {
            return ERR_MEMORY_ALLOCATION;
        }
        
        /* OID */
        cur_ptr->oid_ptr = oid_create();
        TRY(ber_decode_oid(input, len, pos, cur_ptr->oid_ptr));

        /* void value */
        TRY(ber_decode_value(input, len, pos, &cur_ptr->value_type, &cur_ptr->value));
        pdu->varbind_len++;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Parse a BER encoded SNMP request.
 */
s8t ber_decode_request(const u8t* const input, const u16t len, message_t* request)
{
    static u16t pos, length;
    static s32t tmp;

    pos = 0;

    /* Sequence */
    TRY(ber_decode_sequence(input, len, &pos, 1));

    /* version */
    TRY(ber_decode_integer(input, len, &pos, &tmp));
    request->version = (u8t)tmp;
    if (request->version != SNMP_VERSION_1 && request->version != SNMP_VERSION_2C) {
        /* it then verifies the version number of the SNMP message.  */
        /* if there is no mismatch, it discards the datagram and performs no further actions. */
        snmp_log("unsupported SNMP version %d\n", request->version);
        return -1;
    }
    snmp_log("snmp version: %d\n", request->version);

    /* community name */
    if (ber_decode_string((u8t*)input, len, &pos, &request->community, &length) == -1) {
        return -1;
    } else if (strlen((char*)request->community) < 1) {
        snmp_log("unsupported SNMP community '%s'\n", request->community);
        return -1;
    }
    snmp_log("community string: %s\n", request->community);

    /* PDU encoding */
    s_ret = ber_decode_pdu(input, len, &pos, &request->pdu);
    TRY(s_ret);

    snmp_log("parsing finished: OK\n");

    return 0;
}


/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded length to the buffer
 */
s8t ber_encode_length(u8t* output, s16t* pos, u16t length)
{
    if (length > 0xFF) {
        DECN(pos, 3);
        /* first "the length of the length" goes in octets */
        /* the bit 0x80 of the first byte is set to show that the length is composed of multiple octets */
        output[*pos] = 0x82;
        output[*pos + 1] = (length >> 8) & 0xFF;
        output[*pos + 2] = length & 0xFF;
    } else if (length > 0x7F) {
        DECN(pos, 2);
        output[*pos] = 0x81;
	output[*pos + 1] = length & 0xFF;
    } else {
        DEC(pos);
        output[*pos] = length & 0x7F;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded variable binding to the buffer
 */
s8t ber_encode_type_length(u8t* output, s16t* pos, u8t type, u16t len)
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
s8t ber_encode_oid(u8t* output, s16t* pos, oid_t* const  oid)
{
    static u8t length;
    static u8t i;
    static s8t j;
    static u16t oid_length;
    /* reverse order, since we encode from the end */
    oid->first_ptr = oid_item_list_reverse(oid->first_ptr);
    oid_length = 1;
    oid_item_t *cur_ptr = oid->first_ptr;
    /* encode oids from the last to the 2nd */
    for (i = oid->len; i > 2; i--) {
        if (cur_ptr->value >= (268435456)) { // 2 ^ 28
            length = 5;
        } else if (cur_ptr->value >= (2097152)) { // 2 ^ 21
            length = 4;
        } else if (cur_ptr->value >= 16384) { // 2 ^ 14
            length = 3;
        } else if (cur_ptr->value >= 128) { // 2 ^ 7
            length = 2;
        } else {
            length = 1;
        }
        oid_length += length;
        DECN(pos,  length);
        for (j = length - 1; j >= 0; j--) {
            if (j) {
                output[*pos + length - j - 1] = ((cur_ptr->value >> (7 * j)) & 0x7F) | 0x80;
            } else {
                output[*pos + length - j - 1] = ((cur_ptr->value >> (7 * j)) & 0x7F);
            }
        }
        cur_ptr = cur_ptr->next_ptr;
    }
    /* the value of the first 2 oid elements are enconded in the first byte as = 40 * 1st + 2nd */
    DEC(pos);
    output[*pos] = cur_ptr->next_ptr->value * 40 + cur_ptr->value;

    /* type and length */
    TRY(ber_encode_type_length(output, pos, BER_TYPE_OID, oid_length));

    return 0;
}


/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded integer to the buffer
 */
s8t ber_encode_integer(u8t* output, s16t* pos, const s32t value)
{
    s16t init_pos = *pos;
    u16t length;
    s8t j;

    /* get the length of the BER encoded integer value in bytes */
    if (value < -16777216 || value > 16777215) {
        length = 4;
    } else if (value < -32768 || value > 32767) {
        length = 3;
    } else if (value < -128 || value > 127) {
        length = 2;
    } else {
        length = 1;
    }

    /* write integer value */
    DECN(pos, length);
    for (j = length - 1; j >= 0; j--) {
        output[*pos + (length - 1) - j] = (((u32t)value) >> (8 * j)) & 0xFF;
    }

    /* write type and length */
    length = init_pos - *pos;
    TRY(ber_encode_type_length(output, pos, BER_TYPE_INTEGER, length));

    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded unsigned integer to the buffer
 */
s8t ber_encode_unsigned_integer(u8t* output, s16t* pos, const u8t type, const u32t value)
{
    s16t init_pos = *pos;
    u16t length;
    s8t j;

    /* get the length of the BER encoded integer value in bytes */
    if (value & 0xFF000000) {
        length = 4;
    } else if (value & 0x00FF0000) {
        length = 3;
    } else if (value & 0x0000FF00) {
        length = 2;
    } else {
        length = 1;
    }

    /* write integer value */
    DECN(pos, length);
    for (j = length - 1; j >= 0; j--) {
        output[*pos + (length - 1) - j] = (value >> (8 * j)) & 0xFF;
    }

    /* write type and length */
    length = init_pos - *pos;
    TRY(ber_encode_type_length(output, pos, type, length));

    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded string value to the buffer
 */
s8t ber_encode_fixed_string(u8t* output, s16t* pos, const u8t* const str_value, const u16t len)
{
    /* string value */
    DECN(pos, len);
    memcpy(output + *pos, str_value, len);

    /* type and length */
    TRY(ber_encode_type_length(output, pos, BER_TYPE_OCTET_STRING, len));

    return 0;
}


/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded string value to the buffer
 */
s8t ber_encode_string(u8t* output, s16t* pos, const u8t* const str_value)
{
    return ber_encode_fixed_string(output, pos, str_value, strlen((char*)str_value));
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded variable binding to the buffer
 */
s8t ber_encode_var_bind(u8t* output, s16t* pos, const varbind_t* const varbind)
{
    /* write the variable binding in the reverse order */
    u16t len_pos = *pos;
    /* value */
    switch (varbind->value_type) {
        case BER_TYPE_OCTET_STRING:
            TRY(ber_encode_fixed_string(output, pos, varbind->value.s_value.ptr, varbind->value.s_value.len));
            break;

        case BER_TYPE_INTEGER:
            TRY(ber_encode_integer(output, pos, varbind->value.i_value));
            break;

        case BER_TYPE_NULL:
            DECN(pos, ber_void_null.len);
            memcpy(output + (*pos), ber_void_null.buffer, ber_void_null.len);
            break;
        case BER_TYPE_OID:
            /* TODO: implement */
            break;
        case BER_TYPE_COUNTER:
        case BER_TYPE_GAUGE:
        case BER_TYPE_TIME_TICKS:
            TRY(ber_encode_unsigned_integer(output, pos, varbind->value_type, varbind->value.u_value));
            break;
        default:
            break;
    }
    /* oid */
    TRY(ber_encode_oid(output, pos, varbind->oid_ptr));

    /* sequence header*/
    len_pos -= *pos;
    TRY(ber_encode_type_length(output, pos, BER_TYPE_SEQUENCE, len_pos));
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Encode SNMP PDU
 */
s8t ber_encode_pdu(u8t* output, s16t* pos, const u8t* const input, u16t input_len, const pdu_t* const  pdu, const u16t max_output_len)
{
    s32t tmp;
    u16t len;
    /* write in the reverse order */

    if (pdu->error_status == ERROR_STATUS_NO_ERROR) {
        /* variable binding list */
        varbind_t* ptr = pdu->varbind_first_ptr;
        while (ptr) {
            TRY(ber_encode_var_bind(output, pos, ptr));
            ptr = ptr->next_ptr;
        }
        u16t len = max_output_len - *pos;
        TRY(ber_encode_type_length(output, pos, BER_TYPE_SEQUENCE, len));
    } else {
        DECN(pos, (input_len - pdu->varbind_index));
        memcpy(&output[*pos], &input[pdu->varbind_index], input_len - pdu->varbind_index);
    }

    /* error index */
    tmp = pdu->error_index;
    TRY(ber_encode_integer(output, pos, tmp));
    /* error status */
    tmp = pdu->error_status;
    TRY(ber_encode_integer(output, pos, tmp));
    /* request id */
    TRY(ber_encode_integer(output, pos, pdu->request_id));

    /* sequence header*/
    len = max_output_len - *pos;
    TRY(ber_encode_type_length(output, pos, BER_TYPE_SNMP_RESPONSE, len));

    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Encode an SNMP response in BER
 */
s8t ber_encode_response(const message_t* const message, u8t* output, u16t* output_len, const u8t* const input, u16t input_len, const u16t max_output_len)
{
    s32t tmp;
    s16t pos = max_output_len;
    ber_encode_pdu(output, &pos, input, input_len, &message->pdu, max_output_len);

    /* community string */
    TRY(ber_encode_string(output, &pos, message->community));
    /* version */
    tmp = message->version;
    TRY(ber_encode_integer(output, &pos, tmp));

    /* sequence header*/
    u16t len = max_output_len - pos;
    TRY(ber_encode_type_length(output, &pos, BER_TYPE_SEQUENCE, len));

    *output_len = max_output_len - pos;
    if (pos > 0) {
        memmove(output, output + pos, *output_len);
    }
    return 0;
}

