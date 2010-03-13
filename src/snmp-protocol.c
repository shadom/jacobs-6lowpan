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
#include <stdio.h>

#include "snmp-protocol.h"
#include "snmp-conf.h"
#include "snmpd-logging.h"

/*
 * BER identifiers for ASN.1 implementation of SNMP.
 */
#define BER_TYPE_BOOLEAN                                0x01
#define BER_TYPE_INTEGER                                0x02
#define BER_TYPE_BIT_STRING                             0x03
#define BER_TYPE_OCTET_STRING                           0x04
#define BER_TYPE_NULL                                   0x05
#define BER_TYPE_OID                                    0x06
#define BER_TYPE_SEQUENCE                               0x30
#define BER_TYPE_IPADDRESS                              0x40
#define BER_TYPE_COUNTER                                0x41
#define BER_TYPE_GAUGE                                  0x42
#define BER_TYPE_TIME_TICKS				0x43
#define BER_TYPE_OPAQUE                                 0x44
#define BER_TYPE_NASAPADDRESS                           0x45
#define BER_TYPE_COUNTER64                              0x46
#define BER_TYPE_UINTEGER32                             0x47
#define BER_TYPE_NO_SUCH_OBJECT                         0x80
#define BER_TYPE_NO_SUCH_INSTANCE                       0x81
#define BER_TYPE_END_OF_MIB_VIEW                        0x82
#define BER_TYPE_SNMP_GET                               0xA0
#define BER_TYPE_SNMP_GETNEXT                           0xA1
#define BER_TYPE_SNMP_RESPONSE                          0xA2
#define BER_TYPE_SNMP_SET                               0xA3
#define BER_TYPE_SNMP_GETBULK                           0xA5
#define BER_TYPE_SNMP_INFORM                            0xA6
#define BER_TYPE_SNMP_TRAP                              0xA7
#define BER_TYPE_SNMP_REPORT                            0xA8

#define SNMP_VERSION_1					0
#define SNMP_VERSION_2C					1


#define ERROR_STATUS_NO_ERROR					0
#define ERROR_STATUS_TOO_BIG				1
#define ERROR_STATUS_NO_SUCH_NAME			2
#define ERROR_STATUS_BAD_VALUE				3
#define ERROR_STATUS_READ_ONLY				4
#define ERROR_STATUS_GEN_ERR				5
#define ERROR_STATUS_NO_ACCESS				6
#define ERROR_STATUS_WRONG_TYPE				7
#define ERROR_STATUS_WRONG_LENGTH			8
#define ERROR_STATUS_WRONG_ENCODING			9
#define ERROR_STATUS_WRONG_VALUE				10
#define ERROR_STATUS_NO_CREATION				11
#define ERROR_STATUS_INCONSISTENT_VALUE                  12
#define ERROR_STATUS_RESOURCE_UNAVAILABLE                13
#define ERROR_STATUS_COMMIT_FAILED			14
#define ERROR_STATUS_UNDO_FAILED				15
#define ERROR_STATUS_AUTHORIZATION_ERROR                 16
#define ERROR_STATUS_NOT_WRITABLE			17
#define ERROR_STATUS_INCONSISTENT_NAME                   18

#define DECN(pos, value) (*pos) -= value; if (*pos < 0) { snmp_log("too big message: %d", __LINE__); return -1;}

#define DEC(pos) DECN(pos, 1)

#define TRY(c) if (c == -1) { return -1; }


typedef struct {
    u16_t values[OID_LEN];
    u8_t len;
} oid_t;

typedef struct {
    u8_t buffer[VAR_BIND_VALUE_LEN];
    u8_t len;
} varbind_value_t;

typedef struct {
    oid_t oid;
    varbind_value_t value;
} varbind_t;

static const varbind_value_t varbind_t_null = {"\x05\x00", 2};

typedef struct {
    u8_t version;
    u8_t community[COMMUNITY_STRING_LEN];
    u8_t request_type;
    s32_t request_id;
    u8_t error_status;
    u8_t error_index;
    u8_t var_bind_list_len;
    oid_t var_bind_list[VAR_BIND_LEN];
} request_t;

typedef struct {
    u8_t error_status;
    u8_t error_index;
    u8_t var_bind_list_len;
    varbind_t var_bind_list[VAR_BIND_LEN];
} response_t;

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded SNMP message.
 */
static s8_t fetch_type(const u8_t* const request, const u16_t* const len, u16_t* pos, u8_t* type)
{
    if (*pos < *len) {
        switch (request[*pos]) {
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
                *type = request[*pos];
                *pos = *pos + 1;
                break;
            default:
                snmp_log("unsupported BER type %02X\n", request[*pos]);
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
static s8_t fetch_length(const u8_t* const request, const u16_t* const len, u16_t* pos, u16_t* length)
{
    if (*pos < *len) {
        /* length is encoded in a single length byte */
        if (!(request[*pos] & 0x80)) {
            *length = request[*pos];
            *pos = *pos + 1;
        } else {
            /* constructed, definite-length method or indefinite-length method is used */
            u8_t size_of_length = request[*pos] & 0x7F;
            *pos = *pos + 1;
            /* the length only up to 2 octets is supported*/
            if (size_of_length > 2) {
                snmp_log("unsupported value of the length field occurs (must be up to 2 bytes)");
                return 1;
            }
            *length = 0;
            while (size_of_length--) {
                if (*pos < *len) {
                    *length = (*length << 8) + request[*pos];
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
static s8_t fetch_integer_value(const u8_t* const request, const u16_t* const len, u16_t* pos, u16_t* field_len, s32_t* value)
{
    if (*pos + *field_len - 1 < *len) {
        memset(value, (request[*pos] & 0x80) ? 0xFF : 0x00, sizeof (*value));
        while ((*field_len)--) {
            *value = (*value << 8) + request[*pos];
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
static s8_t fetch_octet_string(const u8_t* const request, const u16_t* const len, u16_t* pos, u16_t* field_len, u8_t* value, u8_t value_len)
{
    if (*pos + *field_len - 1 < *len) {
        memcpy(value, &request[*pos], *field_len);
        value[*field_len] = 0;
        *pos = *pos + *field_len;
    } else {
        snmp_log("can't fetch an octet string: unexpected end of the SNMP request\n");
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded OID.
 */
static s8_t fetch_oid(const u8_t* const request, const u16_t* const len, u16_t* pos, u16_t* field_len, oid_t* o )
{
    if (*pos + *field_len -1 < *len) {
        o->len = 0;
        /* The first element after the length contains two OID values.
         * The first value can be obtained by dividing this element by 40.
         * The second data element can be obtained by taking the remainder from the previous division.
         */
        if (!(request[*pos] & 0x80)) {
            o->values[o->len++] = request[*pos] / 40;
            o->values[o->len++] = request[*pos] % 40;
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
                o->values[o->len] = (o->values[o->len] << 7) + (request[*pos] & 0x7F);
                if (request[*pos] & 0x80) {
                    if ((*field_len) == 0) {
                        snmp_log("can't fetch an oid: unexpected end of the SNMP request\n");
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
static s8_t fetch_void(const u8_t* const request, const u16_t* const len, u16_t* pos, u16_t* field_len)
{
    if (*pos + *field_len - 1 < *len) {
        *pos = *pos + *field_len;
    } else {
        snmp_log("can't fetch void: unexpected end of the SNMP request\n");
        return -1;
    }
    return 0;
}


#if DEBUG
void log_oid(oid_t* o) {
    s8_t i;
    for (i = 0; i < o->len - 1; i++) {
        printf("%d.", o->values[i]);
    }
    printf("%d\n", o->values[o->len - 1]);
}
#else
#define log_oid(...)
#endif /* DEBUG */

/*-----------------------------------------------------------------------------------*/
/*
 * Parse a BER encoded SNMP request.
 */
s8_t  snmp_parse_request(const u8_t* const input, const u16_t* const len, request_t* request)
{
    static u16_t pos, length;
    static u8_t type;
    static s32_t tmp;
   
    pos = 0;
    
    /* Sequence */
    if (fetch_type(input, len, &pos, &type) == -1 || fetch_length(input, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_SEQUENCE || length != (*len - pos)) {
        snmp_log("bad SNMP header: type %02X length %d\n", type, length);
        return -1;
    }
    
    /* version */
    if (fetch_type(input, len, &pos, &type) == -1 || !fetch_length(input, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_INTEGER || length != 1) {
        snmp_log("bad SNMP version: type %02X length %d\n", type, length);
        return -1;
    } else if (fetch_integer_value(input, len, &pos, &length, &tmp) == -1) {
        return -1;
    }
    request->version = (u8_t)tmp;
    if (request->version != SNMP_VERSION_1 && request->version != SNMP_VERSION_2C) {
        /* it then verifies the version number of the SNMP message.  */
        /* if there is no mismatch, it discards the datagram and performs no further actions. */
        snmp_log("unsupported SNMP version %d\n", request->version);
        return -1;
    }
    snmp_log("snmp version: %d\n", request->version);
    
    /* community name */
    if (fetch_type(input, len, &pos, &type) == -1 || !fetch_length(input, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_OCTET_STRING) {
        snmp_log("SNMP community string must of type %02X, byt not %02X\n", BER_TYPE_OCTET_STRING, type);
        return -1;
    }
    if (length >= COMMUNITY_STRING_LEN) {
        snmp_log("community string is too long (must be up to 31 character)\n");
        return -1;
    }    
    if (fetch_octet_string((u8_t*)input, len, &pos, &length, request->community, COMMUNITY_STRING_LEN) == -1) {
        return -1;
    } else if (strlen((char*)request->community) < 1) {
        snmp_log("unsupported SNMP community '%s'\n", request->community);
        return -1;
    }
    snmp_log("community string: %s\n", request->community);

    /* request PDU */
    if (fetch_type(input, len, &pos, &request->request_type) == -1 || !fetch_length(input, len, &pos, &length) == -1) {
        return -1;
    }

    if (length != (*len - pos)) {
        snmp_log("bad SNMP header: type %02X length %d\n", request->request_type, length);
        return -1;
    }    
    snmp_log("request type: %d\n", request->request_type);

    /* request-id */
    if (fetch_type(input, len, &pos, &type) == -1 || !fetch_length(input, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_INTEGER || length < 1) {
        snmp_log("bad SNMP request-id: type %02X length %d\n", type, length);
        return -1;
    } else if (fetch_integer_value(input, len, &pos, &length, &request->request_id) == -1) {
        return -1;
    }
    snmp_log("request id: %d\n", request->request_id);

    /* error-state */
    if (fetch_type(input, len, &pos, &type) == -1 || !fetch_length(input, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_INTEGER || length < 1) {
        snmp_log("bad SNMP error-status: type %02X length %d\n", type, length);
        return -1;
    } else if (fetch_integer_value(input, len, &pos, &length, &tmp) == -1) {
        return -1;
    }
    request->error_status = (u8_t)tmp;
    snmp_log("error-status: %d\n", request->error_status);

    /* error-index */
    if (fetch_type(input, len, &pos, &type) == -1 || !fetch_length(input, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_INTEGER || length < 1) {
        snmp_log("bad SNMP error-index: type %02X length %d\n", type, length);
        return -1;
    } else if (fetch_integer_value(input, len, &pos, &length, &tmp) == -1) {
        return -1;
    }
    request->error_index = (u8_t)tmp;
    snmp_log("error-index: %d\n", request->error_index);

    /* variable-bindings */
    if (fetch_type(input, len, &pos, &type) == -1 || !fetch_length(input, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_SEQUENCE || length != (*len - pos)) {
        snmp_log("bad SNMP variable binding header length: type %02X length %d\n", type, length);
        return -1;
    }
    /* variable binding list */
    request->var_bind_list_len = 0;
    while (pos < *len) {
        if (request->var_bind_list_len >= VAR_BIND_LEN) {
            snmp_log("maximum number of var bindings in the list is exceeded: max=%d\n", VAR_BIND_LEN);
            return -1;
        }
        
        /* sequence */
        if (fetch_type(input, len, &pos, &type) == -1 || !fetch_length(input, len, &pos, &length) == -1) {
            return -1;
        }
        if (type != BER_TYPE_SEQUENCE || length < 1) {
            snmp_log("bad SNMP variable binding: type %02X length %d\n", type, length);
            return -1;
        }
        
        /* OID */
        if (fetch_type(input, len, &pos, &type) == -1 || !fetch_length(input, len, &pos, &length) == -1) {
            return -1;
        }
        if (type != BER_TYPE_OID || length < 1) {
            snmp_log("bad SNMP varbinding OID: type %02X length %d\n", type, length);
            return -1;
        }
        if (fetch_oid(input, len, &pos, &length, &request->var_bind_list[request->var_bind_list_len]) == -1) {
            return -1;
        }
        /* value */
        if (fetch_type(input, len, &pos, &type) == -1 || !fetch_length(input, len, &pos, &length) == -1) {
            return -1;
        }
        if ((type == BER_TYPE_NULL && length != 0) || (type != BER_TYPE_NULL && length == 0)) {
            snmp_log("bad SNMP varbinding value: type %02X length %d\n", type, length);
            return -1;
        } else if (fetch_void(input, len, &pos, &length) == -1) {
            return -1;
        }
        log_oid(&request->var_bind_list[request->var_bind_list_len]);
        request->var_bind_list_len++;
    }

    snmp_log("parsing finished: OK\n");

    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Handle an SNMP GET request
 */
s8_t snmp_handle_get(request_t* request, response_t* response)
{
    response->error_status = ERROR_STATUS_GEN_ERR;
    response->error_index = 1;
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded length to the buffer
 */
static s8_t write_length(u8_t* output, s16_t* pos, u16_t* length) {
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
s8_t write_type_length(u8_t* output, s16_t* pos, u8_t type, u16_t *len)
{
    write_length(output, pos, len);
    DEC(pos);
    output[*pos] = type;
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded oid to the buffer
 */
static s8_t write_oid(u8_t* output, s16_t* pos, oid_t* oid)
{
    static u8_t length;
    static u8_t i;
    static s8_t j;
    static u16_t oid_length;

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
    TRY(write_type_length(output, pos, BER_TYPE_OID, &oid_length));

    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded variable binding to the buffer
 */
s8_t write_var_bind(u8_t* output, s16_t* pos, varbind_t* varbind)
{
    /* write the variable binding in the reverse order */
    u16_t len_pos = *pos;
    /* value */
    DECN(pos, varbind->value.len);
    memcpy(output + (*pos), varbind->value.buffer, varbind->value.len);

    /* oid */
    TRY(write_oid(output, pos, &varbind->oid));
    /* sequence header*/
    len_pos -= *pos;
    TRY(write_type_length(output, pos, BER_TYPE_SEQUENCE, &len_pos));
            
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded integer to the buffer
 */
s8_t write_integer(u8_t* output, s16_t* pos, s32_t* value)
{
    s16_t init_pos = *pos;
    u16_t length;
    s8_t j;

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
        output[*pos + (length - 1) - j] = (((u32_t)*value) >> (8 * j)) & 0xFF;
    }

    /* write type and length */
    length = init_pos - *pos;
    TRY(write_type_length(output, pos, BER_TYPE_INTEGER, &length));

    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded string value to the buffer
 */
s8_t write_string(u8_t* output, s16_t* pos, u8_t* str_value)
{
    /* string value */
    u16_t len = strlen((char*)str_value);
    DECN(pos, len);
    memcpy(output + *pos, str_value, len);

    /* type and length */
    TRY(write_type_length(output, pos, BER_TYPE_OCTET_STRING, &len));

    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Encode an SNMP response
 */
s8_t snmp_write_response(request_t* request, response_t* response, u8_t* output, u16_t* output_len, const u16_t max_output_len)
{
    /* TODO: don't forget about too big */
    s32_t tmp;

    /* if, for any object named in the variable-bindings field,
       an error occurs, then the receiving entity sends to the originator
       of the received message the message of identical form, 
       except that the value of the error-status field is set */
    if (response->error_status != ERROR_STATUS_NO_ERROR) {
        u8_t i;
        response->var_bind_list_len = request->var_bind_list_len;
        for (i = 0; i < response->var_bind_list_len; i++) {
            memcpy(&response->var_bind_list[i].oid, &request->var_bind_list[i], sizeof (oid_t));
            response->var_bind_list[i].value.len = varbind_t_null.len;
            memcpy(&response->var_bind_list[i].value.buffer, &varbind_t_null.buffer, response->var_bind_list[i].value.len);            
        }
    }
    s16_t pos = max_output_len;
    s8_t i;

    /* write in the reverse order */

    /* variable binding list */
    for (i = response->var_bind_list_len - 1; i >= 0; i--) {
        TRY(write_var_bind(output, &pos, &response->var_bind_list[i]));
    }
    u16_t len = max_output_len - pos;
    TRY(write_type_length(output, &pos, BER_TYPE_SEQUENCE, &len));

    /* error index */
    tmp = response->error_index;
    TRY(write_integer(output, &pos, &tmp));
    /* error status */
    tmp = response->error_status;
    TRY(write_integer(output, &pos, &tmp));
    /* request id */
    TRY(write_integer(output, &pos, &request->request_id));

    /* sequence header*/
    len = max_output_len - pos;
    TRY(write_type_length(output, &pos, BER_TYPE_SNMP_RESPONSE, &len));

    /* community string */
    TRY(write_string(output, &pos, request->community));
    /* version */
    tmp = request->version;
    TRY(write_integer(output, &pos, &tmp));

    /* sequence header*/
    len = max_output_len - pos;
    TRY(write_type_length(output, &pos, BER_TYPE_SEQUENCE, &len));

    *output_len = max_output_len - pos;
    if (pos > 0) {
        memmove(output, output + pos, *output_len);
    }

    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Handle an SNMP request
 */
s8_t snmp_handler(const u8_t* const input,  const u16_t* const input_len, u8_t* output, u16_t* output_len, const u16_t max_output_len)
{
    static request_t request;
    static response_t response;

    /* parse the incoming datagram and build an ASN.1 object */
    if (snmp_parse_request(input, input_len, &request) == -1) {
        /* if the parse fails, it discards the datagram and performs no further actions. */
        return -1;
    }

    memset(&response, 0, sizeof(response_t));

    /* authentication scheme */
    if (strcmp(COMMUNITY_STRING, (char*)request.community)) {
        /* the protocol entity notes this failure, (possibly) generates a trap, and discards the datagram
         and performs no further actions. */
        response.error_status = (request.version == SNMP_VERSION_2C) ? ERROR_STATUS_NO_ACCESS : ERROR_STATUS_GEN_ERR;
        response.error_index = 0;
        snmp_log("wrong community string \"%s\"\n", request.community);
    } else {
        snmp_log("authentication passed\n");
    }

    /* request processing */
    if (request.error_status == ERROR_STATUS_NO_ERROR) {
        if (request.request_type == BER_TYPE_SNMP_GET) {
            snmp_handle_get(&request, &response);
        }
    }

    /* encode the response */
    if (snmp_write_response(&request, &response, output, output_len, max_output_len) == -1) {
            return -1;
    }

    snmp_log("processing finished\n---------------------------------\n");
    return 0;
}

