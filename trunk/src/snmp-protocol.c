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


#define SNMP_STATUS_OK					0
#define SNMP_STATUS_TOO_BIG				1
#define SNMP_STATUS_NO_SUCH_NAME			2
#define SNMP_STATUS_BAD_VALUE				3
#define SNMP_STATUS_READ_ONLY				4
#define SNMP_STATUS_GEN_ERR				5
#define SNMP_STATUS_NO_ACCESS				6
#define SNMP_STATUS_WRONG_TYPE				7
#define SNMP_STATUS_WRONG_LENGTH			8
#define SNMP_STATUS_WRONG_ENCODING			9
#define SNMP_STATUS_WRONG_VALUE				10
#define SNMP_STATUS_NO_CREATION				11
#define SNMP_STATUS_INCONSISTENT_VALUE                  12
#define SNMP_STATUS_RESOURCE_UNAVAILABLE                13
#define SNMP_STATUS_COMMIT_FAILED			14
#define SNMP_STATUS_UNDO_FAILED				15
#define SNMP_STATUS_AUTHORIZATION_ERROR                 16
#define SNMP_STATUS_NOT_WRITABLE			17
#define SNMP_STATUS_INCONSISTENT_NAME                   18

typedef struct {
    u16_t values[OID_LEN];
    short len;
} oid_t;

typedef struct {
    int len;
} varbind_value_t;

typedef struct {
    oid_t oid;
    varbind_value_t value;
} varbind_t;

typedef struct {
    int version;
    u8_t community[COMMUNITY_STRING_LEN];
    u8_t request_type;
    int request_id;
    int error_status;
    int error_index;
    u8_t var_bind_list_len;
    oid_t var_bind_list[VAR_BIND_LEN];
} request_t;

typedef struct {
    int error_status;
    int error_index;
    int var_bind_list_len;
    varbind_t var_bind_list[VAR_BIND_LEN];
} response_t;

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded SNMP message.
 */
static int fetch_type(const u8_t* const request, const u16_t* const len, u16_t* pos, u8_t* type)
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
static int fetch_length(const u8_t* const request, const u16_t* const len, u16_t* pos, u16_t* length)
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
static int fetch_integer_value(const u8_t* const request, const u16_t* const len, u16_t* pos, u16_t* field_len, int* value)
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
static int fetch_octet_string(const u8_t* const request, const u16_t* const len, u16_t* pos, u16_t* field_len, u8_t* value, u8_t value_len)
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
static int fetch_oid(const u8_t* const request, const u16_t* const len, u16_t* pos, u16_t* field_len, oid_t* o )
{
    if (*pos + *field_len -1 < *len) {
        o->len = 0;
        if (!(request[*pos] & 0x80)) {
            o->values[o->len++] = request[*pos] / 40;
            o->values[o->len++] = request[*pos] % 40;
            *pos = *pos + 1;
            (*field_len)--;
        } else {
            snmp_log("first bit of the oid must be set\n");
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
static int fetch_void(const u8_t* const request, const u16_t* const len, u16_t* pos, u16_t* field_len)
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
    int i;
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
 * Decode a BER encoded SNMP request.
 */
int  snmp_decode_request(const u8_t* const input, const u16_t* const len, request_t* request)
{
    static u16_t pos, length;
    static u8_t type;
   
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
    } else if (fetch_integer_value(input, len, &pos, &length, &request->version) == -1) {
        return -1;
    } else if (request->version != SNMP_VERSION_1 && request->version != SNMP_VERSION_2C) {
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
    } else if (fetch_integer_value(input, len, &pos, &length, &request->error_status) == -1) {
        return -1;
    }
    snmp_log("error-status: %d\n", request->error_status);

    /* error-index */
    if (fetch_type(input, len, &pos, &type) == -1 || !fetch_length(input, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_INTEGER || length < 1) {
        snmp_log("bad SNMP error-index: type %02X length %d\n", type, length);
        return -1;
    } else if (fetch_integer_value(input, len, &pos, &length, &request->error_index) == -1) {
        return -1;
    }
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

    snmp_log("OK\n");

    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Handle an SNMP GET request
 */
int snmp_handle_get(request_t* request, response_t* response) {
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Encode an SNMP response
 */
int snmp_encode_response(request_t* request, response_t* response) {
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Handle an SNMP request
 */
int snmp_handler(const u8_t* const input, const u16_t* const len)
{
    static request_t request;
    static response_t response;

    /* decode the request */
    if (snmp_decode_request(input, len, &request) == -1) {
        return -1;
    }

    memset(&response, 0, sizeof(response_t));

    /* secutiry check */
    if (request.version == SNMP_VERSION_2C || request.version == SNMP_VERSION_1) {
        if (strcmp(COMMUNITY_STRING, (char*)request.community)) {
            response.error_status = (request.version == SNMP_VERSION_2C) ? SNMP_STATUS_NO_ACCESS : SNMP_STATUS_GEN_ERR;
            response.error_index = 0;
            snmp_log("wrong community string \"%s\"\n", request.community);
        }
    }

    /* request processing */
    if (request.error_status == SNMP_STATUS_OK) {
        if (request.request_type == BER_TYPE_SNMP_GET) {
            snmp_handle_get(&request, &response);
        }
    }

    /* encode the response */
    if (snmp_encode_response(&request, &response) == -1) {
            return -1;
    }


    return 0;
}

