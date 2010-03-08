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
#include "snmpd-logging.h"

/** maximum length of the community string */
#define COMMUNITY_STRING_LEN    32

/** maximum number of variable bindings in a request */
#define VAR_BIND_LEN            32

/** maximum number of elements in an OID */
#define OID_LEN                 20

typedef struct oid {
    u16_t values[OID_LEN];
    short len;
} oid;
/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded SNMP message.
 */
static char fetch_type(const u8_t* const request, const u16_t* const len, u16_t* pos, u8_t* type)
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
        snmp_log("unexpected end of the SNMP request [1]\n");
        return -1;
    }
    return 0;
}


/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded length field.
 */
static char fetch_length(const u8_t* const request, const u16_t* const len, u16_t* pos, u16_t* length)
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
static char fetch_integer_value(const u8_t* const request, const u16_t* const len, u16_t* pos, u16_t* field_len, int* value)
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
static char fetch_octet_string(const char* const request, const u16_t* const len, u16_t* pos, u16_t* field_len, char* value, u8_t value_len)
{
    if (*pos + *field_len - 1 < *len) {
        snprintf(value, value_len, "%.*s", *field_len, &request[*pos]);
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
static int fetch_oid(const u8_t* const request, const u16_t* const len, u16_t* pos, u16_t* field_len, oid* o )
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
void log_oid(oid* o) {
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
u8_t snmp_decode_request(const u8_t* const request, const u16_t* const len)
{
    static u16_t pos, length;
    static u8_t type;
    static int version;
    static char community[COMMUNITY_STRING_LEN];
    static u8_t request_type;
    static int request_id, error_status, error_index;
    static u8_t var_bind_list_len;
    static oid var_bind_list[VAR_BIND_LEN];
    
    pos = 0;

    /* Sequence */
    if (fetch_type(request, len, &pos, &type) == -1 || fetch_length(request, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_SEQUENCE || length != (*len - pos)) {
        snmp_log("bad SNMP header: type %02X length %d\n", type, length);
        return -1;
    }

    /* version */
    if (fetch_type(request, len, &pos, &type) == -1 || !fetch_length(request, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_INTEGER || length != 1) {
        snmp_log("bad SNMP version: type %02X length %d\n", type, length);
        return -1;
    } else if (fetch_integer_value(request, len, &pos, &length, &version) == -1) {
        return -1;
    } else if (version != SNMP_VERSION_1 && version != SNMP_VERSION_2C) {
        snmp_log("unsupported SNMP version %d\n", version);
        return -1;
    }
    snmp_log("snmp version: %d\n", version);

    /* community name */
    if (fetch_type(request, len, &pos, &type) == -1 || !fetch_length(request, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_OCTET_STRING) {
        snmp_log("SNMP community string must of type %02X, byt not %02X\n", BER_TYPE_OCTET_STRING, type);
        return -1;
    } else if (length >= COMMUNITY_STRING_LEN) {
        snmp_log("community string is too long (must be up to 31 character)\n");
        return -1;
    } else if (fetch_octet_string((char*)request, len, &pos, &length, community, COMMUNITY_STRING_LEN) == -1) {
        return -1;
    } else if (strlen(community) < 1) {
        snmp_log("unsupported SNMP community '%s'\n", community);
        return -1;
    }
    snmp_log("community string: %s\n", community);

    /* request PDU */
    if (fetch_type(request, len, &pos, &request_type) == -1 || !fetch_length(request, len, &pos, &length) == -1) {
        return -1;
    }

    if (length != (*len - pos)) {
        snmp_log("bad SNMP header: type %02X length %d\n", type, length);
        return -1;
    }    
    snmp_log("request type: %d\n", request_type);

    /* request-id */
    if (fetch_type(request, len, &pos, &type) == -1 || !fetch_length(request, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_INTEGER || length < 1) {
        snmp_log("bad SNMP request-id: type %02X length %d\n", type, length);
        return -1;
    } else if (fetch_integer_value(request, len, &pos, &length, &request_id) == -1) {
        return -1;
    }
    snmp_log("request id: %d\n", request_id);

    /* error-state */
    if (fetch_type(request, len, &pos, &type) == -1 || !fetch_length(request, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_INTEGER || length < 1) {
        snmp_log("bad SNMP error-status: type %02X length %d\n", type, length);
        return -1;
    } else if (fetch_integer_value(request, len, &pos, &length, &error_status) == -1) {
        return -1;
    }
    snmp_log("error-status: %d\n", error_status);

    /* error-index */
    if (fetch_type(request, len, &pos, &type) == -1 || !fetch_length(request, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_INTEGER || length < 1) {
        snmp_log("bad SNMP error-index: type %02X length %d\n", type, length);
        return -1;
    } else if (fetch_integer_value(request, len, &pos, &length, &error_index) == -1) {
        return -1;
    }
    snmp_log("error-index: %d\n", error_index);

    /* variable-bindings */
    if (fetch_type(request, len, &pos, &type) == -1 || !fetch_length(request, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_SEQUENCE || length != (*len - pos)) {
        snmp_log("bad SNMP variable binding header length: type %02X length %d\n", type, length);
        return -1;
    }
    /* variable binding list */
    var_bind_list_len = 0;
    while (pos < *len) {
        if (var_bind_list_len >= VAR_BIND_LEN) {
            snmp_log("maximum number of var bindings in the list is exceeded: max=%d\n", VAR_BIND_LEN);
            return -1;
        }
        
        /* sequence */
        if (fetch_type(request, len, &pos, &type) == -1 || !fetch_length(request, len, &pos, &length) == -1) {
            return -1;
        }
        if (type != BER_TYPE_SEQUENCE || length < 1) {
            snmp_log("bad SNMP variable binding: type %02X length %d\n", type, length);
            return -1;
        }
        
        /* OID */
        if (fetch_type(request, len, &pos, &type) == -1 || !fetch_length(request, len, &pos, &length) == -1) {
            return -1;
        }
        if (type != BER_TYPE_OID || length < 1) {
            snmp_log("bad SNMP varbinding OID: type %02X length %d\n", type, length);
            return -1;
        }
        if (fetch_oid(request, len, &pos, &length, &var_bind_list[var_bind_list_len]) == -1) {
            return -1;
        }
        /* value */
        if (fetch_type(request, len, &pos, &type) == -1 || !fetch_length(request, len, &pos, &length) == -1) {
            return -1;
        }
        if ((type == BER_TYPE_NULL && length != 0) || (type != BER_TYPE_NULL && length == 0)) {
            snmp_log("bad SNMP varbinding value: type %02X length %d\n", type, length);
            return -1;
        } else if (fetch_void(request, len, &pos, &length) == -1) {
            return -1;
        }
        log_oid(&var_bind_list[var_bind_list_len]);
        var_bind_list_len++;
    }

    snmp_log("OK\n");

    return 0;
}
