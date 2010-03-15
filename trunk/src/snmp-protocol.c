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

#include "snmp-protocol.h"
#include "ber.h"
#include "logging.h"

/*-----------------------------------------------------------------------------------*/
/*
 * Parse a BER encoded SNMP request.
 */
static s8t decode_request(const u8t* const input, const u16t* const len, message_t* request)
{
    static u16t pos, length;
    static u8t type;
    static s32t tmp;
   
    pos = 0;
    
    /* Sequence */
    if (ber_decode_type(input, len, &pos, &type) == -1 || ber_decode_length(input, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_SEQUENCE || length != (*len - pos)) {
        snmp_log("bad SNMP header: type %02X length %d\n", type, length);
        return -1;
    }
    
    /* version */
    if (ber_decode_type(input, len, &pos, &type) == -1 || !ber_decode_length(input, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_INTEGER || length != 1) {
        snmp_log("bad SNMP version: type %02X length %d\n", type, length);
        return -1;
    } else if (ber_decode_integer_value(input, len, &pos, &length, &tmp) == -1) {
        return -1;
    }
    request->version = (u8t)tmp;
    if (request->version != SNMP_VERSION_1 && request->version != SNMP_VERSION_2C) {
        /* it then verifies the version number of the SNMP message.  */
        /* if there is no mismatch, it discards the datagram and performs no further actions. */
        snmp_log("unsupported SNMP version %d\n", request->version);
        return -1;
    }
    snmp_log("snmp version: %d\n", request->version);
    
    /* community name */
    if (ber_decode_type(input, len, &pos, &type) == -1 || !ber_decode_length(input, len, &pos, &length) == -1) {
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
    if (ber_decode_string((u8t*)input, len, &pos, &length, request->community, COMMUNITY_STRING_LEN) == -1) {
        return -1;
    } else if (strlen((char*)request->community) < 1) {
        snmp_log("unsupported SNMP community '%s'\n", request->community);
        return -1;
    }
    snmp_log("community string: %s\n", request->community);

    /* request PDU */
    if (ber_decode_type(input, len, &pos, &request->pdu.request_type) == -1 || !ber_decode_length(input, len, &pos, &length) == -1) {
        return -1;
    }

    if (length != (*len - pos)) {
        snmp_log("bad SNMP header: type %02X length %d\n", request->request_type, length);
        return -1;
    }    
    snmp_log("request type: %d\n", request->request_type);

    /* request-id */
    if (ber_decode_type(input, len, &pos, &type) == -1 || !ber_decode_length(input, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_INTEGER || length < 1) {
        snmp_log("bad SNMP request-id: type %02X length %d\n", type, length);
        return -1;
    } else if (ber_decode_integer_value(input, len, &pos, &length, &request->pdu.request_id) == -1) {
        return -1;
    }
    snmp_log("request id: %d\n", request->request_id);

    /* error-state */
    if (ber_decode_type(input, len, &pos, &type) == -1 || !ber_decode_length(input, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_INTEGER || length < 1) {
        snmp_log("bad SNMP error-status: type %02X length %d\n", type, length);
        return -1;
    } else if (ber_decode_integer_value(input, len, &pos, &length, &tmp) == -1) {
        return -1;
    }
    request->pdu.error_status = (u8t)tmp;
    snmp_log("error-status: %d\n", request->error_status);

    /* error-index */
    if (ber_decode_type(input, len, &pos, &type) == -1 || !ber_decode_length(input, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_INTEGER || length < 1) {
        snmp_log("bad SNMP error-index: type %02X length %d\n", type, length);
        return -1;
    } else if (ber_decode_integer_value(input, len, &pos, &length, &tmp) == -1) {
        return -1;
    }
    request->pdu.error_index = (u8t)tmp;
    snmp_log("error-index: %d\n", request->error_index);

    /* variable-bindings */
    if (ber_decode_type(input, len, &pos, &type) == -1 || !ber_decode_length(input, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_SEQUENCE || length != (*len - pos)) {
        snmp_log("bad SNMP variable binding header length: type %02X length %d\n", type, length);
        return -1;
    }
    /* variable binding list */
    request->pdu.var_bind_list_len = 0;
    while (pos < *len) {
        if (request->pdu.var_bind_list_len >= VAR_BIND_LEN) {
            snmp_log("maximum number of var bindings in the list is exceeded: max=%d\n", VAR_BIND_LEN);
            return -1;
        }
        
        /* sequence */
        if (ber_decode_type(input, len, &pos, &type) == -1 || !ber_decode_length(input, len, &pos, &length) == -1) {
            return -1;
        }
        if (type != BER_TYPE_SEQUENCE || length < 1) {
            snmp_log("bad SNMP variable binding: type %02X length %d\n", type, length);
            return -1;
        }
        
        /* OID */
        if (ber_decode_type(input, len, &pos, &type) == -1 || !ber_decode_length(input, len, &pos, &length) == -1) {
            return -1;
        }
        if (type != BER_TYPE_OID || length < 1) {
            snmp_log("bad SNMP varbinding OID: type %02X length %d\n", type, length);
            return -1;
        }
        if (ber_decode_oid(input, len, &pos, &length, &request->pdu.var_bind_list[request->pdu.var_bind_list_len].oid) == -1) {
            return -1;
        }
        /* value */
        if (ber_decode_type(input, len, &pos, &type) == -1 || !ber_decode_length(input, len, &pos, &length) == -1) {
            return -1;
        }
        if ((type == BER_TYPE_NULL && length != 0) || (type != BER_TYPE_NULL && length == 0)) {
            snmp_log("bad SNMP varbinding value: type %02X length %d\n", type, length);
            return -1;
        } else if (ber_decode_void(input, len, &pos, &length) == -1) {
            return -1;
        }
        request->pdu.var_bind_list_len++;
    }

    snmp_log("parsing finished: OK\n");

    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Handle an SNMP GET request
 */
static s8t snmp_get(message_t* message)
{
    message->pdu.error_status = ERROR_STATUS_GEN_ERR;
    message->pdu.error_index = 1;
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Encode an SNMP response
 */
static s8t encode_response(message_t* message, u8t* output, u16t* output_len, const u16t max_output_len)
{
    /* TODO: don't forget about too big */
    s32t tmp;
    s16t pos = max_output_len;

    /* if, for any object named in the variable-bindings field,
       an error occurs, then the receiving entity sends to the originator
       of the received message the message of identical form, 
       except that the value of the error-status field is set */
    if (message->pdu.error_status != ERROR_STATUS_NO_ERROR) {
        u8t i;
        message->pdu.var_bind_list_len = message->pdu.var_bind_list_len;
        for (i = 0; i < message->pdu.var_bind_list_len; i++) {
            memcpy(&message->pdu.var_bind_list[i].oid, &message->pdu.var_bind_list[i], sizeof (oid_t));
            message->pdu.var_bind_list[i].value.len = varbind_t_null.len;
            memcpy(&message->pdu.var_bind_list[i].value.buffer, &varbind_t_null.buffer, message->pdu.var_bind_list[i].value.len);
        }
    }
    ber_encode_pdu(output, &pos, &message->pdu, &max_output_len);

    /* community string */
    TRY(ber_encode_string(output, &pos, message->community));
    /* version */
    tmp = message->version;
    TRY(ber_encode_integer(output, &pos, &tmp));

    /* sequence header*/
    u16t len = max_output_len - pos;
    TRY(ber_encode_type_length(output, &pos, BER_TYPE_SEQUENCE, &len));

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
s8t snmp_handler(const u8t* const input,  const u16t* const input_len, u8t* output, u16t* output_len, const u16t max_output_len)
{
    static message_t message;
    memset(&message, 0, sizeof(message_t));

    /* parse the incoming datagram and build an ASN.1 object */
    if (decode_request(input, input_len, &message) == -1) {
        /* if the parse fails, it discards the datagram and performs no further actions. */
        return -1;
    }

    /* authentication scheme */
    if (strcmp(COMMUNITY_STRING, (char*)message.community)) {
        /* the protocol entity notes this failure, (possibly) generates a trap, and discards the datagram
         and performs no further actions. */
        message.pdu.error_status = (message.version == SNMP_VERSION_2C) ? ERROR_STATUS_NO_ACCESS : ERROR_STATUS_GEN_ERR;
        message.pdu.error_index = 0;
        snmp_log("wrong community string \"%s\"\n", message.community);
    } else {
        snmp_log("authentication passed\n");
    }

    /* request processing */
    if (message.pdu.error_status == ERROR_STATUS_NO_ERROR) {
        if (message.pdu.request_type == BER_TYPE_SNMP_GET) {
            snmp_get(&message);
        }
    }

    /* encode the response */
    if (encode_response(&message, output, output_len, max_output_len) == -1) {
            return -1;
    }

    snmp_log("processing finished\n---------------------------------\n");
    return 0;
}

