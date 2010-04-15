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

#include <stdlib.h>
#include <string.h>

#include "snmp-protocol.h"
#include "ber.h"
#include "mib.h"
#include "logging.h"

/*-----------------------------------------------------------------------------------*/
/*
 * Handle an SNMP GET request
 */
static s8t snmp_get(message_t* message)
{
    static u8t i;
    for (i = 0; i < message->pdu.var_bind_list_len; i++) {
        if (mib_get(&message->pdu.var_bind_list[i]) == -1) {
            message->pdu.error_status = ERROR_STATUS_NO_SUCH_NAME;
            message->pdu.error_index = i + 1;
            break;
        }
    }    
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Handle an SNMP GETNEXT request
 */
static s8t snmp_get_next(message_t* message)
{
    static u8t i;
    for (i = 0; i < message->pdu.var_bind_list_len; i++) {
        if (mib_get_next(&message->pdu.var_bind_list[i]) == -1) {
            message->pdu.error_status = ERROR_STATUS_NO_SUCH_NAME;
            message->pdu.error_index = i + 1;
            break;
        }
    }
    return 0;
}


/*-----------------------------------------------------------------------------------*/
/*
 * Handle an SNMP SET request
 */
static s8t snmp_set(message_t* message)
{
    static u8t i;
    static u8t var_index[VAR_BIND_LEN];
    static varbind_t tmp_var_bind;
    /* find mib objects and check their types */
    for (i = 0; i < message->pdu.var_bind_list_len; i++) {
        memcpy(&tmp_var_bind, &message->pdu.var_bind_list[i], sizeof(varbind_t));
        if ((var_index[i] = mib_get(&tmp_var_bind)) == -1) {
            message->pdu.error_status = ERROR_STATUS_NO_SUCH_NAME;
            message->pdu.error_index = i + 1;
            break;
        }
        if (tmp_var_bind.value_type != message->pdu.var_bind_list[i].value_type) {
            snmp_log("bad value type %d %d\n", tmp_var_bind.value_type, message->pdu.var_bind_list[i].value_type);
            message->pdu.error_status = ERROR_STATUS_BAD_VALUE;
            message->pdu.error_index = i + 1;
            break;
        }
    }

    /* execute set operations for all mib objects in varbindings */
    if (message->pdu.error_status == ERROR_STATUS_NO_ERROR) {
        for (i = 0; i < message->pdu.var_bind_list_len; i++) {
            if (mib_set(var_index[i], &message->pdu.var_bind_list[i]) == -1) {
                message->pdu.error_status = ERROR_STATUS_GEN_ERR;
                message->pdu.error_index = i + 1;
                return -1;
            }
        }
    }
    return 0;
}

void free_message(message_t* message) {
    if (message->community) {
        free(message->community);
    }
}

/*-----------------------------------------------------------------------------------*/
/*
 * Handle an SNMP request
 */
s8t snmp_handler(const u8t* const input,  const u16t input_len, u8t* output, u16t* output_len, const u16t max_output_len)
{
    static message_t message;
    /* copy of the input varbindings */
    static varbind_t var_bind_list[VAR_BIND_LEN];
    
    memset(&message, 0, sizeof(message_t));
    
    /* parse the incoming datagram and build an ASN.1 object */
    s8t ret = ber_decode_request(input, input_len, &message);
    if (ret == -1) {
        /* if the parse fails, it discards the datagram and performs no further actions. */
        free_message(&message);
        return -1;
    } else if (ret == BER_ERROR_TOO_MANY_ENTRIES) {
        // too big
        message.pdu.error_status = ERROR_STATUS_TOO_BIG;
    } else {
        memcpy(var_bind_list, message.pdu.var_bind_list, message.pdu.var_bind_list_len * sizeof(varbind_t));
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
        } else if (message.pdu.request_type == BER_TYPE_SNMP_GETNEXT) {
            snmp_get_next(&message);
        } else if (message.pdu.request_type == BER_TYPE_SNMP_SET) {
            snmp_set(&message);
        }
    }

    /* If, for any object named in the variable-bindings field,
       an error occurs, then the receiving entity sends to the originator
       of the received message the message of identical form,
       except that the value of the error-status field is set */
    if (message.pdu.error_status != ERROR_STATUS_NO_ERROR) {
        u8t i;
        if ((message.pdu.request_type == BER_TYPE_SNMP_GETNEXT || message.pdu.request_type == BER_TYPE_SNMP_SET)
                && message.pdu.error_status != ERROR_STATUS_TOO_BIG) {
            memcpy(message.pdu.var_bind_list, var_bind_list, message.pdu.var_bind_list_len * sizeof(varbind_t));
        }
        for (i = 0; i < message.pdu.var_bind_list_len; i++) {
            message.pdu.var_bind_list[i].value_type = BER_TYPE_NULL;
        }
    }

    /* copy the value */
    /* encode the response */
    if (ber_encode_response(&message, output, output_len, max_output_len) == -1) {
        /* Too big message.
         * If the size of the GetResponse-PDU generated as described
         * below would exceed a local limitation, then the receiving
         * entity sends to the originator of the received message
         * the GetResponse-PDU of identical form, except that the
         * value of the error-status field is tooBig, and the value
         * of the error-index field is zero.
         */
        memcpy(message.pdu.var_bind_list, var_bind_list, message.pdu.var_bind_list_len * sizeof(varbind_t));
        u8t i;
        for (i = 0; i < message.pdu.var_bind_list_len; i++) {
            message.pdu.var_bind_list[i].value_type = BER_TYPE_NULL;
        }
        message.pdu.error_status = ERROR_STATUS_TOO_BIG;
        message.pdu.error_index = 0;
        if (ber_encode_response(&message, output, output_len, max_output_len) == -1) {
            free_message(&message);
            return -1;
        }
    }
    free_message(&message);
    snmp_log("processing finished\n---------------------------------\n");
    return 0;
}
