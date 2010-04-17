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
#include "utils.h"

/*-----------------------------------------------------------------------------------*/
/*
 * Handle an SNMP GET request
 */
static s8t snmp_get(message_t* message)
{
    int i = 0;
    varbind_t* ptr = message->pdu.varbind_first_ptr;
    while (ptr) {
        i++;
        if (mib_get(ptr) == -1) {
            message->pdu.error_status = ERROR_STATUS_NO_SUCH_NAME;
            message->pdu.error_index = i;
            break;
        }
        ptr = ptr->next_ptr;
    }    
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Handle an SNMP GETNEXT request
 */
static s8t snmp_get_next(message_t* message)
{
    int i = 0;
    varbind_t* ptr = message->pdu.varbind_first_ptr;
    while (ptr) {
        i++;
        if (mib_get_next(ptr) == -1) {
            message->pdu.error_status = ERROR_STATUS_NO_SUCH_NAME;
            message->pdu.error_index = i;
            break;
        }
        ptr = ptr->next_ptr;
    }
    return 0;
}


/*-----------------------------------------------------------------------------------*/
/*
 * Handle an SNMP SET request
 */
static s8t snmp_set(message_t* message)
{
    varbind_t tmp_var_bind;
    u8t_list_t *var_index_ptr, *cur_ptr;

    varbind_t* ptr = message->pdu.varbind_first_ptr;
    int i = 0, index;
    /* find mib objects and check their types */
    while (ptr) {
        i++;
        memcpy(&tmp_var_bind, ptr, sizeof(varbind_t));
        if ((index = mib_get(&tmp_var_bind)) == -1) {
            message->pdu.error_status = ERROR_STATUS_NO_SUCH_NAME;
            message->pdu.error_index = i;
            break;
        } else {
            if (i == 1) {
                cur_ptr = var_index_ptr = u8t_list_append(0, index);
            } else {
                cur_ptr = u8t_list_append(cur_ptr, index);
            }
        }
        if (tmp_var_bind.value_type != ptr->value_type) {
            snmp_log("bad value type %d %d\n", tmp_var_bind.value_type, ptr->value_type);
            message->pdu.error_status = ERROR_STATUS_BAD_VALUE;
            message->pdu.error_index = i;
            break;
        }
        ptr = ptr->next_ptr;
    }

    /* execute set operations for all mib objects in varbindings */
    if (message->pdu.error_status == ERROR_STATUS_NO_ERROR) {
        ptr = message->pdu.varbind_first_ptr;
        cur_ptr = var_index_ptr;
        i = 0;
        while (ptr) {
            i++;
            if (mib_set(cur_ptr->value, ptr) == -1) {
                message->pdu.error_status = ERROR_STATUS_GEN_ERR;
                message->pdu.error_index = i;
                u8t_list_free(var_index_ptr);
                return -1;
            }
            ptr = ptr->next_ptr;
            cur_ptr = cur_ptr->next_ptr;
        }
    }
    u8t_list_free(var_index_ptr);
    return 0;
}

void free_message(message_t* message) {
    /* free memory for the community string */
    if (message->community) {
        free(message->community);
    }

    /* free memory for string values */
    varbind_t* ptr = message->pdu.varbind_first_ptr;
    while (ptr) {
        if (message->pdu.request_type == BER_TYPE_SNMP_SET &&
                ptr->value_type == BER_TYPE_OCTET_STRING && ptr->value.s_value.ptr) {
            free(ptr->value.s_value.ptr);
        }
        oid_free(ptr->oid_ptr);
        varbind_t* next_ptr = ptr->next_ptr;
        free(ptr);
        ptr = next_ptr;
    }
}

/*-----------------------------------------------------------------------------------*/
/*
 * Handle an SNMP request
 */
s8t snmp_handler(const u8t* const input,  const u16t input_len, u8t* output, u16t* output_len, const u16t max_output_len)
{
    static message_t message;
    memset(&message, 0, sizeof(message_t));
    /* parse the incoming datagram and build an ASN.1 object */
    s8t ret = ber_decode_request(input, input_len, &message);
    if (ret == -1) {
        /* if the parse fails, it discards the datagram and performs no further actions. */
        free_message(&message);
        return -1;
    } else if (ret == ERR_MEMORY_ALLOCATION) {
        snmp_info("here!!!");
        message.pdu.error_status = ERROR_STATUS_GEN_ERR;
    }

    /* authentication scheme */
    if (message.pdu.error_status == ERROR_STATUS_NO_ERROR &&
            strcmp(COMMUNITY_STRING, (char*)message.community)) {
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

    /* copy the value */
    /* encode the response */
    if (ber_encode_response(&message, output, output_len, input, input_len, max_output_len) == -1) {
        /* Too big message.
         * If the size of the GetResponse-PDU generated as described
         * below would exceed a local limitation, then the receiving
         * entity sends to the originator of the received message
         * the GetResponse-PDU of identical form, except that the
         * value of the error-status field is tooBig, and the value
         * of the error-index field is zero.
         */
        message.pdu.error_status = ERROR_STATUS_TOO_BIG;
        message.pdu.error_index = 0;
        if (ber_encode_response(&message, output, output_len, input, input_len, max_output_len) == -1) {
            free_message(&message);
            return -1;
        }
    }
    free_message(&message);
    snmp_log("processing finished\n---------------------------------\n");
    return 0;
}