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
#include "logging.h"


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
 * Handle an SNMP request
 */
s8t snmp_handler(const u8t* const input,  const u16t* const input_len, u8t* output, u16t* output_len, const u16t max_output_len)
{
    static message_t message;
    memset(&message, 0, sizeof(message_t));

    /* parse the incoming datagram and build an ASN.1 object */
    if (ber_decode_request(input, input_len, &message) == -1) {
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

    /* if, for any object named in the variable-bindings field,
       an error occurs, then the receiving entity sends to the originator
       of the received message the message of identical form,
       except that the value of the error-status field is set */
    if (message.pdu.error_status != ERROR_STATUS_NO_ERROR) {
        u8t i;
        for (i = 0; i < message.pdu.var_bind_list_len; i++) {
            message.pdu.var_bind_list[i].value.len = varbind_t_null.len;
            memcpy(&message.pdu.var_bind_list[i].value.buffer, &varbind_t_null.buffer, varbind_t_null.len);
        }
    }

    /* encode the response */
    if (ber_encode_response(&message, output, output_len, max_output_len) == -1) {
            return -1;
    }

    snmp_log("processing finished\n---------------------------------\n");
    return 0;
}

