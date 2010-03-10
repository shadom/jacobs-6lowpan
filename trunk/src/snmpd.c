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

#include <stdio.h>
#include <string.h>

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"

#include "snmpd.h"
#include "snmp-protocol.h"
#include "snmpd-utils.h"
#include "snmpd-logging.h"

static struct uip_udp_conn *udpconn;

PROCESS(snmpd_process, "SNMP daemon process");

/*-----------------------------------------------------------------------------------*/
/*
 * UDP handler.
 */
static void udp_handler(process_event_t ev, process_data_t data)
{
    #if DEBUG && CONTIKI_TARGET_AVR_RAVEN
    static u8_t request[UIP_APPDATA_SIZE];
    static u16_t len;
    #endif /* DEBUG && CONTIKI_TARGET_AVR_RAVEN */
    if (ev == tcpip_event && uip_newdata()) {
        #if DEBUG && CONTIKI_TARGET_AVR_RAVEN
        len = uip_datalen();
        memcpy(request, uip_appdata, len);
        snmp_decode_request(request, &len);
        #else
        snmp_decode_request((u8_t*)uip_appdata, &uip_datalen());
        #endif /* DEBUG && CONTIKI_TARGET_AVR_RAVEN */

    }
}
/*-----------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------------*/
/*
 *  Entry point of the SNMP server.
 */
PROCESS_THREAD(snmpd_process, ev, data) {
	PROCESS_BEGIN();
	udpconn = udp_new(NULL, HTONS(0), NULL);
	udp_bind(udpconn, HTONS(LISTEN_PORT));

	while(1) {
            PROCESS_YIELD();
            udp_handler(ev, data);
	}
	PROCESS_END();
}
/*-----------------------------------------------------------------------------------*/

