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
#include "snmpd-conf.h"
#include "snmp-protocol.h"
#include "logging.h"

#define UDP_IP_BUF   ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])

/* UDP connection*/
static struct uip_udp_conn *udpconn;

PROCESS(snmpd_process, "SNMP daemon process");

/*-----------------------------------------------------------------------------------*/
/*
 * UDP handler.
 */
static void udp_handler(process_event_t ev, process_data_t data)
{
    static u8t respond[MAX_BUF_SIZE];
    static u16t resp_len;
    
    #if DEBUG && CONTIKI_TARGET_AVR_RAVEN
    static u8t request[MAX_BUF_SIZE];
    static u16t req_len;
    #endif /* DEBUG && CONTIKI_TARGET_AVR_RAVEN */
    if (ev == tcpip_event && uip_newdata()) {
        uip_ipaddr_copy(&udpconn->ripaddr, &UDP_IP_BUF->srcipaddr);
        udpconn->rport = UDP_IP_BUF->srcport;

        #if DEBUG && CONTIKI_TARGET_AVR_RAVEN
        req_len = uip_datalen();
        memcpy(request, uip_appdata, req_len);
        if (snmp_handler(request, &req_len, respond, resp_len, MAX_BUF_SIZE) == -1) {
            return;
        }
        #else

/*
        resp_len = MAX_BUF_SIZE - 1;
        s16t i;
        for (i = 0; i < resp_len; i++) {
            respond[i] = 64 + i / 100;
        }
        respond[MAX_BUF_SIZE - 1] = 0;
*/

        if (snmp_handler((u8_t*)uip_appdata, &uip_datalen(), respond, &resp_len, MAX_BUF_SIZE) == -1) {
            return;
        }
        #endif /* DEBUG && CONTIKI_TARGET_AVR_RAVEN */

        uip_udp_packet_send(udpconn, respond, resp_len);

        memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
        udpconn->rport = 0;
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

