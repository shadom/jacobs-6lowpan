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
    if (ev == tcpip_event && uip_newdata()) {
        snmp_decode_request((u8_t*)uip_appdata, &uip_datalen());
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

