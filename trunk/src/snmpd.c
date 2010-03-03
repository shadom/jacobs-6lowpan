#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include <string.h>

#define UDP_IP_BUF   ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])

char *help_buf = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
				 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
				 "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n"
				 "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\n"
				 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
				 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
				 "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n"
				 "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\n"
				 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
				 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
				 "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n"
				 "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\n";				 
				 
#define min(a,b) ( (a>b) ? b : a )
#define max(a,b) ( (a>b) ? a : b )				 
#define BUF_LEN 300
#define UDP_DATA_LEN 10000

static struct uip_udp_conn *udpconn;

PROCESS(udp_process_receiver, "UPD test receiver");
AUTOSTART_PROCESSES(&udp_process_receiver);

void send(char *r) {
	uip_ipaddr_copy(&udpconn->ripaddr, &UDP_IP_BUF->srcipaddr);
	udpconn->rport = UDP_IP_BUF->srcport;

	u16_t cur = 0;
	while (cur < strlen(r)) {
		uip_udp_packet_send(udpconn, r + cur, min(strlen(r + cur), UDP_DATA_LEN));
		cur += UDP_DATA_LEN;
	}

	if (strlen(r) > 0) {
		uip_udp_packet_send(udpconn, "\nsiarhei$ ", 10);
	} else {
		uip_udp_packet_send(udpconn, "siarhei$ ", 9);
	}

	memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
	udpconn->rport = 0;
}

static void udphandler(process_event_t ev, process_data_t data) {
	char buf[BUF_LEN];
	if (ev == tcpip_event && uip_newdata()) {
		send(help_buf);
	}
}

PROCESS_THREAD(udp_process_receiver, ev, data) {
	static struct etimer timer;

	PROCESS_BEGIN();
	udpconn = udp_new(NULL, HTONS(0), NULL);
	udp_bind(udpconn, HTONS(3000));

	while(1) {
		PROCESS_YIELD();
		udphandler(ev, data);
	}
	PROCESS_END();
}

