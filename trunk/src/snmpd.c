#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include <string.h>

#define UDP_IP_BUF   ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])

#define PRINT6ADDR(addr) "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", ((u8_t *)addr)[0], ((u8_t *)addr)[1], ((u8_t *)addr)[2], ((u8_t *)addr)[3], ((u8_t *)addr)[4], ((u8_t *)addr)[5], ((u8_t *)addr)[6], ((u8_t *)addr)[7], ((u8_t *)addr)[8], ((u8_t *)addr)[9], ((u8_t *)addr)[10], ((u8_t *)addr)[11], ((u8_t *)addr)[12], ((u8_t *)addr)[13], ((u8_t *)addr)[14], ((u8_t *)addr)[15]
				 
#define min(a,b) ( (a>b) ? b : a )
#define max(a,b) ( (a>b) ? a : b )

#define UDP_DATA_LEN 10000

static struct uip_udp_conn *udpconn;

PROCESS(udp_process_receiver, "UPD test receiver");
AUTOSTART_PROCESSES(&udp_process_receiver);

/*-----------------------------------------------------------------------------------*/
void send(char *r) 
{
	uip_ipaddr_copy(&udpconn->ripaddr, &UDP_IP_BUF->srcipaddr);
	udpconn->rport = UDP_IP_BUF->srcport;

	u16_t cur = 0;
	while (cur < strlen(r)) {
		uip_udp_packet_send(udpconn, r + cur, min(strlen(r + cur), UDP_DATA_LEN));
		cur += UDP_DATA_LEN;
	}

	memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
	udpconn->rport = 0;
}
/*-----------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------------*/
char buf[1000];

static void udphandler(process_event_t ev, process_data_t data) 
{
	if (ev == tcpip_event && uip_newdata()) {
		((char *)uip_appdata)[uip_datalen() - 1] = 0;
		memset(buf, 0, 1000);
		sprintf(buf, PRINT6ADDR(&(UDP_IP_BUF->srcipaddr)));
//        send((char *)uip_appdata);
        send(buf);
	}
}
/*-----------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------------*/
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
/*-----------------------------------------------------------------------------------*/

