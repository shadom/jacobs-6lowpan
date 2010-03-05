/**
 * \file
 *         UDP implementatio of logging facilites for the SNMP server
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */
#include "snmpd-logging.h"

#ifdef DEBUG
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "contiki-net.h"

/** \brief port number where debug messages are sent */
#define LOGGING_PORT 12345

/** \brief length of the buffer used for debugging messages */
#define BUF_LEN 100

/*--------------------------------------------------------------------------*/
/*
 * Log a debug message by sending it within a UDP message.
 */
void snmp_log(char* format, ...)
{  
    static struct uip_udp_conn *udp_con = NULL;
    if (udp_con == NULL) {
        udp_con = udp_new(NULL, HTONS(LOGGING_PORT), NULL);
        uip_ip6addr(&udp_con->ripaddr, 0xaaaa, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001);
	udp_bind(udp_con, HTONS(3000));
    }

/*    static char buf[BUF_LEN];
    memset(buf, 0, BUF_LEN);
    va_list args;
    va_start(args, format);
    sprintf(buf, format, args);
    va_end(args);*/

    va_list args;
    va_start(args, format);
    char buf[100];
    memset(buf, 0, 100);
    vsprintf(buf, "type: %02x, pos: %02x, type: %02x\n", args);
    va_end(args);

    //uip_udp_packet_send(udp_con, format, strlen(format));
    uip_udp_packet_send(udp_con, buf, strlen(buf));

}
#else
void snmp_log(char* format, ... )
{
}
#endif /* DEBUG */