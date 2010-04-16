#include "contiki.h"
PROCESS(fake_snmpd_process, "FAKE SNMP daemon process");
/*-----------------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
AUTOSTART_PROCESSES(&fake_snmpd_process);
/*---------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------------*/
/*
 *  Entry point of the FAKE SNMPD server.
 */
PROCESS_THREAD(fake_snmpd_process, ev, data) {
    PROCESS_BEGIN();

    /* init MIB */
    while(1) {
          PROCESS_YIELD();
    }
    PROCESS_END();
}
