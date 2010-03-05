/**
 * \file
 *         Implementation of the SNMP protocol
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */

#ifndef __SNMP_PROTOCOL_H__
#define	__SNMP_PROTOCOL_H__

#include "contiki.h"
/*
 * BER identifiers for ASN.1 implementation of SNMP.
 */
#define BER_TYPE_BOOLEAN                                0x01
#define BER_TYPE_INTEGER                                0x02
#define BER_TYPE_BIT_STRING                             0x03
#define BER_TYPE_OCTET_STRING                           0x04
#define BER_TYPE_NULL                                   0x05
#define BER_TYPE_OID                                    0x06
#define BER_TYPE_SEQUENCE                               0x30
#define BER_TYPE_IPADDRESS                              0x40
#define BER_TYPE_COUNTER                                0x41
#define BER_TYPE_GAUGE                                  0x42
#define BER_TYPE_TIME_TICKS				0x43
#define BER_TYPE_OPAQUE                                 0x44
#define BER_TYPE_NASAPADDRESS                           0x45
#define BER_TYPE_COUNTER64                              0x46
#define BER_TYPE_UINTEGER32                             0x47
#define BER_TYPE_NO_SUCH_OBJECT                         0x80
#define BER_TYPE_NO_SUCH_INSTANCE                       0x81
#define BER_TYPE_END_OF_MIB_VIEW                        0x82
#define BER_TYPE_SNMP_GET                               0xA0
#define BER_TYPE_SNMP_GETNEXT                           0xA1
#define BER_TYPE_SNMP_RESPONSE                          0xA2
#define BER_TYPE_SNMP_SET                               0xA3
#define BER_TYPE_SNMP_GETBULK                           0xA5
#define BER_TYPE_SNMP_INFORM                            0xA6
#define BER_TYPE_SNMP_TRAP                              0xA7
#define BER_TYPE_SNMP_REPORT                            0xA8

u8_t snmp_decode_request(const u8_t* const data,  const u16_t* const len);

#endif	/* __SNMP_PROTOCOL_H__ */

