/* -----------------------------------------------------------------------------
 * SNMP implementation for Contiki
 *
 * Copyright (C) 2010 Siarhei Kuryla
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

/**
 * \file
 *         BER encoding and decoding
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */

#ifndef __BER_H__
#define	__BER_H__

#include "snmp.h"

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

/* BER decoding */
s8t ber_decode_type(const u8t* const input, const u16t* const len, u16t* pos, u8t* type);

s8t ber_decode_length(const u8t* const input, const u16t* const len, u16t* pos, u16t* length);

s8t ber_decode_integer_value(const u8t* const input, const u16t* const len, u16t* pos, u16t* field_len, s32t* value);

s8t ber_decode_string(const u8t* const input, const u16t* const len, u16t* pos, u16t* field_len, u8t* value, u8t value_len);

s8t ber_decode_oid(const u8t* const input, const u16t* const len, u16t* pos, u16t* field_len, oid_t* o );

s8t ber_decode_void(const u8t* const input, const u16t* const len, u16t* pos, u16t* field_len);

/* BER encoding */

s8t ber_encode_length(u8t* output, s16t* pos, u16t* length);

s8t ber_encode_type_length(u8t* output, s16t* pos, u8t type, u16t *len);

s8t ber_encode_integer(u8t* output, s16t* pos, s32t* value);

s8t ber_encode_string(u8t* output, s16t* pos, u8t* str_value);

s8t ber_encode_oid(u8t* output, s16t* pos, oid_t* oid);

s8t ber_encode_var_bind(u8t* output, s16t* pos, varbind_t* varbind);

s8t ber_encode_pdu(u8t* output, s16t* pos, message_t* message, const u16t* max_output_len);

#define DECN(pos, value) (*pos) -= value; if (*pos < 0) { snmp_log("too big message: %d", __LINE__); return -1;}

#define DEC(pos) DECN(pos, 1)

#define TRY(c) if (c == -1) { return -1; }

#endif	/* __BER_H__ */

