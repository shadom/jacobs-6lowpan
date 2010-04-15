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
#define BER_TYPE_UINTEGER32                             0x42
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

/*
 * BER errors.
 */
#define BER_ERROR_TOO_MANY_ENTRIES                      -2

/* BER decoding */
s8t ber_decode_type(const u8t* const input, const u16t len, u16t* pos, u8t* type);

s8t ber_decode_length(const u8t* const input, const u16t len, u16t* pos, u16t* length);

s8t ber_decode_type_length(const u8t* const input, const u16t len, u16t* pos, u8t* type, u16t* length);

s8t ber_decode_sequence(const u8t* const input, const u16t len, u16t* pos, u8t is_last);

s8t ber_decode_oid(const u8t* const input, const u16t len, u16t* pos, oid_t* o);

s8t ber_decode_string(const u8t* const input, const u16t len, u16t* pos, u8t** value, u16t* field_len);

s8t ber_decode_integer(const u8t* const input, const u16t len, u16t* pos, s32t* value);

s8t ber_decode_unsigned_integer(const u8t* const input, const u16t len, u16t* pos, u32t* value);

s8t ber_decode_void(const u8t* const input, const u16t len, u16t* pos);

s8t ber_decode_pdu(const u8t* const input, const u16t len, u16t* pos, pdu_t* pdu);

s8t ber_decode_request(const u8t* const input, const u16t len, message_t* request);

/* BER encoding */

s8t ber_encode_length(u8t* output, s16t* pos, const u16t length);

s8t ber_encode_type_length(u8t* output, s16t* pos, const u8t type, const u16t len);

s8t ber_encode_integer(u8t* output, s16t* pos, const s32t value);

s8t ber_encode_unsigned_integer(u8t* output, s16t* pos, const u8t type, const u32t value);

s8t ber_encode_string(u8t* output, s16t* pos, const u8t* const str_value);

s8t ber_encode_oid(u8t* output, s16t* pos, const oid_t* const oid);

s8t ber_encode_var_bind(u8t* output, s16t* pos, const varbind_t* const varbind);

s8t ber_encode_pdu(u8t* output, s16t* pos, const pdu_t* const pdu, const u16t max_output_len);

s8t ber_encode_response(const message_t* const message, u8t* output, u16t* output_len, const u16t max_output_len);

#endif	/* __BER_H__ */
