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
 *         Configuration of the SNMP protocol
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */

#ifndef __SNMP_CONF_H__
#define	__SNMP_CONF_H__

/** community string */
#define COMMUNITY_STRING        "public"

/** maximum length of the community string in octets */
#define COMMUNITY_STRING_LEN    32

/** maximum number of variable bindings in a request */
#define VAR_BIND_LEN            16

/** maximum number of elements in an OID */
#define OID_LEN                 20

/** maximum length of the value of a variable bindings in a response (in octets)*/
#define VAR_BIND_VALUE_LEN      128


#endif	/* __SNMP_CONF_H__ */

