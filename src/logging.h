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

/**
 * \file
 *         Logging facilites for the SNMP server
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */

#ifndef __SNMPD_LOGGING_H__
#define __SNMPD_LOGGING_H__

/** \brief indicates whether debug is enabled */
#define DEBUG 0

/** \brief indicates whether info messages are enabled */
#define INFO 1


#if DEBUG
/**
 * Log a message.
 *
 * \param m A pointer to a string containing a message.
 *
 * \sa log()
 *
 * \hideinitializer
 */
void snmp_log(char* format, ...);
#else
#define snmp_log(...)
#endif /* DEBUG */

#if INFO
/**
 * Log a message.
 *
 * \param m A pointer to a string containing a message.
 *
 * \sa log()
 *
 * \hideinitializer
 */
void snmp_info(char* format, ...);
#else
#define snmp_info(...)
#endif /* INFO */


#endif /* __SNMPD_LOGGING_H__ */