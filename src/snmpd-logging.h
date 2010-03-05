/**
 * \file
 *         Logging facilites for the SNMP server
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */

#ifndef __SNMPD_LOGGING_H__
#define __SNMPD_LOGGING_H__

/** \brief indicates whether debug is enabled */
#define DEBUG 1

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

#endif /* __SNMPD_LOGGING_H__ */