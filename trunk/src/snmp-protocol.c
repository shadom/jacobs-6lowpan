#include "snmp-protocol.h"
#include "snmpd-logging.h"

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded SNMP message.
 */

static u8_t fetch_type(const u8_t* const request, const u16_t* const len, u16_t* pos, u8_t* type)
{
    if (*pos < *len) {
        switch (request[*pos]) {
            case BER_TYPE_BOOLEAN:
            case BER_TYPE_INTEGER:
            case BER_TYPE_BIT_STRING:
            case BER_TYPE_OCTET_STRING:
            case BER_TYPE_NULL:
            case BER_TYPE_OID:
            case BER_TYPE_SEQUENCE:
            case BER_TYPE_IPADDRESS:
            case BER_TYPE_COUNTER:
            case BER_TYPE_GAUGE:
            case BER_TYPE_TIME_TICKS:
            case BER_TYPE_OPAQUE:
            case BER_TYPE_NASAPADDRESS:
            case BER_TYPE_COUNTER64:
            case BER_TYPE_UINTEGER32:
            case BER_TYPE_NO_SUCH_OBJECT:
            case BER_TYPE_NO_SUCH_INSTANCE:
            case BER_TYPE_END_OF_MIB_VIEW:
            case BER_TYPE_SNMP_GET:
            case BER_TYPE_SNMP_GETNEXT:
            case BER_TYPE_SNMP_RESPONSE:
            case BER_TYPE_SNMP_SET:
            case BER_TYPE_SNMP_GETBULK:
            case BER_TYPE_SNMP_INFORM:
            case BER_TYPE_SNMP_TRAP:
                *type = request[*pos];
                *pos = *pos + 1;
                break;
            default:
                //snmp_log("unsupported BER type %02X\n", request[*pos]);
                return -1;
        }
    } else {
            //snmp_log("malformed SNMP request\n");
            return -1;
    }
    return 0;
}


/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded SNMP message.
 */
u8_t snmp_decode_request(const u8_t* const request, const u16_t* const len)
{
    static u16_t pos = 0;
    static u8_t type, res;

    //snmp_log("pos: %u\n", pos);
    
    res = fetch_type(request, len, &pos, &type);
    snmp_log("%d %d %dx\n", pos, type, res);
    /*if () {
		return -1;
	} else if (type != BER_TYPE_SEQUENCE || length != (client->size - pos)) {
		lprintf(LOG_DEBUG, "unexpected SNMP header type %02X length %d\n",
			type, length);
		errno = EINVAL;
		return -1;
	}*/
    return 0;
}

/*
static int fetch_length(const unsigned char *packet,
	size_t size, size_t *pos, int *type, int *length)*/

	/* Fetch the ASN.1 element length (only lengths up to 16 bit supported) */
/*	if (*pos < size) {
		if (!(packet[*pos] & 0x80)) {
			*length = packet[*pos];
			*pos = *pos + 1;
		} else {
			length_of_length = packet[*pos] & 0x7F;
			if (length_of_length > 2) {
				lprintf(LOG_DEBUG, "overflow for element length\n");
				errno = EINVAL;
				return -1;
			}
			*pos = *pos + 1;
			*length = 0;
			while (length_of_length--) {
				if (*pos < size) {
					*length = (*length << 8) + packet[*pos];
					*pos = *pos + 1;
				} else {
					lprintf(LOG_DEBUG, "underflow for element length\n");
					errno = EINVAL;
					return -1;
				}
			}
		}
	} else {
		lprintf(LOG_DEBUG, "underflow for element length\n");
		errno = EINVAL;
		return -1;
	}

}*/