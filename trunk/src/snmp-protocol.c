#include "snmp-protocol.h"
#include "snmpd-logging.h"

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded SNMP message.
 */
static char fetch_type(const u8_t* const request, const u16_t* const len, u16_t* pos, u8_t* type)
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
                snmp_log("unsupported BER type %02X\n", request[*pos]);
                return -1;
        }
    } else {
        snmp_log("unexpected end of the SNMP request [type=1]\n");
        return -1;
    }
    return 0;
}


/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded length field.
 */
static char fetch_length(const u8_t* const request, const u16_t* const len, u16_t* pos, u16_t* length)
{
    if (*pos < *len) {
        /* length is encoded in a single length byte */
        if (!(request[*pos] & 0x80)) {
            *length = request[*pos];
            *pos = *pos + 1;
        } else {
            /* constructed, definite-length method or indefinite-length method is used */
            u8_t size_of_length = request[*pos] & 0x7F;
            *pos = *pos + 1;
            if (size_of_length > 2) {
                snmp_log("unsupported value of the length field occures (must be up to 2 bytes)");
                return 1;
            }
            *length = 0;
            while (size_of_length--) {
                if (*pos < *len) {
                    *length = (*length << 8) + request[*pos];
                    *pos = *pos + 1;
                } else {
                    snmp_log("unexpected end of the SNMP request [type=2]\n");
                    return -1;
                }
            }
        }
    } else {
        snmp_log("unexpected end of the SNMP request [type=3]\n");
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
    static u16_t pos, length;
    static u8_t type;
    pos = 0;
    if (fetch_type(request, len, &pos, &type) == -1) {
        return -1;
    }
    if (fetch_length(request, len, &pos, &length) == -1) {
        return -1;
    }
    if (type != BER_TYPE_SEQUENCE || length != (*len - pos)) {
        snmp_log("unexpected SNMP header type %02X length %d\n", type, length);
        return -1;
    }
    printf("OK\n");
    return 0;
}

