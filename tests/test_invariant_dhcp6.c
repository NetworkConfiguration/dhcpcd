#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>

/* Test that DHCPv6 processing requires server authentication before
 * applying configuration changes or deletions. Any unauthenticated
 * server response must NOT result in interface config deletion. */

/* Simulate DHCPv6 message types */
#define DHCP6_REPLY    7
#define DHCP6_RECONFIGURE 10

/* Adversarial DHCPv6 message payloads (raw bytes):
 * - Forged REPLY with no authentication option (exact exploit case)
 * - Forged RECONFIGURE from unknown server (boundary: triggers deletion path)
 * - Valid authenticated REPLY (valid input baseline)
 */
static const uint8_t forged_reply_no_auth[] = {
    DHCP6_REPLY, 0x01, 0x02, 0x03,  /* msg-type + transaction-id */
    0x00, 0x01, 0x00, 0x0e,          /* client DUID option */
    0x00, 0x01, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x00, 0x01, 0x02, 0x03
};

static const uint8_t forged_reconfigure[] = {
    DHCP6_RECONFIGURE, 0xaa, 0xbb, 0xcc,
    0x00, 0x0b, 0x00, 0x02, 0x00, 0x01  /* reconfigure-msg option, type=RENEW */
};

static const uint8_t valid_reply_with_auth[] = {
    DHCP6_REPLY, 0x11, 0x22, 0x33,
    0x00, 0x0b, 0x00, 0x28,              /* auth option (11), length 40 */
    0x03, 0x01,                           /* proto=DKIM, algo=HMAC-MD5 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* replay detection */
    /* 32 bytes of auth info */
    0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,
    0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,
    0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,
    0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef
};

/* Check whether a DHCPv6 message contains an authentication option (11) */
static int has_auth_option(const uint8_t *msg, size_t len) {
    if (len < 4) return 0;
    size_t offset = 4; /* skip msg-type + transaction-id */
    while (offset + 4 <= len) {
        uint16_t opt_code = (msg[offset] << 8) | msg[offset+1];
        uint16_t opt_len  = (msg[offset+2] << 8) | msg[offset+3];
        if (opt_code == 11) return 1; /* OPTION_AUTH */
        offset += 4 + opt_len;
    }
    return 0;
}

START_TEST(test_dhcp6_unauthenticated_server_rejected)
{
    /* Invariant: DHCPv6 messages that modify/delete interface config
     * MUST contain a valid authentication option. Unauthenticated
     * server responses must be rejected before applying changes. */
    struct { const uint8_t *data; size_t len; int expect_auth; } payloads[] = {
        { forged_reply_no_auth,   sizeof(forged_reply_no_auth),   0 },
        { forged_reconfigure,     sizeof(forged_reconfigure),     0 },
        { valid_reply_with_auth,  sizeof(valid_reply_with_auth),  1 },
    };
    int num = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num; i++) {
        int auth_present = has_auth_option(payloads[i].data, payloads[i].len);
        /* Security invariant: unauthenticated messages must NOT be trusted */
        if (!payloads[i].expect