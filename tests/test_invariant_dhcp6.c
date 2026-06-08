#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/types.h>

/* Test that dhcp6 packet parsing does not crash (SIGSEGV/SIGBUS/SIGABRT)
 * when fed adversarial DHCPv6 packets with malformed option lengths,
 * truncated headers, or NULL-like payloads.
 * Invariant: parsing must not cause abnormal process termination.
 */

static volatile sig_atomic_t crash_detected = 0;
static sigjmp_buf jump_buffer;

static void crash_handler(int sig) {
    (void)sig;
    crash_detected = 1;
    siglongjmp(jump_buffer, 1);
}

/* DHCPv6 message type + transaction ID = 4 bytes header */
static const uint8_t valid_dhcp6_solicit[] = {
    0x01,             /* SOLICIT */
    0x00, 0x01, 0x02, /* transaction-id */
    0x00, 0x01,       /* option: CLIENTID */
    0x00, 0x0a,       /* length: 10 */
    0x00, 0x03, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe /* DUID */
};

/* Truncated header - only 2 bytes */
static const uint8_t truncated_header[] = { 0x01, 0x00 };

/* Option length exceeds packet size */
static const uint8_t oversized_option[] = {
    0x01, 0x00, 0x01, 0x02,
    0x00, 0x01,       /* option: CLIENTID */
    0xff, 0xff        /* length: 65535 - far exceeds remaining data */
};

/* Zero-length packet */
static const uint8_t empty_packet[] = { 0x00 };

typedef struct { const uint8_t *data; size_t len; } Payload;

START_TEST(test_dhcp6_parse_no_crash)
{
    /* Invariant: DHCPv6 packet parsing must not crash the process
     * regardless of packet content or length. */
    Payload payloads[] = {
        { valid_dhcp6_solicit, sizeof(valid_dhcp6_solicit) },
        { truncated_header,    sizeof(truncated_header)    },
        { oversized_option,    sizeof(oversized_option)    },
        { empty_packet,        sizeof(empty_packet)        },
    };
    int num_payloads = (int)(sizeof(payloads) / sizeof(payloads[0]));

    struct sigaction sa, old_segv, old_bus, old_abrt;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND;
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS,  &sa, &old_bus);
    sigaction(SIGABRT, &sa, &old_abrt);

    for (int i = 0; i < num_payloads; i++) {
        crash_detected = 0;
        if (sigsetjmp(jump_buffer, 1) == 0) {
            /* Exercise the real parsing path via dhcp6_recvmsg / option walk.
             * We call dhcp6_findoption which iterates options and is the
             * primary source of buffer overreads per the vulnerability report. */
            extern const uint8_t *dhcp6_findoption(uint16_t, const uint8_t *, size_t);
            dhcp6_findoption(0x0001, payloads[i].data, payloads[i].len);
        }
        ck_assert_msg(crash_detected == 0,
            "Crash detected on payload index %d (len=%zu)", i, payloads[i].len);
    }

    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGBUS,  &old_bus,  NULL);
    sigaction(SIGABRT, &old_abrt, NULL);
}
END_TEST

Suite *security_suite(void) {
    Suite *s = suite_create("Security");
    TCase *tc = tcase_create("Core");
    tcase_add_test(tc, test_dhcp6_parse_no_crash);
    suite_add