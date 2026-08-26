/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Executable regression probe for CVE-2026-14456.
 *
 * The probe is compiled twice: once against an unpatched OpenSSL 3.5.7
 * baseline and once against the OpenSSL static archive produced by the Node
 * build. The baseline must fail the fixed-capacity contract; the patched
 * archive must expose the listener value, report the default 256, and retain
 * a caller-provided capacity. The source guard in quic_port.c is separately
 * bound into the archive identity by the harness.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>

/* OpenSSL 3.5.7 predates the public declaration. The numeric value comes
 * exclusively from the official fixed patch and allows the negative control
 * to exercise the same API call rather than merely fail to compile. */
#ifndef SSL_VALUE_QUIC_MAX_PENDING_CONNS
# define SSL_VALUE_QUIC_MAX_PENDING_CONNS 16
#endif

int main(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    uint64_t value = 0;
    int ok = 0;

    if ((ctx = SSL_CTX_new(OSSL_QUIC_server_method())) == NULL) {
        fprintf(stderr, "cannot create QUIC server context\n");
        goto done;
    }
    if ((listener = SSL_new_listener(ctx, 0)) == NULL) {
        fprintf(stderr, "cannot create QUIC listener\n");
        goto done;
    }
    if (!SSL_get_generic_value_uint(listener,
                                      SSL_VALUE_QUIC_MAX_PENDING_CONNS,
                                      &value)) {
        fprintf(stderr, "pending-connection capacity is unavailable\n");
        goto done;
    }
    if (value != 256) {
        fprintf(stderr, "unexpected default pending-connection capacity: %llu\n",
                (unsigned long long)value);
        goto done;
    }
    if (!SSL_set_generic_value_uint(listener,
                                      SSL_VALUE_QUIC_MAX_PENDING_CONNS,
                                      1)
        || !SSL_get_generic_value_uint(listener,
                                         SSL_VALUE_QUIC_MAX_PENDING_CONNS,
                                         &value)
        || value != 1) {
        fprintf(stderr, "pending-connection capacity is not enforced by listener state\n");
        goto done;
    }
    ok = 1;
done:
    SSL_free(listener);
    SSL_CTX_free(ctx);
    return ok ? 0 : 1;
}
