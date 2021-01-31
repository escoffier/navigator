#include <inttypes.h>
#include <stdlib.h>

static uint32_t rc_crc32(uint32_t crc, const char *buf, size_t len) {
    static uint32_t table[256];
    static int have_table = 0;
    uint32_t rem;
    uint8_t octet;
    int i, j;
    const char *p, *q;
 
    if (have_table == 0) {
        for (i = 0; i < 256; i++) {
            rem = i;
            for (j = 0; j < 8; j++) {
                if (rem & 1) {
                    rem >>= 1;
                    rem ^= 0xedb88320;
                } else
                    rem >>= 1;
            }
            table[i] = rem;
        }
        have_table = 1;
    }
 
    crc = ~crc;
    q = buf + len;
    for (p = buf; p < q; p++) {
        octet = *p;
        crc = table[(crc & 0xff) ^ octet] ^ (crc >> 8);
    }
    return ~crc;
}
