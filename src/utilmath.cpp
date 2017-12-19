// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <utilmath.h>

int Log2Floor(uint32_t v)
{
    static const uint32_t b[] = {0x2, 0xC, 0xF0, 0xFF00, 0xFFFF0000};
    static const unsigned int S[] = {1, 2, 4, 8, 16};

    int r = 0;
    for (int i = sizeof(v); i >= 0; i--) {
        if (v & b[i]) {
            v >>= S[i];
            r |= S[i];
        }
    }
    return r;
}

int Log2Floor(uint64_t v)
{
    static const uint64_t b[] = {0x2ULL, 0xCULL, 0xF0ULL, 0xFF00ULL, 0xFFFF0000ULL, 0xFFFFFFFF00000000ULL};
    static const unsigned int S[] = {1, 2, 4, 8, 16, 32};

    int r = 0;
    for (int i = sizeof(v); i >= 0; i--) {
        if (v & b[i]) {
            v >>= S[i];
            r |= S[i];
        }
    }
    return r;
}
