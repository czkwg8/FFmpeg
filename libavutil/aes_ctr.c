/*
 * AES-CTR cipher
 * Copyright (c) 2015 Eran Kornblau <erankor at gmail dot com>
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "common.h"
#include "aes_ctr.h"
#include "aes.h"
#include "aes_internal.h"
#include "intreadwrite.h"
#include "random_seed.h"

#define AES_BLOCK_SIZE (16)

typedef struct AVAESCTR {
    DECLARE_ALIGNED(16, uint8_t, counter)[AES_BLOCK_SIZE];
    DECLARE_ALIGNED(16, uint8_t, encrypted_counter)[AES_BLOCK_SIZE];
    int block_offset;
    AVAES aes;
} AVAESCTR;

struct AVAESCTR *av_aes_ctr_alloc(void)
{
    return av_mallocz(sizeof(struct AVAESCTR));
}

void av_aes_ctr_set_iv(struct AVAESCTR *a, const uint8_t* iv)
{
    memcpy(a->counter, iv, AES_CTR_IV_SIZE);
    memset(a->counter + AES_CTR_IV_SIZE, 0, sizeof(a->counter) - AES_CTR_IV_SIZE);
    a->block_offset = 0;
}

void av_aes_ctr_set_full_iv(struct AVAESCTR *a, const uint8_t* iv)
{
    memcpy(a->counter, iv, sizeof(a->counter));
    a->block_offset = 0;
}

const uint8_t* av_aes_ctr_get_iv(struct AVAESCTR *a)
{
    return a->counter;
}

void av_aes_ctr_set_random_iv(struct AVAESCTR *a)
{
    uint32_t iv[2];

    iv[0] = av_get_random_seed();
    iv[1] = av_get_random_seed();

    av_aes_ctr_set_iv(a, (uint8_t*)iv);
}

int av_aes_ctr_init(struct AVAESCTR *a, const uint8_t *key)
{
    av_aes_init(&a->aes, key, 128, 0);

    memset(a->counter, 0, sizeof(a->counter));
    a->block_offset = 0;

    return 0;
}

void av_aes_ctr_free(struct AVAESCTR *a)
{
    av_free(a);
}

static inline void av_aes_ctr_increment_be64(uint8_t* counter)
{
    uint64_t c = AV_RB64(counter) + 1;
    AV_WB64(counter, c);
}

void av_aes_ctr_increment_iv(struct AVAESCTR *a)
{
    av_aes_ctr_increment_be64(a->counter);
    memset(a->counter + AES_CTR_IV_SIZE, 0, sizeof(a->counter) - AES_CTR_IV_SIZE);
    a->block_offset = 0;
}

void av_aes_ctr_crypt(struct AVAESCTR *a, uint8_t *dst, const uint8_t *src, int count)
{
    if (a->block_offset && count > 0) {
        int left = FFMIN(count, AES_BLOCK_SIZE - a->block_offset);
        for (int len = 0; len < left; len++)
            dst[len] = src[len] ^ a->encrypted_counter[a->block_offset++];
        a->block_offset &= AES_BLOCK_SIZE - 1;
        dst += left;
        src += left;
        count -= left;
    }

    /* 4-block parallel CTR fast-path */
    while (count >= 4 * AES_BLOCK_SIZE) {
        DECLARE_ALIGNED(16, uint8_t, counters)[4 * AES_BLOCK_SIZE];
        DECLARE_ALIGNED(16, uint8_t, enc_counters)[4 * AES_BLOCK_SIZE];
        uint64_t c0 = AV_RB64(a->counter + 8);

        memcpy(&counters[0 * AES_BLOCK_SIZE], a->counter, 8);
        AV_WB64(&counters[0 * AES_BLOCK_SIZE + 8], c0);
        memcpy(&counters[1 * AES_BLOCK_SIZE], a->counter, 8);
        AV_WB64(&counters[1 * AES_BLOCK_SIZE + 8], c0 + 1);
        memcpy(&counters[2 * AES_BLOCK_SIZE], a->counter, 8);
        AV_WB64(&counters[2 * AES_BLOCK_SIZE + 8], c0 + 2);
        memcpy(&counters[3 * AES_BLOCK_SIZE], a->counter, 8);
        AV_WB64(&counters[3 * AES_BLOCK_SIZE + 8], c0 + 3);

        av_aes_crypt(&a->aes, enc_counters, counters, 4, NULL, 0);
        AV_WB64(a->counter + 8, c0 + 4);

#if HAVE_FAST_64BIT
        for (int len = 0; len < 4 * AES_BLOCK_SIZE; len += 8)
            AV_WN64(&dst[len], AV_RN64(&src[len]) ^ AV_RN64(&enc_counters[len]));
#else
        for (int len = 0; len < 4 * AES_BLOCK_SIZE; len += 4)
            AV_WN32(&dst[len], AV_RN32(&src[len]) ^ AV_RN32(&enc_counters[len]));
#endif
        dst += 4 * AES_BLOCK_SIZE;
        src += 4 * AES_BLOCK_SIZE;
        count -= 4 * AES_BLOCK_SIZE;
    }

    /* Single block path */
    while (count >= AES_BLOCK_SIZE) {
        av_aes_crypt(&a->aes, a->encrypted_counter, a->counter, 1, NULL, 0);
        av_aes_ctr_increment_be64(a->counter + 8);
#if HAVE_FAST_64BIT
        for (int len = 0; len < AES_BLOCK_SIZE; len += 8)
            AV_WN64(&dst[len], AV_RN64(&src[len]) ^ AV_RN64(&a->encrypted_counter[len]));
#else
        for (int len = 0; len < AES_BLOCK_SIZE; len += 4)
            AV_WN32(&dst[len], AV_RN32(&src[len]) ^ AV_RN32(&a->encrypted_counter[len]));
#endif
        dst += AES_BLOCK_SIZE;
        src += AES_BLOCK_SIZE;
        count -= AES_BLOCK_SIZE;
    }

    /* Trailing partial block */
    if (count > 0) {
        av_aes_crypt(&a->aes, a->encrypted_counter, a->counter, 1, NULL, 0);
        av_aes_ctr_increment_be64(a->counter + 8);
        for (int len = 0; len < count; len++)
            dst[len] = src[len] ^ a->encrypted_counter[a->block_offset++];
    }
}
