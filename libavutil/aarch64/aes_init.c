/*
 * AArch64 ARMv8 Crypto Extensions AES optimization (128, 192, 256-bit)
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

#include <stddef.h>
#include "libavutil/aes_internal.h"
#include "libavutil/aarch64/cpu.h"

#define DECLARE_AES_CRYPT_AARCH64(rounds) \
void ff_aes_encrypt_##rounds##_aarch64(struct AVAES *a, uint8_t *dst,\
                                       const uint8_t *src, int count,\
                                       uint8_t *iv, int rounds_param);\
void ff_aes_decrypt_##rounds##_aarch64(struct AVAES *a, uint8_t *dst,\
                                       const uint8_t *src, int count,\
                                       uint8_t *iv, int rounds_param);

DECLARE_AES_CRYPT_AARCH64(10)
DECLARE_AES_CRYPT_AARCH64(12)
DECLARE_AES_CRYPT_AARCH64(14)

typedef void (*crypt_func_t)(struct AVAES *a, uint8_t *dst,
                             const uint8_t *src, int count,
                             uint8_t *iv, int rounds);

int ff_aes_init_aarch64(AVAES *a, int decrypt);

int ff_aes_init_aarch64(AVAES *a, int decrypt)
{
    int cpu_flags = av_get_cpu_flags();
    crypt_func_t fn;

    if (!have_aes(cpu_flags))
        return 0;

    /*
     * The ARMv8 AESE/AESD instructions apply their operand as AddRoundKey
     * before SubBytes/InvSubBytes; see the asm for the resulting operand
     * sequences. The schedule handling differs per direction:
     *   encrypt: reverse the schedule in place (rk[i] = FK[nr-i]).
     *   decrypt: keep the plain forward schedule.
     */
    switch (a->rounds) {
    case 10: fn = decrypt ? ff_aes_decrypt_10_aarch64 : ff_aes_encrypt_10_aarch64; break;
    case 12: fn = decrypt ? ff_aes_decrypt_12_aarch64 : ff_aes_encrypt_12_aarch64; break;
    case 14: fn = decrypt ? ff_aes_decrypt_14_aarch64 : ff_aes_encrypt_14_aarch64; break;
    default: return 0;
    }

    if (!decrypt) {
        /* Reverse the schedule: rk[i] = FK[nr - i]. */
        for (int i = 0; i <= a->rounds / 2; i++)
            FFSWAP(av_aes_block, a->round_key[i], a->round_key[a->rounds - i]);
    }
    a->crypt = fn;
    return 1;
}

