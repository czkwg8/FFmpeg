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

#include "asm.S"

#if HAVE_AS_ARCH_DIRECTIVE
        .arch           armv8-a+crypto
#elif defined(__clang__) || defined(__GNUC__)
        .arch           armv8-a+crypto
#endif

// void ff_aes_encrypt_N_aarch64(struct AVAES *a, uint8_t *dst,
//                              const uint8_t *src, int count,
//                              uint8_t *iv, int rounds_param)
//
// AES ECB/CBC encryption using the ARMv8 Crypto Extensions (N = rounds).
// When iv is non-NULL, CBC chaining is performed and iv[] receives the last
// ciphertext block; otherwise plain ECB.
//
// AESE applies its operand as AddRoundKey BEFORE SubBytes/ShiftRows, so each
// round's AddRoundKey is fused into the NEXT instruction's operand and the
// sequence is shifted by one round relative to FIPS-197:
//   EOR FK0, AESE(0), AESE(FK1)..AESE(FK_{nr-1}), EOR FK_nr
// a->round_key holds the reversed schedule produced for encryption
// (rk[i] = FK[nr-i]).
.macro AES_ENCRYPT rounds
function ff_aes_encrypt_\rounds\()_aarch64, export = 1
        cbz             w3, 4f

        movi            v30.16b, #0                     // first AESE operand (zero)
        cbz             x4, 2f                          // no IV -> ECB

        // CBC mode encryption:
        ld1             {v7.16b}, [x4]                  // load initial IV into chain register

1:      ld1             {v0.16b}, [x2], #16
        ldr             q17, [x0, #16 * \rounds]        // whitening key (FK0)
        eor             v0.16b, v0.16b, v7.16b          // CBC: plaintext ^ prev ciphertext/IV
        eor             v0.16b, v0.16b, v17.16b         // AddRoundKey(FK0)

        aese            v0.16b, v30.16b                 // round 1: SB+SR (key already added)
        aesmc           v0.16b, v0.16b

.set k, (\rounds - 1)
.rept (\rounds - 2)
        ldr             q16, [x0, #16 * k]              // rk[k] = FK_(nr-k)
        aese            v0.16b, v16.16b
        aesmc           v0.16b, v0.16b
.set k, (k - 1)
.endr

        ldr             q16, [x0, #16]                  // rk[1]: last full round
        aese            v0.16b, v16.16b

        ldr             q17, [x0]                       // rk[0]: final EOR, no MixColumns
        eor             v0.16b, v0.16b, v17.16b
        st1             {v0.16b}, [x1], #16

        mov             v7.16b, v0.16b                  // CBC: chain ciphertext to next block
        subs            w3, w3, #1
        b.ne            1b

        str             q7, [x4]                        // iv <- last ciphertext block
        ret

        // ECB mode encryption:
2:      ld1             {v0.16b}, [x2], #16
        ldr             q17, [x0, #16 * \rounds]        // whitening key (FK0)
        eor             v0.16b, v0.16b, v17.16b         // AddRoundKey(FK0)

        aese            v0.16b, v30.16b                 // round 1: SB+SR (key already added)
        aesmc           v0.16b, v0.16b

.set k, (\rounds - 1)
.rept (\rounds - 2)
        ldr             q16, [x0, #16 * k]              // rk[k] = FK_(nr-k)
        aese            v0.16b, v16.16b
        aesmc           v0.16b, v0.16b
.set k, (k - 1)
.endr

        ldr             q16, [x0, #16]                  // rk[1]: last full round
        aese            v0.16b, v16.16b

        ldr             q17, [x0]                       // rk[0]: final EOR, no MixColumns
        eor             v0.16b, v0.16b, v17.16b
        st1             {v0.16b}, [x1], #16

        subs            w3, w3, #1
        b.ne            2b

4:      ret
endfunc
.endm

// void ff_aes_decrypt_N_aarch64(struct AVAES *a, uint8_t *dst,
//                              const uint8_t *src, int count,
//                              uint8_t *iv, int rounds_param)
//
// AES CBC/ECB decryption using the ARMv8 Crypto Extensions (N = rounds).
// AESD applies its operand as AddRoundKey BEFORE InvSubBytes/InvShiftRows, which
// does not match the inverse cipher's key position (after the S-box); the round
// keys are therefore applied with plain EORs between the AESD/AESIMC pairs:
//   EOR FK_nr, then per round (FK_{nr-1}..FK_1): EOR K, AESD(0), AESIMC,
//   finally AESD(0) and EOR FK0.
// round_key is left exactly as av_aes_init() expands it (forward schedule).
// On return iv[] holds the last ciphertext block if iv is non-NULL.
.macro AES_DECRYPT rounds
function ff_aes_decrypt_\rounds\()_aarch64, export = 1
        cbz             w3, 4f

        movi            v30.16b, #0                     // zero AESD operand
        cbz             x4, 2f                          // no IV -> ECB

        // CBC mode decryption:
        ld1             {v6.16b}, [x4]                  // load initial IV into chain register

1:      ld1             {v8.16b}, [x2], #16             // ciphertext block
        ldr             q16, [x0, #16 * \rounds]        // rk[nr] = FK_nr
        eor             v0.16b, v8.16b, v16.16b         // AddRoundKey(FK_nr)
        aesd            v0.16b, v30.16b

        ldr             q16, [x0, #16 * (\rounds - 1)]  // rk[nr-1] = FK_{nr-1}
        eor             v0.16b, v0.16b, v16.16b

.set k, (\rounds - 2)
.rept (\rounds - 2)
        aesimc          v0.16b, v0.16b
        aesd            v0.16b, v30.16b
        ldr             q16, [x0, #16 * k]
        eor             v0.16b, v0.16b, v16.16b
.set k, (k - 1)
.endr

        aesimc          v0.16b, v0.16b                  // final round: no key
        aesd            v0.16b, v30.16b
        ldr             q16, [x0]                       // rk[0] = FK0: final EOR
        eor             v0.16b, v0.16b, v16.16b
        eor             v0.16b, v0.16b, v6.16b          // CBC: XOR with prev ciphertext/IV
        st1             {v0.16b}, [x1], #16

        mov             v6.16b, v8.16b                  // chain register = current ciphertext
        subs            w3, w3, #1
        b.ne            1b

        str             q6, [x4]                        // iv <- last ciphertext block
        ret

        // ECB mode decryption:
2:      ld1             {v8.16b}, [x2], #16             // ciphertext block
        ldr             q16, [x0, #16 * \rounds]        // rk[nr] = FK_nr
        eor             v0.16b, v8.16b, v16.16b         // AddRoundKey(FK_nr)
        aesd            v0.16b, v30.16b

        ldr             q16, [x0, #16 * (\rounds - 1)]  // rk[nr-1] = FK_{nr-1}
        eor             v0.16b, v0.16b, v16.16b

.set k, (\rounds - 2)
.rept (\rounds - 2)
        aesimc          v0.16b, v0.16b
        aesd            v0.16b, v30.16b
        ldr             q16, [x0, #16 * k]
        eor             v0.16b, v0.16b, v16.16b
.set k, (k - 1)
.endr

        aesimc          v0.16b, v0.16b                  // final round: no key
        aesd            v0.16b, v30.16b
        ldr             q16, [x0]                       // rk[0] = FK0: final EOR
        eor             v0.16b, v0.16b, v16.16b
        st1             {v0.16b}, [x1], #16

        subs            w3, w3, #1
        b.ne            2b

4:      ret
endfunc
.endm

AES_ENCRYPT 10
AES_ENCRYPT 12
AES_ENCRYPT 14
AES_DECRYPT 10
AES_DECRYPT 12
AES_DECRYPT 14

