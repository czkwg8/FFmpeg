/*
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

#include "libavutil/cpu.h"
#include "libavutil/cpu_internal.h"
#include "config.h"

#if defined(__linux__) || defined(__ANDROID__)
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if HAVE_GETAUXVAL
#include <sys/auxv.h>
#endif

#ifndef AT_HWCAP
#define AT_HWCAP 16
#endif
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif

static int detect_flags(void)
{
    int flags = 0;
#if HAVE_GETAUXVAL
    unsigned long hwcap = getauxval(AT_HWCAP);
    if (hwcap & HWCAP_AES)
        flags |= AV_CPU_FLAG_ARM_AES;
#else
    FILE *f = fopen("/proc/self/auxv", "r");
    if (f) {
        struct { unsigned long a_type; unsigned long a_val; } auxv;
        while (fread(&auxv, sizeof(auxv), 1, f) > 0) {
            if (auxv.a_type == AT_HWCAP) {
                if (auxv.a_val & HWCAP_AES)
                    flags |= AV_CPU_FLAG_ARM_AES;
                break;
            }
        }
        fclose(f);
    }
#endif
    return flags;
}
#elif defined(__APPLE__) && defined(__aarch64__)
static int detect_flags(void)
{
    return AV_CPU_FLAG_ARM_AES;
}
#elif defined(_WIN32) && defined(_M_ARM64)
#include <windows.h>
static int detect_flags(void)
{
    int flags = 0;
#ifdef PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE
    if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE))
        flags |= AV_CPU_FLAG_ARM_AES;
#endif
    return flags;
}
#else
static int detect_flags(void)
{
    return 0;
}
#endif

int ff_get_cpu_flags_aarch64(void)
{
    int flags = AV_CPU_FLAG_ARMV8 * HAVE_ARMV8 |
                AV_CPU_FLAG_NEON  * HAVE_NEON  |
                AV_CPU_FLAG_VFP   * HAVE_VFP;

#if defined(__ARM_FEATURE_CRYPTO) || defined(__ARM_FEATURE_AES)
    flags |= AV_CPU_FLAG_ARM_AES;
#else
    flags |= detect_flags();
#endif

    return flags;
}

size_t ff_get_cpu_max_align_aarch64(void)
{
    int flags = av_get_cpu_flags();

    if (flags & AV_CPU_FLAG_NEON)
        return 16;

    return 8;
}
