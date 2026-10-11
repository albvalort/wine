/*
 * Futex emulation for fsync on macOS, on top of the XNU ulock interface
 *
 * Copyright 2026 Proton-macOS contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef __WINE_WINE_DARWIN_FUTEX_H
#define __WINE_WINE_DARWIN_FUTEX_H

#ifdef __APPLE__

#include <errno.h>
#include <stdint.h>

/* fsync keeps all synchronization state in a shared memory section and relies on three futex
 * operations: wake all waiters of a word, wait on one word and wait on several words at once
 * (futex_waitv). XNU's __ulock_wait2/__ulock_wake (macOS 11+, used by libc and libdispatch)
 * provide the first two across processes with UL_COMPARE_AND_WAIT_SHARED.
 *
 * There is no multi-word wait, so waiting on several words uses a shared wake epoch: wakers bump
 * the epoch after changing a word and, if anybody is in a multi-word wait, wake the epoch.
 * Multi-word waiters register, read the epoch, check their words and sleep on the epoch.
 * With sequentially consistent atomics no wakeup can be lost; spurious wakeups are harmless
 * because fsync always re-checks the objects after a wait. The control block lives in the
 * otherwise unused shm index 0. */

#define DARWIN_UL_COMPARE_AND_WAIT_SHARED 3
#define DARWIN_ULF_WAKE_ALL               0x00000100
#define DARWIN_ULF_NO_ERRNO               0x01000000

/* timeout_ns value for a deadline that has already passed: check the words, never sleep.
 * (A tiny ulock timeout would still arm a coalesced kernel timer and take tens of us.) */
#define DARWIN_FUTEX_EXPIRED              UINT64_MAX

extern int __ulock_wait2( uint32_t operation, void *addr, uint64_t value, uint64_t timeout_ns, uint64_t value2 );
extern int __ulock_wake( uint32_t operation, void *addr, uint64_t wake_value );

/* Spin briefly before sleeping: waking a thread blocked in the kernel costs several
 * microseconds on Apple Silicon, while many waits are satisfied within that time.
 * Override with WINE_MSYNC_SPIN (iterations, 0 disables). */
#define DARWIN_FUTEX_DEFAULT_SPIN 4000

static inline void darwin_cpu_relax(void)
{
#if defined(__x86_64__) || defined(__i386__)
    __builtin_ia32_pause();
#elif defined(__aarch64__)
    __asm__ __volatile__( "yield" );
#endif
}

extern int darwin_futex_spin_count;

struct darwin_futex_ctl
{
    int epoch;          /* bumped on every wake */
    int multi_waiters;  /* threads currently in a multi-word wait */
};

/* Wait while *addr == val, for at most timeout_ns (0 = infinite).
 * Returns 0 when woken (or the value already differed), -ETIMEDOUT or -EINTR. */
static inline int darwin_ulock_wait( int *addr, int val, uint64_t timeout_ns )
{
    int ret = __ulock_wait2( DARWIN_UL_COMPARE_AND_WAIT_SHARED | DARWIN_ULF_NO_ERRNO, addr, (uint32_t)val, timeout_ns, 0 );

    /* The shared lookup does not fault pages in; touch the page and retry once. */
    if (ret == -EFAULT)
    {
        (void)*(volatile int *)addr;
        ret = __ulock_wait2( DARWIN_UL_COMPARE_AND_WAIT_SHARED | DARWIN_ULF_NO_ERRNO, addr, (uint32_t)val, timeout_ns, 0 );
    }
    if (ret >= 0) return 0;
    return ret;
}

/* Wake every waiter of addr, whose value the caller has already changed. */
static inline void darwin_futex_wake( struct darwin_futex_ctl *ctl, int *addr )
{
    __ulock_wake( DARWIN_UL_COMPARE_AND_WAIT_SHARED | DARWIN_ULF_WAKE_ALL | DARWIN_ULF_NO_ERRNO, addr, 0 );
    __atomic_add_fetch( &ctl->epoch, 1, __ATOMIC_SEQ_CST );
    if (__atomic_load_n( &ctl->multi_waiters, __ATOMIC_SEQ_CST ))
        __ulock_wake( DARWIN_UL_COMPARE_AND_WAIT_SHARED | DARWIN_ULF_WAKE_ALL | DARWIN_ULF_NO_ERRNO, &ctl->epoch, 0 );
}

/* Wait until any addrs[i] != vals[i] is signaled, for at most timeout_ns (0 = infinite,
 * DARWIN_FUTEX_EXPIRED = deadline already passed).
 * Returns 0 when woken, -EAGAIN if a value already differs, -ETIMEDOUT or -EINTR. */
static inline int darwin_futex_wait_multiple( struct darwin_futex_ctl *ctl, int *const *addrs, const int *vals,
                                              int count, uint64_t timeout_ns )
{
    int i, epoch, ret;

    if (timeout_ns == DARWIN_FUTEX_EXPIRED)
    {
        for (i = 0; i < count; i++)
            if (__atomic_load_n( addrs[i], __ATOMIC_SEQ_CST ) != vals[i]) return -EAGAIN;
        return -ETIMEDOUT;
    }

    for (ret = 0; ret < darwin_futex_spin_count; ret++)
    {
        for (i = 0; i < count; i++)
            if (__atomic_load_n( addrs[i], __ATOMIC_RELAXED ) != vals[i]) return -EAGAIN;
        darwin_cpu_relax();
    }

    if (count == 1)
    {
        if (__atomic_load_n( addrs[0], __ATOMIC_SEQ_CST ) != vals[0]) return -EAGAIN;
        return darwin_ulock_wait( addrs[0], vals[0], timeout_ns );
    }

    __atomic_add_fetch( &ctl->multi_waiters, 1, __ATOMIC_SEQ_CST );
    epoch = __atomic_load_n( &ctl->epoch, __ATOMIC_SEQ_CST );
    for (i = 0; i < count; i++)
    {
        if (__atomic_load_n( addrs[i], __ATOMIC_SEQ_CST ) != vals[i])
        {
            __atomic_sub_fetch( &ctl->multi_waiters, 1, __ATOMIC_SEQ_CST );
            return -EAGAIN;
        }
    }
    ret = darwin_ulock_wait( &ctl->epoch, epoch, timeout_ns );
    __atomic_sub_fetch( &ctl->multi_waiters, 1, __ATOMIC_SEQ_CST );
    return ret;
}

#endif /* __APPLE__ */

#endif /* __WINE_WINE_DARWIN_FUTEX_H */
