#ifndef ONEPLUS_PAD3_EX01_STRUCT_OFFSETS_H
#define ONEPLUS_PAD3_EX01_STRUCT_OFFSETS_H

/*
 * Exact BTF-derived layout for the OPD2415 kernel Image.
 * Raw BTF sha256: 126141db2e40972c63fa12b2e080faa86080314e3a8bee0f0ccc420ad6a39d67
 */

/* struct rt_mutex_waiter, sizeof 0x70. */
#define RT_MUTEX_WAITER_SIZE       0x70
#define WAITER_LOCAL_OFF          0x80
#define WAITER_TREE_ENTRY_OFF     0x00
#define WAITER_PI_TREE_ENTRY_OFF  0x28
#define WAITER_TASK_OFF           0x50
#define WAITER_LOCK_OFF           0x58
#define WAITER_WAKE_STATE_OFF     0x60
#define WAITER_PRIO_OFF           0x18
#define WAITER_DEADLINE_OFF       0x20
#define WAITER_WW_CTX_OFF         0x68

#define FAKE_WAITER_TREE_PRIO_OFF         0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF     0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF     0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF      0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF  0x48
#define FAKE_WAITER_TASK_OFF              0x50
#define FAKE_WAITER_LOCK_OFF              0x58
#define FAKE_WAITER_WAKE_STATE_OFF        0x60
#define FAKE_WAITER_WW_CTX_OFF            0x68

/* struct task_struct, sizeof 0x12c0. */
#define TASK_STACK_OFF              0x38
#define TASK_THREAD_SIZE            0x4000
#define FAKE_TASK_USAGE_OFF          0x40
#define FAKE_TASK_PRIO_OFF           0x84
#define FAKE_TASK_NORMAL_PRIO_OFF    0x8c
#define FAKE_TASK_TASK_GROUP_OFF     0x348
#define FAKE_TASK_PI_LOCK_OFF        0x90c
#define FAKE_TASK_PI_WAITERS_OFF     0x920
#define FAKE_TASK_PI_TOP_TASK_OFF    0x930
#define FAKE_TASK_PI_BLOCKED_ON_OFF  0x938

#define MM_OWNER_OFF             0x2b0
#define TASK_PID_OFF             0x618
#define TASK_TGID_OFF            0x61c
#define TASK_REAL_PARENT_OFF     0x628
#define TASK_PARENT_OFF          0x630
#define TASK_CHILDREN_OFF        0x638
#define TASK_SIBLING_OFF         0x648
#define TASK_GROUP_LEADER_OFF    0x658
#define TASK_THREAD_GROUP_OFF    0x6c8
#define TASK_THREAD_NODE_OFF     0x6d8
#define TASK_ATOMIC_FLAGS_OFF    0x5d8
#define TASK_REAL_CRED_OFF       0x818
#define TASK_CRED_OFF            0x820
#define TASK_COMM_OFF            0x830
#define TASK_TASKS_OFF           0x550
#define TASK_SIGNAL_OFF          0x878
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF         0x8e8

/* struct signal_struct, sizeof 0x470. */
#define SIGNAL_NR_THREADS_OFF    0x08
#define SIGNAL_THREAD_HEAD_OFF   0x10

/* struct cred, sizeof 0xb8; struct seccomp, sizeof 0x10. */
#define CRED_USAGE_OFF       0x00
#define CRED_UID_OFF         0x08
#define CRED_SECUREBITS_OFF  0x28
#define CRED_CAPS_OFF        0x30
#define CRED_SECURITY_OFF    0x80
#define CRED_USER_NS_OFF     0x90
#define SELINUX_CRED_BLOB_OFF 0x00
#define SELINUX_CRED_OSID_OFF  0x00
#define SELINUX_CRED_SID_OFF   0x04
#define SECCOMP_MODE_OFF          0x00
#define SECCOMP_FILTER_COUNT_OFF  0x04
#define SECCOMP_FILTER_OFF        0x08
#define TIF_SECCOMP_BIT           11
#define PFA_NO_NEW_PRIVS_BIT      0

/* struct page, sizeof 0x40. */
#define STRUCT_PAGE_SIZE              0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF         0x08
#define STRUCT_PAGE_TYPE_OFF          0x30

/* struct pipe_inode_info, sizeof 0xb8. */
#define PIPE_BUFFER_SIZE              0x28
#define PIPE_BUFFER_SLOTS             32
#define PIPE_BUF_FLAG_CAN_MERGE       0x10
#define PIPE_INODE_INFO_STRUCT_SIZE   0xb8
#define PIPE_INODE_INFO_SIZE          0xc0
#define PIPE_INODE_INFO_SLOTS_PER_PAGE 21
#define PIPE_HEAD_OFF                 0x60
#define PIPE_TAIL_OFF                 0x64
#define PIPE_MAX_USAGE_OFF            0x68
#define PIPE_RING_SIZE_OFF            0x6c
#define PIPE_NR_ACCOUNTED_OFF         0x70
#define PIPE_READERS_OFF              0x74
#define PIPE_WRITERS_OFF              0x78
#define PIPE_FILES_OFF                0x7c
#define PIPE_TMP_PAGE_OFF             0x90
#define PIPE_BUFS_OFF                 0xa8
#define PIPE_USER_OFF                 0xb0

/* struct file_operations, sizeof 0x108 (6.6 has no fop_flags). */
#define FOPS_OWNER_OFF        0x00
#define FOPS_LLSEEK_OFF       0x08
#define FOPS_READ_OFF         0x10
#define FOPS_WRITE_OFF        0x18
#define FOPS_READ_ITER_OFF    0x20
#define FOPS_WRITE_ITER_OFF   0x28
#define FOPS_IOCTL_OFF        0x48
#define FOPS_COMPAT_IOCTL_OFF 0x50
#define FOPS_MMAP_OFF         0x58
#define FOPS_OPEN_OFF         0x68
#define FOPS_RELEASE_OFF      0x78
#define FOPS_SPLICE_READ_OFF  0xb8
#define FOPS_SHOW_FDINFO_OFF  0xd8

#endif
