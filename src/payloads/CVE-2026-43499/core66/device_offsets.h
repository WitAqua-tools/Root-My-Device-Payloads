/* OPPO PMG110 (ColorOS 16.0.8, MT6991 / Dimensity 9400) — GKI 6.6, 4K pages
 *
 * Extracted from the stock OTA boot.img with:
 *   python3 tools/extract_device.py boot.img --name pmg110
 *
 * ashmem is the C driver on this build (not the Rust one used by Ace 6T), so
 * off_ashmem_* point at ashmem_{ioctl,mmap,...} / compat_ashmem_ioctl, and
 * off_ashmem_misc_fops is the fops member of `struct miscdevice ashmem_misc`
 * (ashmem_misc + 0x10) — verified to hold &ashmem_fops in the image.
 *
 * NOTE: this kernel is 6.6, whose task_struct / file_operations layout differs
 * from the 6.12 layout baked into src/core/target.h. Build with
 * `make TARGET=pmg110` so src/devices/pmg110/target.h is used instead.
 */

OFFSETS_ENTRY("6.6.118-android15-8-g93e223c276e7-abogki500782043-4k",  /* PMG110_16.0.8.300(CN01) */
  .layout="pmg110-6.6",
  .off_init_task=0x0213E780, .off_init_cred=0x02150C48, .off_init_uts_ns=0x022C41C8,
  .off_empty_zero_page=0x02330000, .off_root_task_group=0x02338580,
  .off_selinux_enforcing=0x0237B220, .off_kptr_restrict=0x0213C1F8,
  .off_selinux_blob_sizes=0x0168EA28, .off_security_hook_heads=0x0168E2F0,
  .off_kmalloc_caches=0x0168DE30, .off_anon_pipe_buf_ops=0x0117F188,
  .off_ashmem_misc_fops=0x0229D268, .off_ashmem_fops=0x012FFF00,
  .off_ashmem_ioctl=0x00C9B0B0, .off_ashmem_compat_ioctl=0x00C9B76C,
  .off_ashmem_mmap=0x00C9B7C0, .off_ashmem_open=0x00C9B9E0,
  .off_ashmem_release=0x00C9BA68, .off_ashmem_show_fdinfo=0x00C9BAF4,
  .off_configfs_read_iter=0x0049FC10, .off_configfs_bin_write_iter=0x0049FE18,
  .off_copy_splice_read=0x004235E0, .off_noop_llseek=0x003D6340,
  .off_cap_capable_active=0,  /* no security_hook_active_* on this 6.6 build */
  .off_slide_nfulnl_logger=0x02132750, .off_slide_loggers_0_1=0x021326A8,
  .off_slide_boot_id=0x0239C218,
),
