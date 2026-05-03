/* Kernel-side logging helpers. */

//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// @@@@ When a process is ptraced, or there are similar operations with the
// @@@@ potential to compromise a subject, its versio should be incremented
// @@@@ so that subsequent outflows are not suppressed by dependence tracking.

//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// TODO: Except for special cases where there is too much data (e.g., execve, 
//    mmap) or the risk of delaying a critical event (e.g., ptrace, kill), we
//    should match up entry and exits here. Matching them at the user level isn't
//    100% reliable, as events are buffered and may be delivered out of order.
//    In particular, user level cannot guarantee that the entry and exits of
//    two instances of the same system call are matched up correctly. 
//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// The bpfcc toolchain does not seem to envision larger C programs, so the tools
// seem to break any time you try to divide up the source code into multiple
// files and include them. The magic rewrites they do on the C programs seem
// prone to breaking when there are inclusions or macros. 
//%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// There is also a major fragility in the verifier that causes it to fail
// on inconsequential code changes. This seems related to our extensive use of
// variable size records. Often, our only option is trial and error, involving
// some reordering of unrelated statements. Fortunately, these failures seem
// mostly consistent across Linux kernel versions, so we have to do this just
// once, and not have to maintain different versions for different kernels.

#include <uapi/asm-generic/siginfo.h>
#include <uapi/asm-generic/statfs.h>
#include <uapi/asm-generic/mman.h>
#include <uapi/linux/mman.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/capability.h>
#include <uapi/linux/fs.h>

#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/ipv6.h>

#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/af_unix.h>

#include "eauditk.h"

#define LOCK_CACHE
#ifdef PERCPU_CACHE
#undef LOCK_CACHE
#undef FLUSH_CACHE_1
#undef FLUSH_CACHE_2
#endif

// Define ignore_failed_calls at build time to suppress provenance records
// for system calls that returned kernel error codes (see is_err in eauditk.h).
// #define IGNORE_FAILED_CALLS

#define cached_toolong(len, tso, tsc)  (len && tsc >= tso + MAXCACHETIME)
#define cached_far_toolong(len, tso, tsc)  (len && tsc > tso + (3*MAXCACHETIME)/2)
#define cached_max_interval(len, tso, tsc) (len && tsc > tso +(3*MAXCACHETIME))

#ifdef ID_NOT_FD
#undef LOG_DUP
#undef LOG_PIPE
#endif

#ifdef FILTER_REP_RDWR
#undef LOG_MMAPALL
#ifdef FILTER_REP_OPEN
#undef LOG_CLOSE
#endif
#endif

#define mymin(x, y) ((x) < (y) ? (x) : (y))
// We use pid and tid as they are used in userland. (Kernel's tgid becomes
// our pid, while kernel's pid becomes our tid.)
static inline int 
gettid() {
   // Lower 32 bits encode task/thread id
   return bpf_get_current_pid_tgid() & 0xffffffff;
}

static inline int 
getpid() {
   return (bpf_get_current_pid_tgid() >> 32) & 0xffffffff;;
}

static inline u64
gettidpid(int *tid, int *pid) {
   u64 pid_tgid = bpf_get_current_pid_tgid();
   *tid = pid_tgid & 0xffffffff;
   *pid = (pid_tgid >> 32) & 0xffffffff;
   return pid_tgid;
}

/****************************************************************************** 
 * Start with some helper functions for accessing status/error counters.      *
 *****************************************************************************/
static inline void incr_sc_entry(int sc) { count.atomic_increment(sc); }

static inline void rdwr_recorded() { mystat.atomic_increment(RDWR_RECORDED); }
static inline void rdwr_suppressed() { mystat.atomic_increment(RDWR_SUPPRESSED); }
static inline void fcntl_err() { mystat.atomic_increment(FCNTL_ERR); }
static inline void pipe_err() { mystat.atomic_increment(PIPE_ERR); }
static inline void saddr_err() { mystat.atomic_increment(SADDR_ERR); }
static inline void mmap_err() { mystat.atomic_increment(MMAP_ERR); }
static inline void string_err() { mystat.atomic_increment(FN_ERR); }
static inline void data_read_ok() { mystat.atomic_increment(DATA_READ_OK); }
static inline void string_trunc_err() { mystat.atomic_increment(FN_TRUNC_ERR); }
static inline void data_trunc_err() { mystat.atomic_increment(DATA_TRUNC_ERR); }
static inline void argv_err() { mystat.atomic_increment(ARGV_ERR); }

static inline void open_data_err() { mystat.atomic_increment(OPEN_DATA_ERR); }
static inline void pipe_read_data_err() 
  { mystat.atomic_increment(PIPE_READ_DATA_ERR); }
static inline void saddr_read_data_err() 
  { mystat.atomic_increment(SADDR_READ_DATA_ERR); }
static inline void saddr_data_err() { mystat.atomic_increment(SADDR_DATA_ERR); }
static inline void conn_data_err() { mystat.atomic_increment(CONN_DATA_ERR); }
static inline void sendto_data_err()  { mystat.atomic_increment(SENDTO_DATA_ERR);}
static inline void bind_data_err()  { mystat.atomic_increment(BIND_DATA_ERR);}
static inline void fd_unfound_err(){mystat.atomic_increment(FD_UNFOUND_ERR);}
static inline void file_unfound_err(){mystat.atomic_increment(FILE_UNFOUND_ERR);}
static inline void pipe_unfound_err(){mystat.atomic_increment(PIPE_UNFOUND_ERR);}
static inline void sock_unfound_err(){mystat.atomic_increment(SOCK_UNFOUND_ERR);}
static inline void inode_unfound_err()  
  { mystat.atomic_increment(INODE_UNFOUND_ERR);}

static inline void subjinfo_hard_fail(){mystat.atomic_increment(SUBJINFO_ERR); }
static inline void undeleted_subjinfo(){mystat.atomic_increment(SUBJINFO_UNDELETED);}
static inline void deleted_subjinfo(){mystat.atomic_increment(SUBJINFO_DELETED);}
static inline void subjinfo_overflow(){mystat.atomic_increment(SUBJINFO_OVERFLOW);}
static inline void inc_subj(){mystat.atomic_increment(NUM_SUBJ_CREATED);}
//static inline void inc_obj(){mystat.atomic_increment(NUM_OBJ_CREATED);}

static inline void objinfo_hard_fail(){mystat.atomic_increment(OBJINFO_ERR); }
static inline void deleted_objinfo(){mystat.atomic_increment(OBJINFO_DELETED);}
static inline void objinfo_overflow(){mystat.atomic_increment(OBJINFO_OVERFLOW); }

static inline void fi_hard_fail(){mystat.atomic_increment(FILEINFO_ERR); }
static inline void deleted_fi(){mystat.atomic_increment(FILEINFO_DELETED); }
static inline void deleted_fdinfo(){mystat.atomic_increment(FDINFO_DELETED); }

static inline void fdtoid_calls(){mystat.atomic_increment(FDTOID_CALLS);}
static inline void fdtoid_errs(){mystat.atomic_increment(FDTOID_ERRS);}
// indicates that the id became zero. Document why (if?) this matters.

static inline void sidoid_collision(){mystat.atomic_increment(SIDOID_COLLISION);}
static inline void file_reuse_succ(){mystat.atomic_increment(FILE_REUSE_SUCC);}
static inline void file_reuse_fail(){mystat.atomic_increment(FILE_REUSE_FAIL);}
static inline void file_reuse_stale(){mystat.atomic_increment(FILE_REUSE_STALE);}
static inline void missed_file_reuse(){mystat.atomic_increment(FILE_REUSE_MISSED);}
static inline void per_thr_fi_subj(){mystat.atomic_increment(PER_THR_FI_SUBJ);}
static inline void deleted_oi_tmp_cache()
   {mystat.atomic_increment(DELETED_OI_IN_TMP_CACHE);}
static inline void sc_dropped_lock_contention()
   {mystat.atomic_increment(LOCK_FAIL_LOST_SYSCALLS);}
static inline void unexp_map_lookup_err()
   {mystat.atomic_increment(UNEXP_MAP_LOOKUP_FAIL);}

BPF_HISTOGRAM(cache_flush_lag);
BPF_HISTOGRAM(msg_delivery_lag);

// BPF_HISTOGRAM(fduse);
// BPF_HISTOGRAM(fduset);
static inline void
profile_fd(int fd, int f) {
#ifndef NO_INSTRUMENT
   //if (f == 1)
   //   fduse.increment(bpf_log2l(fd));
   //else fduset.increment(bpf_log2l(fd));
#endif
}

#ifdef NO_INSTRUMENT
#define incr_sc_entry(sc)
#define rdwr_recorded()
#define rdwr_suppressed()
#endif

/****************************************************************************** 
 ******************************************************************************
 * Helper functions for marshalling data, i.e., copy data into the per-CPU    *
 * buffer and update the relevant header fields.                              *
 *****************************************************************************/
static inline u8 addLong(u8* buf, long v) {
   char v0 = v & 0xff;
   if (v0 == v) {
      *buf = v0;
      return 0;
   }
   short v1 = v & 0xffff;
   if (v1 == v) {
      *(u16*)buf = v1;
      return 1;
   }
   int v2 = v & 0xffffffff;
   if (v2 == v) {
      *(u32*)buf = v2;
      return 2;
   }
   *(u64*)buf = v;
   return 3;
}

/*
   Here are the functions for extra long args
*/
static inline void add_long_full(u8* buf, long v) {
   *(u64*)buf = v;
}

static inline void 
add_long_ex(struct buf* b, long a1, u16* idx) {
   add_long_full(&b->d[*idx], a1);
   *idx += 8;
}

static inline void 
add_long2_ex(struct buf* b, long a1, long a2, u16* idx) {
   add_long_ex(b, a1, idx);
   add_long_ex(b, a2, idx);
}

/******************************************************************************
 * The following three functions, in addition to adding long arguments to the *
 * buffer, additionally set header fields to indicate their lengths. There    *
 * enough bits to support this variable length encoding for up to 3 long args.*
 *****************************************************************************/
static inline void 
add_long1(struct buf* b, long a1, u16* idx, u16 hdr) {
   u8 sz1 = addLong(&b->d[*idx], a1);
   *idx += (1<<sz1);
   b->d[hdr] |= (sz1<<4);
}

static inline void 
add_long2(struct buf* b, long a1, long a2, u16* idx, u16 hdr) {
   u8 sz1 = addLong(&b->d[*idx], a1);
   *idx += (1<<sz1);
   u8 sz2 = addLong(&b->d[*idx], a2);
   *idx += (1<<sz2);
   b->d[hdr] |= (sz1<<4) | (sz2<<2);
}

static inline void 
add_long3(struct buf* b, long a1, long a2, long a3, u16* idx, u16 hdr) {
   u8 sz1 = addLong(&b->d[*idx], a1);
   *idx += (1<<sz1);
   u8 sz2 = addLong(&b->d[*idx], a2);
   *idx += (1<<sz2);
   u8 sz3 = addLong(&b->d[*idx], a3);
   *idx += (1<<sz3);
   b->d[hdr] |= (sz1<<4) | (sz2<<2) | sz3;
}

/******************************************************************************
 * More helper functions for adding strings, adding multiple strings, and     *
 * length-prefixed binary data.                                               *
 *****************************************************************************/
static inline void
add_string(struct buf* b, const char* fn, u16 *idx) {
  *idx += 1; // Space for the length byte.
  if(*idx < BUFSIZE-200){
    int n = bpf_probe_read_str(&b->d[*idx], mymin(MAX_SLEN, BUFSIZE-(*idx)-3),fn);
   // n = max(n, 1);

   if (n < 0) {
   string_err();
   n = 0;
   }
   // Invariant: n >= 0

   if(*idx < BUFSIZE- 200) b->d[*idx-1] = n; // Set str len, incl trailing null
   *idx += n;        // Advance index by string length.
  } else {
    // Buffer nearly full: write a zero-length byte so the parser skips this
    // entry safely. Without this, stale garbage at d[*idx-1] is misread as a
    // string length, desynchronising the entire parse stream.
    if (*idx >= 1 && *idx - 1 < BUFSIZE)
        b->d[*idx - 1] = 0;
  }
}

static inline u16
add_str_array0_16(struct buf* b, const char* const *argv, u16 *idx) {

   u8 rv = 0;    
   const char* argarray[16];
   const char** arga = argarray;

   if (bpf_probe_read_user(argarray, sizeof(argarray), argv)) {
      argv_err();
      return 0;
   }

   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #1
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #2
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #3
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #4
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #5
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #6
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #7
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #8
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #9
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #10
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #11
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #12
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #13
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #14
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #15
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #16
   return rv;
}

static inline u16
add_str_array0_32(struct buf* b, const char* const *argv, u16 *idx) {

   u8 rv = 0;    
   const char* argarray[32];
   const char** arga = argarray;

   if (bpf_probe_read_user(argarray, sizeof(argarray), argv)) {
      argv_err();
      return 0;
   }

   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #1
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #2
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #3
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #4
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #5
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #6
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #7
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #8
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #9
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #10
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #11
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #12
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #13
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #14
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #15
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #16
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #17
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #18
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #19
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #20
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #21
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #22
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #23
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #24
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #25
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #26
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #27
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #28
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #29
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #30
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #31
   if (!*arga) return rv;
   add_string(b, *arga, idx); arga++; rv++; // arg #32
   return rv;
}

static inline int
add_data(struct buf* b, u8* data, int dlen, u16 *idx) {
   int fail=0;
   u8 len = mymin(MAX_DLEN, dlen);
   if (0 < len && len <= BUFSIZE-(*idx)-3) {
      fail = bpf_probe_read(&b->d[1+*idx], len, data);
      if (fail) {
         //data_err();
         len = 0;
      }
      if (len == MAX_DLEN)
         data_trunc_err();
      else data_read_ok();
   }
   else len = 0;
   if(*idx < BUFSIZE-200) b->d[*idx] = len;
   *idx += len+1; // Advance index by length plus space for len field.
   return fail;
}

static inline void 
add_binary(struct buf* b, const uint64_t key[2], int len, u16 *idx) {
   *idx += 1;  
   if (*idx < BUFSIZE - 200) {
      int n = bpf_probe_read(&b->d[*idx], len / 2, (const void *)&key[0]);
      if (n < 0) {
         string_err(); 
         n = 0;
      }
      n = bpf_probe_read(&b->d[*idx + 8], 8, (const void *)&key[1]);
      if (n < 0) {
         string_err();
         n = 0;
      }
      if (*idx < BUFSIZE - 200) {
         b->d[*idx - 1] = len; 
      }
      *idx += len;
   }
}


static inline u16
add_pad_0_16(struct buf* b, u16 *idx, u16 pad_bytes) {
   // *idx += 1;
   // if ( pad_bytes > 0 && *idx < BUFSIZE ) {
   //    b->d[i] = '\0';
   // }
   u16 bytes_added = 0;
   // u16 current_idx = *idx;
   // u16 safe_pad_bytes = pad_bytes;
   // if (current_idx >= BUFSIZE) {
   //     safe_pad_bytes = 0;
   // } else if (current_idx + pad_bytes > BUFSIZE) {
   //     safe_pad_bytes = BUFSIZE - current_idx;
   // }

   // // Completely unrolled writes with explicit bounds checking
   // if (bytes_added < safe_pad_bytes) { b->d[current_idx + 1 + bytes_added] = 0x00; bytes_added++; }
   // if (bytes_added < safe_pad_bytes) { b->d[current_idx + 1 + bytes_added] = 0x00; bytes_added++; }
   // if (bytes_added < safe_pad_bytes) { b->d[current_idx + 1 + bytes_added] = 0x00; bytes_added++; }
   // if (bytes_added < safe_pad_bytes) { b->d[current_idx + 1 + bytes_added] = 0x00; bytes_added++; }
   // if (bytes_added < safe_pad_bytes) { b->d[current_idx + 1 + bytes_added] = 0x00; bytes_added++; }
   // if (bytes_added < safe_pad_bytes) { b->d[current_idx + 1 + bytes_added] = 0x00; bytes_added++; }
   // if (bytes_added < safe_pad_bytes) { b->d[current_idx + 1 + bytes_added] = 0x00; bytes_added++; }
   // if (bytes_added < safe_pad_bytes) { b->d[current_idx + 1 + bytes_added] = 0x00; bytes_added++; }

   *idx += bytes_added;


   // int written = *idx - start_idx;

//    if (*idx < BUFSIZE - 200) {
//       b->d[*idx - written] = written;  // Store the exact binary length
//   }

    return bytes_added;  // Return number of bytes actually padded
}

/****************************************************************************** 
 ******************************************************************************
 * check_xmit1 and check_xmit2 are the only two functions that copy data from
 * the message caches to ring buffer. Both are called by check_xmit, which is in
 * turn called by finish(), the sole function that is called at the end of
 * producing each record. check_xmit1() checks if the cache of the current CPU
 * should be emptied after finishing the record. check_xmit2() is called to
 * empty the cache of another CPU, if that data has been sitting around on that
 * (idle) CPU's cache for too long. It is called by check_xmit(), and the CPU
 * checked is determined by the current sequence number.
 ******************************************************************************/

static inline void check_xmit1(struct buf* b, u16 *i, u64 ts, 
                               int force_tx, int force_wake) {
   if (force_tx || cached_toolong(b->idx, b->start_ts, ts)) {
      u32 rnd = bpf_get_prandom_u32();
      int err=1, flag;
      int sz = mymin(BUFSIZE-1, *i + 8); // Add the size of TSMS record
      if (force_wake || (rnd < (((u32)-1)/RINGBUF_PUSH_INTERVAL)))
         flag = BPF_RB_FORCE_WAKEUP;
      else flag = BPF_RB_NO_WAKEUP;

      mystat.atomic_increment(RB_MSGS);
      if (flag == BPF_RB_FORCE_WAKEUP)
         mystat.atomic_increment(RB_WAKEUPS);
      mystat.atomic_increment(RB_BYTES, *i+8); // # of bytes ATTEMPTED to send

      b->tsrec = TS_RECORD(MS_BITS(b->start_ts));
      // NOTE: we cannot use the reserve/commit API because the verifier
      // requires the size to be a compile-time constant. 

      // The verifier is really finicky on ringbuf access. Unfortunately, the
      // nature of this finickiness changes with the kernel versions. We don't
      // know the exact kernel version to use in the following ifdef
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,12,0)
      //if (sz < BUFSIZE-128)
      if (sz < BUFSIZE-128)
#else
      sz = mymin(sz, BUFSIZE-64);
#endif
         err = events.ringbuf_output(&b->tsrec, sz, flag);

      b->idx = 0;
      b->weight = 0;
      *i = 0;

      if (err)
         mystat.atomic_increment(RB_FAIL);
   }
}

// @@@@ The verifier is very poor at handling copies. When a copy is made,
// @@@@ it does not propagate the known constraints on the values across
// @@@@ copies. This leads to bounds verification failure. Current solution
// @@@@ is trial-and-error to get the compiler and verifier to use the same
// @@@@ register for the bounds checked value and the index. The copy of
// @@@@ check_xmit1 was made to enable this. In the process, we took the
// @@@@ liberty of simplifying away the logic unneeded in the context of xmit2.

static inline void check_xmit2(struct buf* b) {
   int err=1, flag = BPF_RB_FORCE_WAKEUP;
   int sz = mymin(BUFSIZE-1, b->idx+8);
   mystat.atomic_increment(RB_MSGS);
   mystat.atomic_increment(NONLOCAL_CACHE_FLUSHES);
   mystat.atomic_increment(RB_BYTES, b->idx+8); // # of bytes ATTEMPTED to send
   mystat.atomic_increment(RB_WAKEUPS);

   if (sz < (u16)BUFSIZE) { // Always true, but verifier may need help.
         // NOTE: we cannot use the reserve/commit API because the verifier
         // requires the size to be a compile-time constant. 
      b->tsrec = TS_RECORD(MS_BITS(b->start_ts));
      err = events.ringbuf_output(&b->tsrec, sz, flag);
   }            

   b->idx = 0;
   b->weight = 0;

   if (err)
      mystat.atomic_increment(RB_FAIL);
}

static inline void check_xmit3(struct buf* b, u16 *i, u64 ts) {
   if (cached_toolong(b->idx, b->start_ts, ts)
#ifndef FULL_TIME
        || (MS_BITS(b->start_ts) != MS_BITS(ts))
#endif
       )
      check_xmit1(b, i, ts, 1, 0);
}

// Need to define a couple of helpers before check_xmit can be defined

// Cache selection: We need to avoid contention at the cache. The only way
// to do this is by selecting the cache from the CPU id. Other options, such
// as the use of sequence number or thread id's, don't work: two distinct
// sequence numbers (or tids) can hash to the same cache, and hence will
// cause contention. 

static inline int lock_cache_if_needed(struct buf* b, u64 ts) { 
/* returns 1 if lock unnecessary or successfully acquired */
#ifdef LOCK_CACHE 
   // Lock needed only if tsmsb is too long in the past. Note that the lock is
   // to guard against contention with another core that is cleaning up this
   // core's cache. That cleanup won't be attempted until 1.5*MAXCACHETIME, so
   // it is safe to skip the lock until MAXCACHETIME.
   // ALSO NOTE: cached_toolong returns true only when buf nonempty (i.e.
   // idx > 0) and cache age > MAXCACHETIME. It is possible that core j 
   // flushes core i and sets idx=0, and right at that time core i starts
   // to use the cache. Note that core i won't lock the cache in this case.
   // But this OK because the update of idx is the last step core j does 
   // on i's cache. Thus, core i is the only entity accessing cache i, so
   // nothing bad happened although it may have seemed that it incorrectly
   // accessed the cache without locking.

   if (!cached_toolong(b->idx, b->start_ts, ts)) // i.e., lock unnecessary
      return 1;
   if (!__sync_fetch_and_add(&b->lock, 1)) // lock acquired
      return 1;
   else if (b->nargvl > 0) // to avoid lock failure due to tail call getcache
      return 1;
   return 0;
#else
   return 1;
#endif
}         

// MUST NOT BE CALLED IF YOU DON'T HOLD THE LOCK
static inline void unlock_cache(struct buf* b) {
#ifdef LOCK_CACHE
   b->lock = 0;
#endif
}

static inline void flush_cache2(int cpu2check, u64 ts) {
   struct buf* bb = buf.lookup(&cpu2check);

   if (bb && cached_max_interval(bb->idx, bb->start_ts, ts)) {
      // bpf_trace_printk("Flush when A2 is active ");

   // if (bb && cached_far_toolong(bb->idx, bb->start_ts, ts)) {
      // if (ts - bb->start_ts < 100000000000000ul) // 100K seconds
         cache_flush_lag.increment(bpf_log2l((ts - bb->start_ts)/1000));

      // Note: No need to check that cpu2check isn't this CPU: in that case,
      // cached_far_toolong won't hold because we just called check_xmit1.
      // Triggered only when cpu2check has been idle for a long time, and
      // hence is unlikely to wake simultaneously. So, it is OK to handle
      // lock contention by dropping the syscall. Actually, this happens
      // only for lock fails by cpu2check; and not lock fails of this CPU.
      if (lock_cache_if_needed(bb, ts)) {
         check_xmit2(bb);
         unlock_cache(bb);
      }
      // If we don't get the lock, it must be the case that the core woke
      // up. If it is far_toolong, then too_long() will hold, and so the
      // cache will be emptied by the concerned core. No need for this
      // core to do it.
   }
}

static void flush_cache(int cpu2check, u64 ts) {
   struct buf* bb = buf.lookup(&cpu2check);
   if (bb && cached_far_toolong(bb->idx, bb->start_ts, ts)) {
      // if (ts - bb->start_ts < 100000000000000ul) // 100K seconds
         cache_flush_lag.increment(bpf_log2l((ts - bb->start_ts)/1000));

      // Note: No need to check that cpu2check isn't this CPU: in that case,
      // cached_far_toolong won't hold because we just called check_xmit1.
      // Triggered only when cpu2check has been idle for a long time, and
      // hence is unlikely to wake simultaneously. So, it is OK to handle
      // lock contention by dropping the syscall. Actually, this happens
      // only for lock fails by cpu2check; and not lock fails of this CPU.
      if (lock_cache_if_needed(bb, ts)) {
         check_xmit2(bb);
         unlock_cache(bb);
      }
      // If we don't get the lock, it must be the case that the core woke
      // up. If it is far_toolong, then too_long() will hold, and so the
      // cache will be emptied by the concerned core. No need for this
      // core to do it.
   }
}

static inline void check_xmit(struct buf* b, u16 *i, int force_tx, int wake) {
   u64 ts = b->current_ts;
   check_xmit1(b, i, ts, force_tx, wake);
              
   // Check if there is data that is stuck for too long on another core's cache.
   // Such a check is possible only if we are using a shared cache.
#ifdef FLUSH_CACHE_1
   int cpu2check = b->current_sn % NUMCPU;
   flush_cache(cpu2check, ts);
#endif
}

#define LOCKED_INCREMENT
BPF_ARRAY(seqn, u64, 1);  
BPF_ARRAY(curr_scc, u64, 1);
BPF_ARRAY(prev_scc, u64, 1);  
static inline 
u64 getSeqNum() {
      u64 sn=0;
      int z=0;
      u64* snp = seqn.lookup(&z);
      if (snp) {
#ifdef LOCKED_INCREMENT
         sn = __sync_fetch_and_add(snp, 1);
#else
         // A read before AND after seems to reduce the range of possible values,
         // i.e., reduces duplicate sequence numbers. 
         sn = *snp;
         lock_xadd(snp, 1);
         u64 sn1 = *snp;
         if (sn == sn1) // Never true, but the compiler can't figure this out, so
           sn = 0;      // it can't optimize away the second read of *snp.
#endif
      }
      else unexp_map_lookup_err();
      return sn;
}

static inline struct buf*
get_cache(u64 ts) {
   struct buf* b;
   int z = 0;
#ifndef PERCPU_CACHE
   z = bpf_get_smp_processor_id();
#endif

   b = buf.lookup(&z);
   if (!b) {
      unexp_map_lookup_err();
      return b;
   }

#ifndef PERCPU_CACHE
   if (!lock_cache_if_needed(b, ts)) {
      sc_dropped_lock_contention();
      b = NULL;
   }
#endif
   return b;
}

/****************************************************************************** 
 ******************************************************************************
 * Functions for initializing a new event record.                             *
 * init is used to initialize an _entry_ record. It updates the total         *
 * weight of the message (b->weight) but the other helpers don't.             *
 * It calls xmit to copy the per-CPU buffer b into the ring buffer when       *
 * it is too full (idx >= TX_THRESH) or if the MS bits of the timestamp       *
 * has changed from the one in the header of this message.                    *
 ******************************************************************************
 * NOTE: init() copies b->idx into a variable called i or idx, and this       *
 * variable is updated as more params are added to the buffer. Finally,       *
 * finish() copies i back into b->idx.                                        *
 ******************************************************************************/
 
static inline struct buf* 
init(int sc, char scnm, int scwt, u16 *idx, u16 *hdr) {
   u64 ts = bpf_ktime_get_ns(); 
   struct buf* b = get_cache(ts);

   int z = 0;
    u64 *sc_count = curr_scc.lookup(&z);
    if (sc_count) {
        __sync_fetch_and_add(sc_count, 1);  // atomic increment
        if (sc < 500) {
      incr_sc_entry(sc);
         // curr_scc.atomic_increment(1);
      }
    }

   if (b) {
      b->current_ts = ts;
      *idx = b->idx;
      u64 sn = getSeqNum();
      // b->current_sn = (u16)sn;
      b->current_sn = sn & 0x3FFFF;
      if (*idx == 0)
         b->start_ts = ts;
      else if ((*idx > BUFSIZE - 4096)
         // Transmit immediately to ensure (a) enough remaining space in buf,
         // and  (b) TS records are accurate.
#ifndef FULL_TIME
               || (MS_BITS(b->start_ts) != MS_BITS(b->current_ts))
#endif
               )
         {
            check_xmit(b, idx, 1, 0);
            b->start_ts = ts;
         }
      b->d[*idx] = scnm; (*idx)++;

#ifdef SHORT_SEQNUM
      *(u16*)(&b->d[*idx]) = (u16)sn; *idx += 2;
#else
      // *(u32*)(&b->d[*idx]) = (u32)sn; *idx += 4;
      *(u32*)(&b->d[*idx]) = (u32)(sn & 0x3FFFF);  *idx += 4;
#endif
#ifdef INCL_PROCID
      b->d[*idx] = bpf_get_smp_processor_id() & 0xff; *idx += 1;
#endif

#ifdef FULL_TIME
      *(u64*)(&b->d[*idx]) = ts; *idx += 8;
#else
      // Store just the LS bits. MS bits are stored in the header.
      // @@@@ The following line likely works only for little endian
      *(u32*)(&b->d[*idx]) = (u32)(LS_BITS(ts)); *idx += MS_BIT_SHIFT/8;
#endif

      *hdr = *idx; (*idx)++;

      int tid, pid;
      u64 pidtid = gettidpid(&tid, &pid);
      if (pid == tid)
         pidtid = pid;
      u8 sz = addLong(&b->d[*idx], pidtid);
      *idx += (1<<sz);
      b->d[*hdr] = (sz<<6);
      b->weight += scwt;
      return b;
   }
   return 0;
}

/****************************************************************************** 
 ******************************************************************************
 * Functions for adding tamper detection features for each record.             *
 * Three algorithms are used to sign the message block SIPHASH, UMAC1 and UMAC3.
 * my_umac1 and tailcall_umac1 process the message block and generate 64bit MAC*
 * my_umac3 and tailcall_umac3 process the message block and generate 64bit MAC*
 * perform_siphash and tailcall_siphash process the message block and generate *
   MAC   *
 ******************************************************************************
 * NOTE: tailcall_X() recursively calls itself to process the whole length of *
 * message block (this is specially needed to sign execve which logs more than* 
 * 512 bytes.)                                                                *
 ******************************************************************************/
#ifdef TAMPER_DETECT

u8 
tailcall_umac3(void *ctx) {
   int z = bpf_get_smp_processor_id();
   struct buf* b = buf.lookup(&z);
   
   if (!b) return 0;
   static const uint32_t p1 = (1UL << 32) - 5;
   static const uint32_t p2 = (1UL << 32) - 17;
   uint32_t rv1 = b->rv1;
   uint32_t rv2 = b->rv2;
   int remaining_words = b->word_count;
   uint32_t *msgp = b->msgp1;
   uint64_t k1 = b->k1;
   uint64_t k2 = b->k2;
   uint64_t k11 = k1 & 0xffffffff;
   uint64_t k12 = k1 >> 32;
   u16 *idx = &b->idx;
   
   // Process words 1-10 (fully unrolled)
   if (remaining_words >= 1) {
      uint32_t m = 0;
      if (bpf_probe_read(&m, sizeof(m), &msgp[0]) == 0) {
         uint64_t x = rv1 * k11 + m;
         uint64_t y = rv2 * k12 + m;
         rv1 = x % p1;
         rv2 = y % p2;
         remaining_words--;
         msgp++;
      }
   }
   
   if (remaining_words >= 1) {
      uint32_t m = 0;
      if (bpf_probe_read(&m, sizeof(m), &msgp[0]) == 0) {
         uint64_t x = rv1 * k11 + m;
         uint64_t y = rv2 * k12 + m;
         rv1 = x % p1;
         rv2 = y % p2;
         remaining_words--;
         msgp++;
      }
   }
   
   if (remaining_words >= 1) {
      uint32_t m = 0;
      if (bpf_probe_read(&m, sizeof(m), &msgp[0]) == 0) {
         uint64_t x = rv1 * k11 + m;
         uint64_t y = rv2 * k12 + m;
         rv1 = x % p1;
         rv2 = y % p2;
         remaining_words--;
         msgp++;
      }
   }
   
   if (remaining_words >= 1) {
      uint32_t m = 0;
      if (bpf_probe_read(&m, sizeof(m), &msgp[0]) == 0) {
         uint64_t x = rv1 * k11 + m;
         uint64_t y = rv2 * k12 + m;
         rv1 = x % p1;
         rv2 = y % p2;
         remaining_words--;
         msgp++;
      }
   }
   
   if (remaining_words >= 1) {
      uint32_t m = 0;
      if (bpf_probe_read(&m, sizeof(m), &msgp[0]) == 0) {
         uint64_t x = rv1 * k11 + m;
         uint64_t y = rv2 * k12 + m;
         rv1 = x % p1;
         rv2 = y % p2;
         remaining_words--;
         msgp++;
      }
   }
   
   if (remaining_words >= 1) {
      uint32_t m = 0;
      if (bpf_probe_read(&m, sizeof(m), &msgp[0]) == 0) {
         uint64_t x = rv1 * k11 + m;
         uint64_t y = rv2 * k12 + m;
         rv1 = x % p1;
         rv2 = y % p2;
         remaining_words--;
         msgp++;
      }
   }
   
   if (remaining_words >= 1) {
      uint32_t m = 0;
      if (bpf_probe_read(&m, sizeof(m), &msgp[0]) == 0) {
         uint64_t x = rv1 * k11 + m;
         uint64_t y = rv2 * k12 + m;
         rv1 = x % p1;
         rv2 = y % p2;
         remaining_words--;
         msgp++;
      }
   }
   
   if (remaining_words >= 1) {
      uint32_t m = 0;
      if (bpf_probe_read(&m, sizeof(m), &msgp[0]) == 0) {
         uint64_t x = rv1 * k11 + m;
         uint64_t y = rv2 * k12 + m;
         rv1 = x % p1;
         rv2 = y % p2;
         remaining_words--;
         msgp++;
      }
   }
   
   if (remaining_words >= 1) {
      uint32_t m = 0;
      if (bpf_probe_read(&m, sizeof(m), &msgp[0]) == 0) {
         uint64_t x = rv1 * k11 + m;
         uint64_t y = rv2 * k12 + m;
         rv1 = x % p1;
         rv2 = y % p2;
         remaining_words--;
         msgp++;
      }
   }
   
   if (remaining_words >= 1) {
      uint32_t m = 0;
      if (bpf_probe_read(&m, sizeof(m), &msgp[0]) == 0) {
         uint64_t x = rv1 * k11 + m;
         uint64_t y = rv2 * k12 + m;
         rv1 = x % p1;
         rv2 = y % p2;
         remaining_words--;
         msgp++;
      }
   }

   // Update state
   b->rv1 = rv1;
   b->rv2 = rv2;
   b->word_count = remaining_words;
   b->msgp1 = msgp;
   
   // If more words remain, tail call to continue processing
   if (remaining_words > 0) {
      tailcall.call(ctx, 4);  // Recursive tail call
      return 0;
   }
   
   // Final processing when all words are done
   uint64_t result = (k2 ^ rv1) ^ (((uint64_t)rv2) << 32);
   // Delete keys
   k1 = 0; k2 = 0; k11 = 0; k12 = 0;
   b->k1 = 0;
   b->k2 = 0;
   // Output handling
   if (*idx < BUFSIZE) {
      b->d[*idx] = '\\';
      *idx = *idx + 1;
   }
   add_data(b, (u8*)&result, sizeof(result), idx);
   if (*idx < BUFSIZE) {
      b->d[*idx] = '\n'; 
      *idx = *idx + 1;
   }
   
   // Transmission logic
   u32 tx_wt_thresh = TX_WT_THRESH;
   u32 tx_thresh = TX_THRESH;
   int force_wake = (b->weight >= tx_wt_thresh);
   int force_tx = force_wake || (*idx >= tx_thresh);
   check_xmit(b, idx, force_tx, force_wake);
   b->idx = *idx;
   unlock_cache(b);
   
   return 0;
}
/****************************************************************************** 
 *  Takes two signing keys: k1 is used for fingerprint computation, while k2
 *  is applied as a one-time pad at the end. Fingerprint computation uses a 
 *  universal hash function, thereby providing hard guarantees on minimizing
 *  the number of collisions. Specifically, a message M = m_1 m_2 ... m_r, where
 *  each m_i represents a 64-bit block, is treated as a polynomial:
 *     M(x) = sum_{i=1 to r} m_i*x^i mod p [for a prime p ~ 2^64]
 *  The fingerprint equals M(k1). The final MAC is given by:
 *     MAC(M) = M(k1) xor k2
 *  Since we are using k2 like an OTP, we have the following property:
 *    For every message M and any 66-bit value mm, there exists k = (k1, k2) 
 *     such that MAC(M) = mm. 
 *  To see this, pick an arbitrary k1, and set k2 = M(k1) ^ mm. Thus, the
 *  adversary gains nothing by "cracking" the MAC. Specifically, consider an
 *  adversary that sees the (M, mm) pair and is able to construct a (k1', k2')
 *  that will yield the MAC value of mm for M. This factor has gained him ZERO
 *  information about the *real* keys (k1, k2) used to produce this MAC. As a
 *  result, if he tampers with this message to produce (M', mm'), there is
 *  a negligible probability that the tampered message will pass verification.
 *  (The probability is r/2^64, not 1/2^64. In particular, M(x) may not cover 
 *  all of {0..p-1} because multiple x values (say, x_1,..,x_l) can result in 
 *  the same value of M(x), say c. Then, x_1,...,x_l must be roots of the
 *  polynomial M(x) - c = 0. By properties of polynomials over prime fields,
 *  l <= r, the degree of the polynomial, which is the same as the number of
 *  of blocks in the message. Now consider the mapping P -> M(P), where 
 *  P = {0,..,p-1}. This is an onto mapping, with at most r arrows going into
 *  each point in M(P). By pigeonhole principle, |M(P)| >= p/r. In other
 *  words, there are at least p/r distinct values for M(k1'), and unique
 *  corresponding k2' for each of these such that the pair (k1', k2') will
 *  result in (M, mm). Thus, the right key (k1, k2) can be any of these
 *  2^64/r possibilities. In other words, the adversary has a negligible
 *  probability of r/2^64 of being right.)

 *  my_umac1 performs arithmetic modulo a prime number. To do this, we need to
 *  perform all multiplications WITHOUT the possibility of a overflow, and then
 *  apply mod p. my_umac2 avoids the division using a trick that uses additional
 *  multiplications instead. The trick works when p = 2^n-s for a small s. But
 *  it turns out that the optimization leads to worse performance by ~15%

 *  If we implemented fingerprinting at the user level, we can use 128-bit
 *  multiplication and avoid overflows for 64-bit blocks/keys. But in ebpf, we
 *  have only 32-bit multiplications, so we divide the 64-bit fingerprinting key
 *  into two 32-bit keys, then compute two 32-bit fingerprints and concatenate
 *  them into a 64-bit fingerprint. Note that each fingerprint uses only half the
 *  message, but they are uncorrelated as we use different modulos. We *were*
 *  hoping that this still gives us a denominator of 2^64, and that the only
 *  downside is that the numerator will increase to r^2. But this is not true.
 *  The attacker can try to just change the odd blocks and leave the even blocks
 *  as is. Then there are only 2^32/r possible k1 values to try. Still, they
 *  can't figure out which of those possibilities is the right one. Since it is
 *  not feasible to try all of them one by one, we accept this. 
*******************************************************************************/

static inline uint64_t 
my_umac3(struct buf *b, void *ctx, int word_offset, int word_count, 
                  uint64_t k1, uint64_t k2) {
   
   uint32_t p1 = (1UL << 32) - 5;
   uint32_t p2 = (1UL << 32) - 17;

   uint32_t rv1 = 0, rv2 = 0;
   uint32_t m = 0;
   uint64_t k11 = k1 & 0xffffffff;
   uint64_t k12 = k1 >> 32;
   int words_to_process = min(word_count, 1);
   int processed = 0;
   
   if (words_to_process > 0) {
      // Word 1
      if (bpf_probe_read(&m, sizeof(m), b->d + word_offset) == 0) {
         rv1 = m; if (rv1 >= p1) rv1 -= p1;
         rv2 = m; if (rv2 >= p2) rv2 -= p2;
         processed++;
      }
  }
//   if (words_to_process > 1) {
//       // Word 2
//       if (bpf_probe_read(&m, sizeof(m), b->d + word_offset + 4) == 0) {
//          uint64_t x = rv1 * k11 + m;
//          uint64_t y = rv2 * k12 + m;
//          rv1 = x % p1;
//          rv2 = y % p2;
//          processed++;
//       }
//   }
//   if (words_to_process > 2) {
//       // Word 3
//       if (bpf_probe_read(&m, sizeof(m), b->d + word_offset + 8) == 0) {
//          uint64_t x = rv1 * k11 + m;
//          uint64_t y = rv2 * k12 + m;
//          rv1 = x % p1;
//          rv2 = y % p2;
//          processed++;
//       }
//   }
//   if (words_to_process > 3) {
//       // Word 4
//       if (bpf_probe_read(&m, sizeof(m), b->d + word_offset + 12) == 0) {
//          uint64_t x = rv1 * k11 + m;
//          uint64_t y = rv2 * k12 + m;
//          rv1 = x % p1;
//          rv2 = y % p2;
//          processed++;
//       }
//    }
   // Prepare for tail call if more words remain
   int remaining_words = word_count - processed;
   if (remaining_words > 0 && b) {
      b->rv1 = rv1;
      b->rv2 = rv2;
      b->msgp1 = (uint32_t *)(b->d + word_offset + (processed * 4));
      b->k1 = k1;
      b->k2 = k2;
      k1 = 0; k2 = 0; k11 = 0; k12 = 0;
      b->word_count = remaining_words;
      tailcall.call(ctx, 4); 
       
   }
   return (k2 ^ rv1) ^ (((uint64_t)rv2) << 32);
}

/******************************************************************************
 * Helper functions for adding tamper detection.
 ******************************************************************************/

static inline bool 
validate_key_index(int keyidx) {
   if (keyidx < 0 || keyidx >= TOTAL_KEYS) {
      return false;
   }
   return true;
}

static inline bool 
validate_key_pair(u64 k1, u64 k2) {
   int z = 0;
   u16 *is_initkey_added = is_initkey.lookup(&z);
   if(!is_initkey_added) return false;
   if(*is_initkey_added != 1) return false;
   if (k1 == 0 && k2 == 0 ) {
      return false;
   }
   return true;
}

static inline bool 
handle_init_key(struct buf *b, u16 *i, int keyidx) {
   int z = 0;
   u16 init_key_added = 1;
   struct hashkey *firstkey = initkey.lookup(&z);
   u16 *is_initkey_added = is_initkey.lookup(&z);
   
   // if (!firstkey || keyidx >= THREE_QUARTER_POINT - 1) {
   //    return false;
   // }
   if (!firstkey ) {
      return false;
   }

   if(keyidx != QUARTER_POINT - 1) return false;

   u64 check_null = firstkey->keys[0][0];
   if (check_null == 0) {
      return false;
   }

   if (*i < BUFSIZE -200 ) {
      b->d[*i] = '#';  
      (*i)++;
   }

   add_binary(b, firstkey->keys[0], 16, i);
   firstkey->keys[0][0] = 0; 
   firstkey->keys[0][1] = 0;
   if (is_initkey_added) is_initkey.update(&z, &init_key_added);
   return true;
}

static inline bool 
handle_sync_key(struct buf *b, u16 *i, int keyidx) {
   int z = 0;
   struct hashkey *synckey = basekey.lookup(&z);
   
   if (!synckey || keyidx != THREE_QUARTER_POINT - 1) {
      return false;
   }

   if (*i < BUFSIZE -200 ) {
      b->d[*i] = '#';  
      (*i)++;
   }
   
   add_binary(b, synckey->keys[0], 16, i);
   
   return true;
}

static inline void 
update_bank_state(struct bank_state *state, int keyidx) {
   u64 old_state = *((volatile u64 *)state); // Atomic read
   u32 current_bank = (u32)old_state;
   u32 next_bank = (u32)(old_state >> 32);
   u64 new_state = old_state;
   int z = 0;

   if (keyidx == QUARTER_POINT - 1) {
      new_state = ((u64)current_bank << 32) | current_bank;
      u16 signal = (current_bank == 0) ? 2 : 1;
      keygen_signal.update(&z, &signal);
   } 
   else if (keyidx == THREE_QUARTER_POINT - 1) {
      new_state = ((u64)next_bank << 32) | (1 - current_bank);
   }

   if (new_state != old_state) {
      __sync_val_compare_and_swap((u64 *)state, old_state, new_state);
   }
}

static inline u32 
get_active_bank(struct bank_state *state, int keyidx) {
   u64 state_val = *((volatile u64 *)state); // Atomic read
   u32 current_bank = (u32)state_val;
   u32 next_bank = (u32)(state_val >> 32);
   
   return (keyidx <= HALF_POINT - 1) ? current_bank : next_bank;
}

static inline bool 
prepare_signing(struct buf *b, u16 *i, int sign_bytes) {
   int offset = (*i - sign_bytes);
   if (offset < 0) {
      // mystat.atomic_increment(SIGN_OFFSET_INVALID);
      // u16 ret = add_pad_0_16(b, &i, pad);
   // bpf_trace_printk("Padding %d bytes", pad);
   // if ( pad > BUFSIZE) {
   //    pad = 0;
   // }
   // if (i < BUFSIZE ) {
   //    b->d[i] = '$';  
   //    i++;
   // }
   // for (int j = 0; j < 4; j++) {
   //    if (j >= pad) {
   //       break;
   //    }
   //    if ( i < BUFSIZE) b->d[i] = '\0';
   //    i++;
   // }
      return false;
   }
   return true;
}

static inline void 
perform_siphash(struct buf *b, void *ctx, int offset, int sign_bytes, u64 k1, 
                  u64 k2) {
   b->v0 = 0x736f6d6570736575ULL ^ k1;
   b->v1 = 0x646f72616e646f6dULL ^ k2;
   b->v2 = 0x6c7967656e657261ULL ^ k1;
   b->v3 = 0x7465646279746573ULL ^ k2;
   
   b->msgp = (uint64_t*)(b->d + offset);
   b->msglen = sign_bytes;
   b->word_count = b->msglen / sizeof(uint64_t);
   k1 = 0; k2 = 0;
   tailcall.call(ctx, 2);
}

#endif

//#define ADAPTIVE_LATENCY
/****************************************************************************** 
 ******************************************************************************
 * Counterpart of the init functions above: finish() is used to complete an   *
 * event record. It checks the thresholds --- buffer length as well as the    *
 * weight threshold. If they are over the thresholds, xmit() is called. Since *
 * scwt is updated only on entry events, b->weight >= TX_WT_THRESH))          *
 * can hold in finish _only_ for entry events. For exit events, the buffer    *
 * would already have been emptied on the previous operation if it exceeded   *
 * the threshold. THIS MEANS THAT weight-based copying into ring buffer and   *
 * the prompt wake up of user level are possible ONLY for entry events. This  *
 * seems OK, as most dangerous system calls should be treated as if they      *
 * occurred at the time of their entry into the kernel.                       *
 *****************************************************************************
 ******************************************************************************
 * finish1 function is just added to call check_xmit when error are handled in*
 * finish function.
 * finish function is modified to support addition of tamper detection feature*
 * It takes the context (ctx) as argument and passes it to the tailcall 
 * function. It also takes sign_bytes as argument to decide the number of     *
 * bytes to be signed for each system call.                                   *
 ******************************************************************************
 ******************************************************************************
 * Keyrotation logic:
 * At 1/4 * TOTAL_KEYS (cur_bank = next_bank), send nextbank keygen signal to *
 * user level.
 * At 3/4 * TOTAL_KEYS (switch banks).
 ******************************************************************************/
static inline void
finish1(struct buf *b, u16 *i){
   if (b && *i < BUFSIZE - 1) {
      b->d[*i] = '\n';
      (*i)++;
   }
   int force_wake = (b->weight >= TX_WT_THRESH);
   int force_tx = force_wake || (*i >= TX_THRESH);
   check_xmit(b, i, force_tx, force_wake);
   b->idx = *i;
   unlock_cache(b);
}

static inline void
finish(struct buf *b, u16 i, void *ctx, int sign_bytes) {
#ifdef TAMPER_DETECT   
   struct hashkey *synckey, *firstkey;
   uint64_t result = 0;
   int z = 0;
   int force_wake, force_tx;
   int keyidx = (int) b->current_sn;
   // Step 1: Handle initial keys if needed
   handle_init_key(b, &i, keyidx);
   // Step 2: Handle sync key if at transition point
   handle_sync_key(b, &i, keyidx);

   b->keyidx = keyidx;
   b->idx = i;

   // Step 3: Bank state management
   struct bank_state *state = bank_state.lookup(&z);
   if (!state) {
      goto cleanup;
   }
   
   u32 used_bank = get_active_bank(state, keyidx);

   // Step 4: Get appropriate keyset
   struct hashkey *keyset = (used_bank == 0) ? 
                        keyset0.lookup(&z) : keyset1.lookup(&z);
   if (!keyset) {
      goto cleanup;
   }
   
   // Step 5: Validate key index
   if (!validate_key_index(keyidx)) {
      goto cleanup;
   }
   
   // Step 6: Get keys
   u64 k1 = keyset->keys[keyidx][0];
   u64 k2 = keyset->keys[keyidx][1];
   
   // Step 7: Validate keys
   if (!validate_key_pair(k1, k2)) {
      mystat.atomic_increment(SIGN_FAIL);
      goto cleanup;
   }
   // Step 8: Delete keys
   keyset->keys[keyidx][0] = 0;
   keyset->keys[keyidx][1] = 0;

   update_bank_state(state, keyidx);
   // Step 9: Prepare signing
   if (!prepare_signing(b, &i, sign_bytes)) {
      goto cleanup;
   //   return;
   }
   int offset = (i - sign_bytes);
 // Step 10: Perform signing based on algorithm
#ifdef SIPHASH
   perform_siphash(b, ctx, offset, sign_bytes, k1, k2);
#elif defined(UMAC3)
   
   b->k1 = k1;
   b->k2 = k2;
   result = my_umac3(b, ctx, offset, sign_bytes / 4, k1, k2);
   bpf_trace_printk("return umac3" );
// if (i < BUFSIZE - 1000){
//    b->d[i] = '\\';
//    i = i + 1;
// }
// add_data(b, (u8*)&result, sizeof(result), &i);
// finish1(b, &i);

#endif
cleanup:
   finish1(b, &i);
#else
   finish1(b, &i);
#ifdef ADAPTIVE_LATENCY
   int z=0;
   u64 factor = 1<<30;
   if (b->current_sn & 0xf) { // @@@@ Tune this
      int n=RB_MSGS;
      long *mrp = msgs_rcvd.lookup(&z);
      if (mrp) {
         u64 *msp = mystat.lookup(&n);
         if (msp) {
            long mrcvd = *mrp;
            long msent = *msp;
            long qlen = msent-mrcvd;
            msg_delivery_lag.increment(bpf_log2l(qlen));

            u32* facp = tx_fac.lookup(&z);
            if (facp) { 
               factor = *facp;
               if (!factor)
                  factor = 1<<30;
               long thresh = NUMCPU; // @@@@ Tune this
               long facmult = (long)(0.95*(1<<30)); // @@@@ Tune this
               if (qlen > thresh) // Too long, increase msg size threshold
                  factor = (factor << 30)/facmult;
               else if (qlen < thresh/2) // Small enough, decrease 
                  factor = (factor * facmult) >> 30;
               if (factor > (1<<30))
                  factor = 1 << 30;
               if (factor < (1<<23)) // @@@@ Tune this
                  factor = 1 << 23;
               *facp = factor;
            }
         }
      }
   }

   u32* facp = tx_fac.lookup(&z);
   if (facp) 
      factor = *facp;
   if (!factor)
      factor = 1<<30;

   //u32 tx_wt_thresh = (tx_wt_thresh * factor) >> 30;
   tx_thresh = (tx_thresh * factor) >> 30;
#endif
#endif
}

u8
add_string_tail_argv(void *ctx) {
   u16 *idx;
   u64 ts = bpf_ktime_get_ns(); 
   //struct buf* b = get_cache(ts);
   int z = bpf_get_smp_processor_id();
   struct buf* b = buf.lookup(&z);
   if (b) {
      idx = &b->idx;
      u16 n = add_str_array0_32(b, b->argv , idx);
      b->nargvl += n ;
      if(n == 32 && (b->nargvl < (MAX_ARG -32
#ifdef TAMPER_DETECT
         - 256
#endif      
      ))){
         b->argv = b->argv + n;
         tailcall.call(ctx,0);
         // If tailcall fails (limit reached), execution falls through to here.
      }
      
      // Finalize ARGV and tailcall ENVP
      if(b->nargpos < BUFSIZE -200){
         b->d[b->nargpos] = (char)(b->nargvl & 0xff);
         b->d[b->nargpos + 1] = (char)(b->nargvl >>8 & 0xff);
      }
      b->nargpos = 0;
      tailcall.call(ctx, 1);
      
      // If we reach here, it means we are falling through from either a failed
      // ENVP tailcall or we shouldn't have tailcalled. Either way, finishing
      // the record is handled by add_string_tail_envp. BUT if we are here,
      // it means add_string_tail_envp WILL NEVER BE CALLED!
      // So we must finish the record here safely.
      b->nargvl = 0;
      b->nenvpl = 0;
#ifdef FILTER_SC_FLOOD
      // Since it's incomplete, don't stage it. Just rollback.
      if (b->execve_staging) {
          b->execve_staging = 0;
          if (b->staging_hdr >= 9) b->idx = b->staging_hdr - 9;
          else b->idx = 0;
          b->weight -= WT_EXECVE;
          unlock_cache(b);
          return 0;
      }
#endif
      finish(b, b->idx, ctx, 712);
   }
   
   return 0;
}

u8
add_string_tail_envp(void *ctx) {
   u16 *idx;
   u64 ts = bpf_ktime_get_ns(); 
   struct buf* b = get_cache(ts);
   // int z = bpf_get_smp_processor_id();
   // struct buf* b = buf.lookup(&z);
   if (b) {
      idx = &b->idx;
      if(b->nenvpl == 0)
      {  
         b->nargpos = *idx;
         *idx += 2;
      }
      u16 n = add_str_array0_32(b, b->envp , idx);
      b->nenvpl += n ;
      if(n == 32 && (b->nenvpl < (MAX_ARG
#ifdef TAMPER_DETECT
         - 256
#endif       
      ))){
         b->envp = b->envp + n; 
         //tail call itself until finished
         tailcall.call(ctx,1);
         // If tailcall fails (limit reached), execution falls through to here.
      }
      
      // Finalize ENVP array and commit record
      if(b->nargpos < BUFSIZE -200) {
         b->d[b->nargpos] = (char)(b->nenvpl & 0xff);
         b->d[b->nargpos + 1] = (char)(b->nenvpl >>8 & 0xff);
      }
      u16 sign_bytes = (b->nenvpl + b->nargvl) * 4;
      b->nargvl = 0;
      b->nenvpl = 0;
      sign_bytes = mymin(712, sign_bytes);
#ifdef FILTER_SC_FLOOD
      if (b->execve_staging) {
          b->execve_staging = 0;
          // Stage the payload into per-TID map instead of ring buffer
          int scratch_z = 0;
          struct staged_execve *entry = execve_scratch.lookup(&scratch_z);
          if (entry) {
              int tid = gettid();
              u16 start = b->staging_start;
              if (start >= BUFSIZE) start = 0;
              u16 len = *idx - start;
              if (len <= STAGED_EXECVE_SIZE) {
                  // Ensure start + len doesn't exceed buf->d bounds
                  u32 avail = BUFSIZE - start;
                  if (len > avail)
                      len = avail;
                  entry->len = len;
                  entry->sign_bytes = sign_bytes;
                  // Save the hdr byte (arg-width bits patched by add_long3)
                  // It lives before staging_start so is not in the payload copy
                  if (b->staging_hdr < BUFSIZE)
                      entry->hdr_byte = b->d[b->staging_hdr];
                  if (len > 0) {
                      u32 sz = len;
                      if (sz > STAGED_EXECVE_SIZE) sz = STAGED_EXECVE_SIZE;
                      bpf_probe_read_kernel(entry->d, sz, &b->d[start]);
                  }
                  execve_stage.update(&tid, entry);
                  // Rollback buf completely to erase the init() header
                  if (b->staging_hdr >= 9) b->idx = b->staging_hdr - 9;
                  else b->idx = 0;
                  b->weight -= WT_EXECVE;
                  unlock_cache(b);
                  return 0;
              }
          }
      }
#endif
      finish(b, *idx, ctx, sign_bytes);
   }   

   return 0;   
}

/****************************************************************************** 
 ******************************************************************************
 * Higher level marshalling functions. The lower level marshalling functions  *
 * handled a single argument or a single set of arguments. These higher level *
 * functions prepare the complete record: they call one of the init functions *
 * then add all the relevant arguments, and finally call the finish function  *
 * to complete the record. We have several of them below, one for each        *
 * system call entry/exit that is distinct in terms of argument types. Their  *
 * names indicate argument types.                                             *
 *                                                                            *
 * Note that most system calls exits have just a return value to send back to *
 * the user level, so sc_exit() and sc_exitt() are the most frequently used   *
 * for marshalling an exit record. But some system call exits have more data  *
 * return, e.g., an accept system call that returns the information of the    *
 * connected peer. The remaining x() and xt() functions are used for them.    *
 *****************************************************************************/
static inline void 
log_sc_long0(void *ctx, int sc, char scnm, int scwt, int sign_bytes) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      finish(b, i, ctx, sign_bytes);
   }
}

static inline void 
log_sc_long1(void *ctx, int sc, char scnm, int scwt, int sign_bytes, long a1) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long1(b, a1, &i, hdr);
      finish(b, i, ctx, sign_bytes);
   }
}

static inline void 
log_sc_long2(void *ctx, int sc, char scnm, int scwt, int sign_bytes,
             long a1, long a2) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long2(b, a1, a2, &i, hdr);
      finish(b, i, ctx, sign_bytes);
   }
}

static inline void 
log_sc_long3(void *ctx, int sc, char scnm, int scwt, int sign_bytes,
             long a1, long a2, long a3) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      finish(b, i, ctx, sign_bytes);
   }
}

static inline void 
log_sc_long4(void *ctx, int sc, char scnm, int scwt, int sign_bytes, 
             long a1, long a2, long a3, long a4) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      add_long_ex(b, a4, &i);
      finish(b, i, ctx, sign_bytes);
   }
}

static inline void 
log_sc_long5(void *ctx, int sc, char scnm, int scwt, int sign_bytes, 
             long a1, long a2, long a3, long a4, long a5) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      add_long_ex(b, a4, &i);
      add_long_ex(b, a5, &i);
      finish(b, i, ctx, sign_bytes);
   }
}

static inline void 
log_sc_str_long1(void *ctx, int sc, char scnm, int scwt, int sign_bytes,
                 const char* fn, long a1) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long1(b, a1, &i, hdr);
      add_string(b, fn, &i);
      finish(b, i, ctx, sign_bytes);
   } 
}

static inline void 
log_sc_str_long2(void *ctx, int sc, char scnm, int scwt, int sign_bytes,
                 const char* fn, long a1, long a2) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long2(b, a1, a2, &i, hdr);
      add_string(b, fn, &i);
      finish(b, i, ctx, sign_bytes);
   } 
}

static inline void 
log_sc_str_long3(void *ctx, int sc, char scnm, int scwt, int sign_bytes, 
                 const char* fn, long a1, long a2, long a3) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      add_string(b, fn, &i);
      finish(b, i, ctx, sign_bytes);
   } 
}

static inline void 
log_sc_str_long4(void *ctx, int sc, char scnm, int scwt, int sign_bytes, 
                 const char* fn, long a1, long a2, long a3, long a4) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      add_long_ex(b, a4, &i);
      add_string(b, fn, &i);
      finish(b, i, ctx, sign_bytes);
   } 
}

static inline void 
log_sc_str_long5(void *ctx, int sc, char scnm, int scwt, int sign_bytes, 
                 const char* fn, long a1, long a2, long a3, long a4, long a5) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      add_long_ex(b, a4, &i);
      add_long_ex(b, a5, &i);
      add_string(b, fn, &i);
      finish(b, i, ctx, sign_bytes);
   } 
}

static inline void 
log_sc_str2_long2(void *ctx, int sc, char scnm, int scwt, int sign_bytes,
                  const char* s1, const char* s2, long a1, long a2) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long2(b, a1, a2, &i, hdr);
      add_string(b, s1, &i);
      add_string(b, s2, &i);
      finish(b, i, ctx, sign_bytes);
   } 
}

static inline void 
log_sc_str2_long3(void *ctx, int sc, char scnm, int scwt, int sign_bytes, 
                  const char* s1, const char* s2, long a1, long a2, long a3) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      add_string(b, s1, &i);
      add_string(b, s2, &i);
      finish(b, i, ctx, sign_bytes);
   } 
}

static inline void 
log_sc_str2_long4(void *ctx, int sc, char scnm, int scwt, int sign_bytes, 
                  const char* s1, const char* s2, 
                  long a1, long a2, long a3, long a4) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      add_long_ex(b, a4, &i);
      add_string(b, s1, &i);
      add_string(b, s2, &i);
      finish(b, i, ctx, sign_bytes);
   } 
}

static inline void 
log_sc_str2_long5(void *ctx, int sc, char scnm, int scwt, int sign_bytes,
                  const char* s1, const char* s2, 
                  long a1, long a2, long a3, long a4, long a5) {
   u16 i, hdr; struct buf *b;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      add_long_ex(b, a4, &i);
      add_long_ex(b, a5, &i);
      add_string(b, s1, &i);
      add_string(b, s2, &i);
      finish(b, i, ctx, sign_bytes);
   } 
}

static inline void
log_sc_str3_long2(void *ctx, int sc, char scnm, int scwt,  int sign_bytes,
                  const char *s1, const char *s2,
                  const char *s3, long a1, long a2) {
  u16 i, hdr;
  struct buf *b;
  if ((b = init(sc, scnm, scwt, &i, &hdr))) {
    add_long2(b, a1, a2, &i, hdr);
    add_string(b, s1, &i);
    add_string(b, s2, &i);
    add_string(b, s3, &i);
    finish(b, i, ctx, sign_bytes);
  }
}

static inline int
log_sc_data_long2(void *ctx, int sc, char scnm, int scwt,  int sign_bytes,
                  void* data, int len, long a1, long a2) {
   u16 i, hdr; struct buf *b; int fail=0;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long2(b, a1, a2, &i, hdr);
      fail = add_data(b, data, len, &i);
      finish(b, i, ctx, sign_bytes);
   } 
   return fail;
}

static inline int
log_sc_data_long3(void *ctx, int sc, char scnm, int scwt,  int sign_bytes,
                  void* data, int len, long a1, long a2, long a3) {
   u16 i, hdr; struct buf *b; int fail=0;
   if ((b = init(sc, scnm, scwt, &i, &hdr))) {
      add_long3(b, a1, a2, a3, &i, hdr);
      fail = add_data(b, data, len, &i);
      finish(b, i, ctx, sign_bytes);
   } 
   return fail;
}

static inline void unexp_arg_lookup_err(void *ctx, int sc) {
   if (sc < 500 && getpid() != EAUDIT_PID) {
      int z = 0;
      struct log_lv *ll = log_level.lookup(&z);
      if (ll && ll->log_wt <= WT_UNIMPORTANT) {
         log_sc_long2(ctx, sc, ERR_REP, 0, 8, ARG_LOOKUP_ERR, sc);
         mystat.atomic_increment(UNEXP_ARG_LOOKUP_FAIL);
         errcount.atomic_increment(sc);
      }
   }
}

/****************************************************************************** 
 ****************************************************************************** 
 * Often, we need to remember some context between calls and returns, e.g.,   *
 * to store some pointer arguments on sys_enter and then retrieve target mem  *
 * in sys_exit. In other cases, we want to intercept an exit only if we       *
 * intercepted the entry. We can use a single map for all these cases, since  *
 * the information needs to be remembered between two successive events from  *
 * the same pid. But we use more than one because some syscalls require more  *
 * info to be stored, e.g., information about remote address in an accept.    *
 * For the rest, we fix the value to be u64 and reuse a single map.           *
 *****************************************************************************/
// We define a per-task map for stashing syscall arguments between entry and
// exit. We use a separate map just for args, as opposed to consolidating into
// a struct that captures all task-related info. This make sense because it:
//  (a) Easier to separate and enable/disable features indedpendently
//  (b) Args are stored on almost every syscall, while the remaining task-related
//      info is accessed only for specific system calls, e.g., reads, opens, etc.
struct long3 {
   u64 d1;
   u64 d2;
   u64 d3;
};
BPF_TABLE("lru_hash", u32, struct long3, arg3, MAX_TASKS); 
// Entries are short-lived, from syscall entry to exit. So there is essentially
// no risk of LRU evicting valid entries. In fact, MAX_TASKS need not even be 
// very large: the number of simultaneously active syscalls can't be too high.
// Risks are minimal even if we consider attacks by non-root processes. And
// if we do run out of space, the worst possible result is a lost syscall.

// Because this map are initialized at syscall entry and cleaned up at exit,
// there is no chance of stale entries, or the risk of reuse when pids are
// recycled. No need for locks either, since each map is accessed using the 
// subject's tid, and one thread can be making only one syscall at a time.

static inline void
arg3_record(long l1, long l2, long l3, int tid) {
   struct long3 info = {l1, l2, l3};
   arg3.update(&tid, &info);
}

static inline int
arg3_retrieve_and_delete(void *ctx, long* l1, long* l2, long* l3, int tid, int sc) {
   struct long3* succ = arg3.lookup(&tid);
   if (succ) {
      *l1 = succ->d1;
      *l2 = succ->d2;
      *l3 = succ->d3;
      arg3.delete(&tid);
      return 1;
   }
   else {
     unexp_arg_lookup_err(ctx, sc);
     return 0;
   }
}

BPF_TABLE("lru_hash", u32, u64, arg, MAX_TASKS); 

static inline void
arg_record(u64 d, int tid) {
   arg.update(&tid, &d);
}

static inline int
arg_retrieve_and_delete(void *ctx, u64* info, int tid, int sc) {
   u64* succ = arg.lookup(&tid);
   if (succ) {
      *info = *succ;
      arg.delete(&tid);
      return 1;
   }
   else {
      unexp_arg_lookup_err(ctx, sc);
      return 0;
   }
}

struct long5 {
   u64 d1;
   u64 d2;
   u64 d3;
   u64 d4;
   u64 d5;
};

BPF_TABLE("lru_hash", u32, struct long5, arg5, MAX_TASKS); 

static inline void
arg5_record(u64 d1, u64 d2, u64 d3, u64 d4, u64 d5, int tid) {
   struct long5 info = {d1, d2, d3, d4, d5};
   arg5.update(&tid, &info);
}

static inline int
arg5_retrieve_and_delete(void *ctx, long* d1, long* d2, long* d3, long* d4,
                         long* d5, int tid, int sc) {
   struct long5* succ = arg5.lookup(&tid);
   if (succ) {
      *d1 = succ->d1;
      *d2 = succ->d2;
      *d3 = succ->d3;
      *d4 = succ->d4;
      *d5 = succ->d5;
      arg5.delete(&tid);
      return 1;
   }
   else {
      unexp_arg_lookup_err(ctx, sc);
      return 0;
   }
}

typedef u64 ObjId;

#if defined(ID_NOT_FD) || defined(FILTER_REP_RDWR)
/****************************************************************************** 
 ****************************************************************************** 
 * Support functions to lookup OS information on file descriptors, and create *
 * 64-bit ids from them. These ids are intended to be collision-resistant     *
 * hashes of the objects referenced by fds. Since we are able to look up the  *
 * info on the OS, we don't have to carefully track the binding of fds or     *
 * their evolution over time. Instead, we can look them up on the first read  *
 * or write operation that uses the id. From then on, these ids should be     *
 * remembered, so that we don't have to look up the OS on each read/write.    *
 * (But it is OK if we need to recompute it --- this is something happens if  *
 * the cached info is evicted by LRU algorithm used in the maps.)             *
 *                                                                            *
 * The ids have 2 parts: a 1 to 3 bit object type, plus 61 to 63 bits that    *
 * should provide a collision probability of 1 in 2^60 to 2^62. Valid object  *
 * types include: FILE, PIPE, SELF_NET (sockets for intra-host communication),*
 * and sockets for intranet or internet communication. Collision resistance is*
 * slightly weaker for certain fdtypes, e.g., UNIX domain sockets, as we have *
 * prioritized faster algorithms over collision resistance. For others, e.g., *
 * files, collision resistance is minimized at the cost of somewhat higher    *
 * computational costs.                                                       *
 *****************************************************************************/
static inline ObjId
file2fid(struct file* file, u64 *mtime) {
   struct inode* in = file->f_inode;

   // Inode reuse is fairly common, e.g., on my laptop (ext4), each of the 100
   // distinct files created by the following loop get the same exact inode
   // but a distinct generation. 
   //     for ((i=0; i<100; i++)); do rm -f xx; touch xx; done
   // From the intended purpose of i_generation in the context of NFS, this
   // behavior seems right. I would have expected the generation count to
   // increase sequentially, but perhaps some randomization is being used to
   // defend against some stale handle reuse attacks on NFS? (pure speculation)
   u64 ino = in->i_ino;
   u64 sdev = in->i_sb->s_dev;
   u64 gen = in->i_generation;

   // We use two independent universal hash functions to compute a 32-bit and
   // then a 31-bit hash. Combined into a 63-bit hash, this should give us a
   // collision probability of 1 in 2^63, which is negligible for files on a
   // host. Note that all of the above quantities that feed into the id are
   // 32-bit or less (as of the time this code is written). In fact, the numbers
   // are sufficiently below 2^32 that there is no overflow in the additions
   // involved. (BTW, the added overhead of of the arithmetic operations below
   // is insignificant enough that it is hard to measure.)

   u64 a1 = 2237624219ul; // A random number between 2^31 and 2^32
   u64 a2 = 1336889963ul; // Another random number below 2^32
   u64 p1 = (1ul<<32)-5;  // A prime number less than 2^32
   u64 h1 = (a1*ino + a2*gen) % p1;

   u64 b1 = 3024840434ul; // Another random number below 2^32
   u64 b2 = 2790851613ul; // Another random number below 2^32
   u64 p2 = (1ul<<31)-1;  // A prime less than 2^31
   u64 h2 = (b1*ino + b2*sdev) % p2;

   if (mtime)
      *mtime = in->
#if LINUX_VERSION_CODE <= KERNEL_VERSION(6,7,0)
      i_mtime.tv_sec;
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(6,11,0)
      __i_mtime.tv_sec;         
#else
      i_mtime_sec;
#endif

   if (!ino || !sdev) {
      file_unfound_err();
#if (PRINTK_LOG_LEVEL >= 4)
      bpf_trace_printk("file error? ino=%lx dev=%lx gen=%lx", ino, sdev, gen);
#endif
   }
   if (h1==0 || h2==0)
      fdtoid_errs();
   return mkid(FILE_ID, (h2<<32)|h1);
}

static inline ObjId
file2pipeid(struct file* file) {
   struct inode* in = file->f_inode;
   // inodes are created for pipes but perhaps inode numbers are meaningless. In
   // our experiments, we see two successive pipe calls generating the same
   // inode numbers, i.e., 4 fds that have the same i_no. OTOH, there is a
   // pointer i_pipe that stores information about the pipe (such as the
   // buffers, mutextes, etc.) which seems to be reliable: it is shared by the
   // two sides of the pipe, and is not reused until a pipe is closed. (In our
   // tests, i_generation is always zero for pipes.) Ideally, we would like
   // something that does not get reused at all. Our best solution is one that
   // combines the inode and pipe structure pointer.

   u64 ino = in->i_ino; 
   u64 pipe_ptr = (u64)in->i_pipe;
   u64 a = 8975298380752413961ul;
   u64 b = (u64)-6719241545104527607l;
   if (!ino || !pipe_ptr)
      pipe_unfound_err();

   return mkid(PIPE_ID, a*ino + b*(pipe_ptr>>3));
}

// For IP addrs, our id is (meant to be) unique for the 4-tuple (srcip, srcport,
// dstip, dstport) PROVIDED both ends are local to the host. OTHERWISE, our id
// only incorporates remote ip and remote port. This allows us to treat all
// reads of remote IPs as equivalent. For connections between processes on the
// host, the use of 4-tuple ensures that each connection is accurately traced,
// rather than mixing up all the flows involving one of the ends. SECONDLY, for
// remote endpoints, we use current time in deriving the id, allowing the
// trustworthiness of remote endpoints to be different at different times. We
// convert time into an "epoch" by shifting kernel clock (ns) by
// NS_TO_LOCAL_EP_EPOCH bits or NS_TO_FOREIGN_EP_EPOCH bits. (Since we
// accurately trace local endpoints to the right subject at all times, there is
// no need to use time for their ids.)
// @@@@ All of the above made sense at some point. However, our thinking may
// @@@@ evolved on this. Use of too_long_time in the data reduction algorithm
// @@@@ removed (or at least greatly reduced) the rationale for including
// @@@@ time in the id. Secondly, getting local and foreign addresses is
// @@@@ really difficult. Thirdly, the rationale for treating ignoring selfid
// @@@@ is not that strong. At best, it could be an efficiency argument. (Why
// @@@@ reason with distinct connections if they all have same trustworthiness)
// @@@@ But can there be problems? For instance, a spurious propagation of 
// @@@@ provenance between unrelated local processes because they both 
// @@@@ communicated with the same remote host/service? So, it seems best to
// @@@@ disable all this by defining IGNORE_IPADDR_TYPE

#define IGNORE_IPADDR_TYPE

static inline ObjId
inetid2objid(u64 remid, u64 selfid, int kind, int fmly) {
   u64 a = 2897563066638482501ul;
   u64 b = 2348948160164421580ul;
   u64 rv;

#ifdef IGNORE_IPADDR_TYPE
   kind = SELF_NET_ID;
#endif

   if (kind == SELF_NET_ID)
      rv = (remid+a)*(selfid+a);
      // We DON'T want something like a*rem + b*self, as we want to create a 
      // single objid even if rem and self are switched. Addition of (randomly
      // chosen) "a" reduces likelihood that the product will become zero.
   else if (kind == LOCAL_NET_ID) 
      rv = a*(bpf_ktime_get_ns() >> NS_TO_LOCAL_EP_EPOCH) + b*(remid+a);
   else rv = b*(remid+a); 
   // Epoch lengths are different for IP addresses within the enterprise
   
   // Older ID generation taking time into account for remote endpoints: 
   // a*(bpf_ktime_get_ns() >> NS_TO_FOREIGN_EP_EPOCH) + b*(remid+a);
   // Now epoch is taken care of in too_long_time

   if (rv==0) fdtoid_errs();
   return mkid(kind, rv<<2|(fmly != AF_INET));
   // When encoding IP addresses into IDs, we use the least significant two bits
   // for address family, with AF_INET=0, AF_INET6=1, AF_UNIX=2, OTHER=3. (Note
   // that the entire id is shifted left to include FD type --- we are referring
   // to the LS bits before this shift.)
}

#define IPV4LOCALHOST ((127<<24)+1)
static inline int
ip4addrtype(u32 ip) {
   int rv;
   if (ip == INADDR_ANY || ((ip>>24) == 0x7f))
      rv = SELF_NET_ID; 
   else if ((ip & NETMASK1) == NETADDR1 ||
            (ip & NETMASK2) == NETADDR2 ||
            (ip & NETMASK3) == NETADDR3) 
      rv = LOCAL_NET_ID; // %%%% Note: doesn't detect all local addresses.
   else rv = FOREIGN_NET_ID;
   return rv;
}

// @@@@ Fill in the netmask stuff, otherwise every address is considered foreign!
static inline int
ip6addrtype(struct in6_addr* addr) {
   int rv;
   //if ((int)bpf_get_prandom_u32() > 0) // @@@@
   //   rv = SELF_NET_ID;
   // else if ((int)bpf_get_prandom_u32() > (1<<29)) // @@@@
      rv = FOREIGN_NET_ID;
   //else rv = LOCAL_NET_ID;
   return rv;
}

// Unlike v4addr2id, v6addr2id works on just one half of the 4-tuple at a time.
// The caller needs to combine the two halves into one.
static inline ObjId
v6ep2id(struct in6_addr* addr, u32 port) {
   u64 d1 = *(u64*)addr;
   u64 d2 = *((u64*)addr + 1);
   u64 a = 7277111512771247327ul;
   u64 b = 2846993281888046111ul;
   u64 p1 = (1ul<<22)-3;  // Prime numbers to get a 43 bit id
   u64 p2 = (1ul<<21)-9; 
   d1 = a*d1 % p1;
   d2 = b*d2 % p2;
   if (d1==0 || d2==0) fdtoid_errs();
   return (d1<<37)|(((u64)port)<<21)|d2;
}

/* To derive an id from a UNIX domain socket in the abstract name space.   */
static inline ObjId
usock_abs2id(char *n, int len) { 
   // We compute a rolling hash of string p. The hash is a polynomial of the
   // form \sum_{i=0}^{len-1} p[i]*x^i mod N where x is a random number as
   // initialized above. This is the form of Carter-Wegman-Rabin-Karp
   // fingerprinting, with some modifications for efficiency. First is to set N
   // to be 2^64, a suboptimal choice from the perspective of collisions but
   // probably fine because the number of UNIX domain sockets should be
   // relatively small. Second, p isn't a string but a vector of u64s. Third,
   // we only use the first 128 bytes of p.

   u64* p = (u64*)n;
   u64 x = 7892540079625801679ul, rv = 1, t;
   int l = len;

   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /* 1 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /* 2 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /* 3 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /* 4 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /* 5 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /* 6 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /* 7 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /* 8 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /* 9 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /*10 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /*11 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /*12 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /*13 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /*14 */
   if (len < 8) goto done; rv = rv*x + *p; p++; len -= 8; /*15 */
   if (len > 8) len = 8; // truncate if more than 128 bytes

done: /* Invariant: 0 <= len <= 8 */
   t = *p;
   t = t << (8*(8-len)); // @@@@ Correct shift dir for little endian x86
   rv = rv*x + t;

   return rv;
}

static inline ObjId
usock_fn2id(char *n) {
   // Same rolling hash as above, but used for sockets in the file system name
   // space. Two points: (1) We could not reuse the above function, as it 
   // won't get past the verifier in the second use, (2) Perhaps we can count 
   // on this class of UNIX-domain sockets to be present in the file system,
   // and hence use the file-derived id. But I am not sure about some corner
   // cases, e.g., unbound sock. 

   u64 rv=1;
   char s[104];
   u64 x = 7892540079625801679ul, *t, tt;

   int len = bpf_probe_read_str(s, sizeof(s), n);
   int l = len;
   t = (u64*)s; 
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /* 1 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /* 2 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /* 3 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /* 4 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /* 5 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /* 6 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /* 7 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /* 8 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /* 9 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /*10 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /*11 */
   if (len < 8) goto done; rv = rv*x + *t; t++; len -= 8; /*12 */
   if (len > 8) len = 8;

 done:
   if (len > 0) {
      tt = *t;
      tt = tt << (8*(8-len));// @@@@ Correct shift dir for little endian x86
      rv = rv*x + tt; /* 13: max length used is 104 bytes */
   }
   return rv;
}

/* Use the above two functions to compute an id for a UNIX domain socket.     */
/* Also handles the case of unnamed sockets.                                  */
static inline ObjId
usock2id(struct unix_sock* usk, int peer) {
   u64 rv = 1;
   struct unix_address *ua = usk->addr;
   int len = ua? ua->len : 0;
   if (len <= 2) { 
      // There is some complexity involving unbound sockets vs unnamed sockets.
      // Apparently, unbound sockets can have len=0, but unnamed ones should have
      // len=2. Since we don't have any address info in either case, we hope
      // the location of usk won't change during the lifetime of either type
      // of socket. If so, we can use the location of usk as the id. (Note: both
      // are different from abstract sockets (len > 2) handled below.)
      rv = (u64)usk; 
#if (PRINTK_LOG_LEVEL > 4)
      bpf_trace_printk("usock2id unnamed/unbound socket: peer=%d, id=%lx", 
                       peer, rv);
#endif
      return rv;
   }

   struct sockaddr_un *sa = ua->name;
   if (sa->sun_family != AF_UNIX) {
#if (PRINTK_LOG_LEVEL >= 4)
      bpf_trace_printk("usock2id error: sun_family=%d", sa->sun_family);
#endif
      return 0;
   }

   char *n = sa->sun_path;
   if (*n)
     return usock_fn2id(n);
   else return usock_abs2id(n, len);
}

/* Determine socket type, use the right function above to compute an id */
static inline ObjId
file2sockid(struct file* fst) {
   u64 rv=0;
   struct socket* sock = fst->private_data;
   struct sock* sk = sock->sk;
   u16 fmly = sk->sk_family;

   if (fmly == AF_INET || fmly == AF_INET6) {
     struct inet_sock* inetsk = (struct inet_sock *)sk;
     u32 selfport = inetsk->inet_sport;
     selfport = ntohs(selfport);
     u32 remport = inetsk->inet_dport;
     remport = ntohs(remport);
     u32 remid, selfid; int kind;

     if (fmly == AF_INET) { // IP V4
       u32 remip = inetsk->inet_daddr;
       remip = ntohl(remip);
       u32 selfip = inetsk->inet_rcv_saddr;
       selfip = ntohl(selfip);
       if (selfip == INADDR_ANY)
          selfip = inetsk->inet_saddr;

       kind = ip4addrtype(remip);
       remid  = (((u64)remip) <<16) | remport;
       selfid = (((u64)selfip)<<16) | selfport; 
     }

     else { // IP V6
       struct in6_addr remip = sk->sk_v6_daddr;
       struct in6_addr selfip = sk->sk_v6_rcv_saddr;
       if (*(u64*)&selfip == 0 && *((u64*)&selfip + 1) == 0) //INADDR_ANY
          selfip = inetsk->pinet6->saddr;

       kind = ip6addrtype(&remip);
       remid = v6ep2id(&remip, remport);
       selfid = v6ep2id(&selfip, selfport);
     }
     return inetid2objid(remid, selfid, kind, fmly);
   }

   else if (fmly == AF_UNIX) {
     struct unix_sock* usk = (struct unix_sock*)sk;
     struct unix_sock* rusk = (struct unix_sock*)usk->peer;
     rv = usock2id(usk, 0);
     if (rusk)
        rv *= usock2id(rusk, 1);
     if (!rv)
        fdtoid_errs();
     return mkid(SELF_NET_ID, ((rv>>2)<<2)|2);
   }

#if (PRINTK_LOG_LEVEL >= 4)
   if (fmly != 16) // suppress NETLINK socket related errors
      bpf_trace_printk("Unsupported socket family=%d", fmly);
#endif
   return mkid(SELF_NET_ID, 0); // Return some meaningful default
}

/******************************************************************************
 * Top-level function to compute an id from a file descriptor. If mtime is
 * non-null then modification time is filled in for files, dirs and devices.
 ******************************************************************************/
static inline ObjId
fdtoid(int fd, ObjId* mtime) {
   if (mtime) *mtime = 0;
   fdtoid_calls();
   struct task_struct *t = (struct task_struct *)bpf_get_current_task();
   struct files_struct *fst = t->files;
   struct fdtable* fdt = fst->fdt;
   if (fdt && fd < fdt->max_fds) {
      struct file** fds = fdt->fd;
      struct file* file = fds[fd];
      struct inode* in = file->f_inode;
      if (in) {
         u32 mode = in->i_mode;
         if (S_ISREG(mode))
            return file2fid(file, mtime);
         else if (S_ISSOCK(mode))
            return file2sockid(file); // @@@@
         if (S_ISFIFO(mode))
            return file2pipeid(file);
         else if (S_ISDIR(mode) || S_ISLNK(mode))
            return file2fid(file, mtime);
         else /* char or block device */
            return file2fid(file, mtime);
      }
      else inode_unfound_err();
   }
   else fd_unfound_err();
   return mkid(SELF_NET_ID, 0); // Return some meaningful default
}

#endif

#ifdef FILTER_REP_RDWR
/******************************************************************************
 ******************************************************************************
 * We implement two kinds of data reduction: 
 *
 *   [A] skip redundant and/or repetitive read/writes by the same subject
 *   [B] skip repeated opens by the same subject
 * 
 * Note that [B] => [A]. Moreover, when open reduction is enabled, read/write
 * reductions operate across multiple opens. [A] incorporates:
 *
 *    (1) an exponentially increasing size window: this forces reporting when
 *        the total number of bytes read/written surpasses the window size.
 *        The window sizes increase exponentially, e.g., 1, r, r^2, r^3, ...
 *        where r is given by MED_RDWR_RATIO. In addition, if the number
 *        reported bytes exceeds TOO_LARGE_RDWR_BYTES, then the operation is
 *        reported even if the current r^n threshold isn't exceeded. 
 *
 *        Note that the total number of bytes are reported accurately even if
 *        some of the operations are suppressed. To support this, and to
 *        support these window sizes, we maintain the number of bytes read or
 *        written by an application, as well as the number of bytes that have
 *        been reported in event records emitted so far.
 *
 *        NOTE THAT THIS IS A SAFETY FEATURE. These reads/writes are reported
 *        even if they are not a new dependency.
 *
 *    (2) new dependencies: read/writes are suppressed if they do not create
 *        new dependencies. 
 *
 *    (3) adaptive new dependencies: Similar to (b), but redefines "new" as
 *        differing in version numbers by a given threshold VDT. IT IS USED
 *        ONLY ON THE READ SIDE. For writes, note that each write (typically)
 *        has a corresponding read, so an adaptive threshold can be applied
 *        there. Otherwise, we will be applying it twice, and the effect will
 *        be similar to doubling a threshold that is applied only on reads.
 *        A second reason for NOT applying it on the write side is that it
 *        takes away a good property: that adaptivity applies ONLY to version
 *        changes, not the dependence on a new source. In other words, each
 *        new dependence is propagated immediately. If adaptivity is applied
 *        on the write side, then a subject fails to propagate new dependences
 *        in cases where the adaptive threshold on the write side is nonzero
 *
 *        The threshold t starts off at 1. A read using an fd is considered
 *        new dependence if object version > last read version + t - 1. This
 *        means that the first read from a newly opened object is always
 *        treated as a new dependence. After each above-threshold read, the
 *        threshold is multiplied by a threshold factor f > 1. So, after N
 *        above-threshold reads, the threshold becomes f^N.
 *
 *        A ceiling for the threshold should be specified. A high ceiling will
 *        cause almost all reads to be ignored for all but processes with very* 
 *        short runtimes. A value of 4 is probably a good ceiling. Values of
 *        64 or more are not expected to be useful so the valid ceiling is
 *        capped at 63. Note that (2) is a special case of (3) with maximum
 *        threshold set to one.
 *
 *    (4) a TOO_LONG time window: if this much time has passed since the
 *        reporting of the last event, the next event will be reported *even*
 *        if it is redundant as per all of the preceding criteria. THIS IS
 *        ALSO A SAFETY FEATURE and operates regardless of new dependencies.
 *
 * %%%%   Should implement a version of TOO_LONG based on size and number of
 * %%%%   operations. This is already done for size (TOO_LARGE_SIZE) but not
 * %%%%   number of operations. Can be easily fixed WITHOUT maintaining # of
 * %%%%   ops. (Just use a random number generator.) However, what may be
 * %%%%   useful is an adaptive scheme similar to size-based. 
 ******** But we are not implementing this now. A concrete motivator for 
 *        TOO_LONG is that attacks can cause re-reading of files that were read
 *        long ago (e.g., /etc/passwd) and we don't want to miss them as existing
 *        dependencies. Size-based reductions are maintained because they serve
 *        the added purpose of maintaining total number of bytes read. In 
 *        contrast, counting the number of calls does not seem to have any
 *        compelling use  cases.
 *
 *    (5) We should consider a generalization of (3) that reverses the direction
 *        of adaptation of when a file descriptor is seeing relatively few
 *        operations.
 *
 *        Another generalization is to adjust the ceilings globally, as a
 *        function of system call volume being logged. During periods of
 *        intense activity, these ceilings should be increased, while during
 *        periods of low activity, the ceilings can be decreased. (Note that
 *        this is not a substitute for what is mentioned in the last para ---
 *        global adjustment helps with managing event volume but does not help
 *        us with I/O increase/decrease on specific file descriptors
 ******************************************************************************
 * [B] is relatively simple as compared to [A]: if a process closes and then
 * reopens the same object (i.e., the id is the same) then we treat it as if the
 * close and open didn't happen at all. This seems like a simple interpretation.
 * It also dictates that we suppress all close operations in this mode, i.e.,
 * they are never logged. Note that dup's are not logged when [A] is enabled.
 *****************************************************************************
 *****************************************************************************
 * Note that there is still and important case where post-processing can
 * recognize redundancies that the current technique cannot. Specifically, if a
 * subject makes several writes to an object but no one reads the object, it is
 * safe to combine all the writes into one *without* changing dependence. (The
 * subject's version should be changing between these writes-- otherwise only
 * the first of these writes would not have propagated to the pbject.) Note that
 * this reduction depends on future information: whether someone sees the
 * results of a write before a subsequent update overwrites the first one. So,
 * we will need to buffer such writes and wait in order to remove them. Such
 * buffering runs counter to our goals of minimizing the tampering window. It
 * will also be hard to implement such logic in ebpf due to the lack of loops. A
 * post-processing improvement can implement this without running into these
 * difficulties. Moreover, post-processing can do a lot more, such as removing
 * all references to files that were removed before they were read (by anyone
 * other than its creator). In otherwords, we will likely need an offline
 * component for dependency-preserving reduction, so might as well defer aspects
 * of reduction that don't match the goals and limitations of the primary data
 * collection step.
 *****************************************************************************
 *****************************************************************************
 *****************************************************************************
 * Now, onto the details of how we implement the above-mentioned reductions.
 * There are three key data structures that support [A]:
 *   obj_tab: LRU table mapping 64-bit id computed by fdtoid() to ObjInfo.
 *  subj_tab: LRU table mapping pid to SubjInfo.
 *    fi_tab: LRU table mapping fdkey = (fd, pid) pair to fileinfo, which 
 *            maintains subject-relevant info for the objects used by it.
 * These data structures are described in more detail below. 
 *****************************************************************************/

#ifdef FILTER_DIFF
#define OBJ_DIFF_LOG_SZ 4

struct ObjDiffEntry {
   u32 start_ver;
   u32 writer_pid;
   u32 writer_ver;
};
#endif

struct ObjInfo {
   u64 info;
#ifdef FILTER_DIFF
   struct ObjDiffEntry diff_log[OBJ_DIFF_LOG_SZ];
   u32 diff_head;
   u32 diff_tail;
   u32 diff_count;
   u32 diff_pad;
   u32 diff_min_start;
#endif
   // 6-bit ref count:    total # of fds pointing to this obj (from all subjs)
   // 22-bit last subj:   last writer (subject pid)
   // 6-bit update count: # of vers from this subj (no intervening writes from
   // 30-bit object version number.                               other subjs.)
 };

BPF_TABLE("lru_hash", ObjId, struct ObjInfo, obj_tab, MAX_OBJS);
// Commands such as find/tar can easily create so many new objects that every
// existing object will be evicted from this table. To prevent this, we should
// proactively delete objects from this table when all references to them have
// been closed. To do this, we need a refcount, which we maintain inside
// ObjInfo. (Note that if an ObjInfo does get evicted, this does not affect
// correctness but only (temporarily) reduces the effectiveness of the
// read/write optimization on these evicted objects. So, the worst outcome of an
// attack on this table is that read/write optimization becomes less effective.)
//
// ObjIds uniquely identify objects over time, so there is no reuse risk. But
// races are possible since multiple processes or threads may modify it at the
// same time. Ref count operations don't impact correctness of optimization,
// just its effectiveness, so the lack of locks is fine. Race conditions
// involving the remaining fields can lead to missed new dependencies. We will
// decide later if this is a big enough problem for us to use locks. Note: we
// can use bcc's atomic increment, but will need to separate the fields into
// distinct variables. Otherwise, we will need to unpack/repack bit fields,
// which cannot be done in a way that avoids race conditions (since ebpf does
// not give us a lock primitive at the tracepoint probes).

#define OBJ_REFCT_BITS 6
#define OBJ_SUBJ_BITS 22
#define UPDATE_CT_BITS 6
#define OBJ_VER_BITS 30
#define MAX_REFCT ((1<<OBJ_REFCT_BITS)-16)
// Hopefully, there won't be more than 16 concurrent refct operations on an
// object, and hence no possibility of overflowing refcount in the code below
// for updating refcounts.

#define refcount(oi) ((oi).info & ((1ul<<OBJ_REFCT_BITS)-1))
#define reset_refct(oi) \
   (oi).info = (((oi).info >> OBJ_REFCT_BITS) << OBJ_REFCT_BITS) | 0x1

#define inc_refct(oi) (oi).info++
#define dec_refct(oi) (oi).info--

#define objver(oi) ((oi).info >> (64-OBJ_VER_BITS))
#define inc_objver(oi) (oi).info += (1ul<<(64-OBJ_VER_BITS))


#ifdef FILTER_DIFF
static inline u8 next_idx(u8 idx, u8 limit) {
   u8 rv = idx + 1;
   if (rv >= limit)
      rv = 0;
   return rv;
}

static inline u8 prev_idx(u8 idx, u8 limit) {
   if (idx == 0)
      return limit - 1;
   return idx - 1;
}

static inline void obj_diff_reset(struct ObjInfo* oi) {
   oi->diff_head = 0;
   oi->diff_tail = 0;
   oi->diff_count = 0;
   oi->diff_pad = 0;
// #pragma unroll
   for (int i = 0; i < OBJ_DIFF_LOG_SZ; i++) {
      oi->diff_log[i].start_ver = 0;
      oi->diff_log[i].writer_pid = 0;
      oi->diff_log[i].writer_ver = 0;
   }
}

static inline void
init_objinfo(struct ObjInfo *oi) {
   oi->info = (((u64)bpf_get_prandom_u32()) << (64-OBJ_VER_BITS))|1;
   obj_diff_reset(oi);
}
 // We initialize the starting version to be a random number. This way, there
 // is only a very small chance that the new object will have a version
 // number that could be mistaken as the version already read by a subject. (Note
 // that this can happen only when an ObjInfo is auto-created after eviction.)
 
static inline void obj_diff_append(struct ObjInfo* oi, u32 start_ver,
                                   u32 writer_pid, u32 writer_ver) {
   if (!writer_pid)
      return;
   u8 tail = oi->diff_tail;
   u8 count = oi->diff_count;
   if (count) {
      u8 last = prev_idx(tail, OBJ_DIFF_LOG_SZ);
      struct ObjDiffEntry *last_entry = &oi->diff_log[last];
      if (last_entry->writer_pid == writer_pid) {
         last_entry->writer_ver = writer_ver;
         return;
      }
   }
   struct ObjDiffEntry *entry = &oi->diff_log[tail];
   entry->start_ver = start_ver;
   entry->writer_pid = writer_pid;
   entry->writer_ver = writer_ver;
   if (count < OBJ_DIFF_LOG_SZ) {
      oi->diff_count = count + 1;
   }
   else {
      oi->diff_head = next_idx(oi->diff_head, OBJ_DIFF_LOG_SZ);
   }
   oi->diff_tail = next_idx(tail, OBJ_DIFF_LOG_SZ);
}

static inline int 
obj_diff_has_history(struct ObjInfo* oi, u32 last_seen) {
   if (!last_seen)
      return 0;
   if (last_seen == objver(*oi))
      return 1;
   if (!oi->diff_count)
      return 0;
   u32 head = (u32)oi->diff_head;
   if (head >= OBJ_DIFF_LOG_SZ)
      return 0;
   struct ObjDiffEntry* oldest = &oi->diff_log[head];
   // if(oldest) {
      // u32 start_ver = oldest->start_ver;
      if (oldest->start_ver  > last_seen)
      return 0;
   // }
   return 1;
}
#else
static inline void
init_objinfo(struct ObjInfo *oi) {
   oi->info = (((u64)bpf_get_prandom_u32()) << (64-OBJ_VER_BITS))|1;
}
#endif


static inline void
link_oi(struct ObjInfo* oid) {
   u32 refct = refcount(*oid);
   if (refct <= MAX_REFCT)
      inc_refct(*oid);
   if (refct == MAX_REFCT)
      objinfo_overflow();
   // Note: If there are no races, then overflow will be triggered only once
   // per objinfo, regardless of how many times link_oi is called on it: once
   // refct goes above MAX_REFCT, it will never come back down.
}

// Returns a valid ObjInfo if oid is deleted; otherwise returns invalid value.
// A valid return value has refct <= 0, invalid one has refct MAX_REFCT. 
static inline struct ObjInfo
unlink_oi(ObjId oid) {
   struct ObjInfo rv = {MAX_REFCT};
   struct ObjInfo *oi = obj_tab.lookup(&oid);
   if (oi) { // If found, decrement refcount
      u32 refct = refcount(*oi);
      if (refct < MAX_REFCT) {
         if (refct <= 1) {
            rv = *oi;
            obj_tab.delete(&oid);
         }
         else dec_refct(*oi);
      }
      // If it is above the max, then we cannot rule out overflow, so
      // we don't delete. LRU should get rid of it eventually.
   }
   return rv;
}

static inline struct ObjInfo*
init_oi(ObjId oid) {
   struct ObjInfo ioi;
   init_objinfo(&ioi);
   obj_tab.insert(&oid, &ioi);
   struct ObjInfo *rv = obj_tab.lookup(&oid); 
   if (!rv) 
      objinfo_hard_fail();
   return rv;
} 

static inline struct ObjInfo* 
lookup_or_init_oi(ObjId oid, int addref, int complain) {
   struct ObjInfo *rv = obj_tab.lookup(&oid);
   if (rv) { 
      if (addref) 
         link_oi(rv);
   }
   else {
      if (complain)
         deleted_objinfo();
      rv = init_oi(oid);
   }
   return rv;
}

static inline u32
getobjver(ObjId oid, int addref, int complain) {
   struct ObjInfo* oi = lookup_or_init_oi(oid, addref, complain);
   if (oi)
      return objver(*oi);
   else return 0;
}

/****************************************************************************** 
 ******************************************************************************
 * We maintain info about subjects for the purposes of repeated read/write    *
 * optimization. The most important piece of info here is the subject version *
 * number, incremented each time the subject acquires a new dependency. It is *
 * OK to increment when we don't know if the dependency is new, but unsound if*
 * we fail to increment when there is a new dependence. For this reason, it is*
 * better to maintain a subject version for a task group, as the tasks inside *
 * may share memory, and hence a read by one task may change the dependence of*
 * other tasks in the task group. (Of course, it is possible for tasks NOT to *
 * share memory, and if so, this knowledge can be applied to achieve further  *
 * reduction in a post-processing phase. Our goal here is to reduce the amount*
 * of primary data that is logged, while ensuring soundness and simplicity of *
 * implementation. So we prefer this post-processing option.)                 *
 *****************************************************************************/

#ifdef FILTER_DIFF
#define SUBJ_WRITER_LOG_SZ 8
struct SubjWriterEntry {
   u32 writer_pid;
   u32 writer_ver;
};
#endif

struct SubjInfo {
   u8 flag_and_thr_ct;       // 7 bits for num threads, 1 bit per_thread_fi flag
   u8 pad_byte;              //
   u16 tseq;                 // Leading bits of subj creation time, used for
                             // disambiguating pids. +1 tseq = +64 seconds
   u32 subj_ver;             // Version, last_read and num_ver_from have
   u64 pad_word;             // the same meaning as for objects.
#ifdef FILTER_DIFF
   struct SubjWriterEntry writer_log[SUBJ_WRITER_LOG_SZ];
   u8 writer_head;
   u8 writer_tail;
   u8 writer_count;
   u8 writer_pad;
#endif
};

BPF_TABLE("lru_hash", u32 /*pid*/, struct SubjInfo, subj_tab, MAX_TASKS);
// Shell scripts can create more than MAX_TASKS child processes in a very short
// period, a period during which most other processes are likely idle. As a
// result, all existing processes may be evicted from subj_tab, and then
// read/write optimization will have to restart from scratch for all of them. To
// preempt this, we should proactively remove entries from this table as soon as
// processes exit. (From a correctness perspective, such eviction is OK: we will
// reinitialize these subjects when they make their next syscall.) To do this,
// we need to keep track of the number of threads in a task group, and delete
// subjinfo when the last thread exits. We also need to reset the thread count
// to one if an execve is performed. (Note: normal (single-threaded) processes 
// have exactly one thread.)

// PIds are reused, so we need to avoid subjinfo for one use of pid being mixed
// up with a reuse of the same pid. This is easy: each time a new process is
// created, we override the contents of subj_tab to reflect the current use. For
// single-threaded processes, subj_tab can be accessed safely without locks. For
// multi-threaded processes, locks are needed. However, the scope of race is
// reduced in the case of subjects because it is only among the threads in a
// thread group. And even these race conditions are unlikely because the process
// will then have the same races.

#define MAX_THREADS 116 // A margin of 12 for possible errors
#define S_THR_MASK 0xfe
#define S_THR_SHIFT 1

#define per_thread_fi(si) ((si).flag_and_thr_ct & 0x1)
#define reset_per_thread_fi(si) \
   (si).flag_and_thr_ct &= S_THR_MASK

#define nthreads(si) (((si).flag_and_thr_ct & S_THR_MASK) >> S_THR_SHIFT)
#define inc_thr(si) (si).flag_and_thr_ct += (1 << S_THR_SHIFT)
#define dec_thr(si) (si).flag_and_thr_ct -= (1 << S_THR_SHIFT)

// #define reset_si(si) \
//    (si).flag_and_thr_ct = 0x2 // per_thread flag=0, num threads=1

#ifdef FILTER_DIFF
static inline u32 
ring_next_u32(u32 x) {
    x++;
    if (x >= SUBJ_WRITER_LOG_SZ) x = 0;
    return x;
}

static inline void subj_writer_reset(struct SubjInfo* si) {
   si->writer_head = 0;
   si->writer_tail = 0;
   si->writer_count = 0;
   si->writer_pad = 0;
// #pragma unroll
   for (int i = 0; i < SUBJ_WRITER_LOG_SZ; i++) {
      si->writer_log[i].writer_pid = 0;
      si->writer_log[i].writer_ver = 0;
   }
}

static inline void reset_si(struct SubjInfo* si) {
   si->flag_and_thr_ct = 0x2; // per_thread flag=0, num threads=1
   subj_writer_reset(si);
}
#else
static inline void reset_si(struct SubjInfo* si) {
   si->flag_and_thr_ct = 0x2; // per_thread flag=0, num threads=1
}
#endif
#define ts_to_tseq(tsns) (((tsns) >> 36) & 0xffff)

#define subj_tseq(si) ((si).tseq)
#define subjver(si) ((si).subj_ver)

// %%%% Convert to locked increment
#define inc_subjver(si) (si).subj_ver++

static inline void
set_per_thread_fi(struct SubjInfo* si) {
   si->flag_and_thr_ct |= 0x1;
   per_thr_fi_subj();
}

#ifdef FILTER_DIFF
static inline u32 
subj_writer_known(struct SubjInfo* si, u32 writer_pid, u32 writer_ver) {
   if (!si || !writer_pid)
        return 0;

    u32 head  = (u32)si->writer_head;
    u32 count = (u32)si->writer_count;

    if (head >= SUBJ_WRITER_LOG_SZ)
        return 0;
    if (count > SUBJ_WRITER_LOG_SZ)
        count = SUBJ_WRITER_LOG_SZ;

   for (int i = 0; i < SUBJ_WRITER_LOG_SZ; i++) {
      if ((u32)i >= count)
         break;

      u32 idx = head + (u32)i;
      if (idx >= SUBJ_WRITER_LOG_SZ)
         idx -= SUBJ_WRITER_LOG_SZ;

      /* Read fields directly; no &pointer into map value */
      u32 pid = si->writer_log[idx].writer_pid;
      if (pid == writer_pid) {
         u32 ver = si->writer_log[idx].writer_ver; // version seen till now
         if (writer_ver <= ver)
            return 1;
         else return 0;
      }
      else //return 0 (i.e not known if writer_id is not in the diff log)
      return 0;
   }

    return 0;
}

static inline void 
subj_writer_record(struct SubjInfo* si, u32 writer_pid, u32 writer_ver) {
     if (!si || !writer_pid)
        return;

    u32 head  = (u32)si->writer_head;
    u32 tail  = (u32)si->writer_tail;
    u32 count = (u32)si->writer_count;

    if (head >= SUBJ_WRITER_LOG_SZ)
        head = 0;                       
    if (tail >= SUBJ_WRITER_LOG_SZ)
        tail = 0;
    if (count > SUBJ_WRITER_LOG_SZ)
        count = SUBJ_WRITER_LOG_SZ;

    for (int i = 0; i < SUBJ_WRITER_LOG_SZ; i++) {
         if ((u32)i >= count)
            break;

         u32 idx = head + (u32)i;
         if (idx >= SUBJ_WRITER_LOG_SZ)
            idx -= SUBJ_WRITER_LOG_SZ;
         si->writer_log[1].writer_ver = writer_ver;
         // u32 pid = si->writer_log[idx].writer_pid;
         // if (pid == writer_pid) {
         //    si->writer_log[idx].writer_ver = writer_ver;
         //    return;
         // }
    }

    /* PASS 2: insert at tail (ring buffer push) */
    /* Write new entry at tail (tail is proven < N above) */
   //  si->writer_log[tail].writer_pid = writer_pid;
   //  si->writer_log[tail].writer_ver = writer_ver;

    /* Advance tail, and if full advance head too; maintain count */
    u32 new_tail = ring_next_u32(tail);
   //  if (count < SUBJ_WRITER_LOG_SZ) {
   //      si->writer_count = count + 1;
   //  } else {
   //      /* Buffer full: drop oldest by advancing head */
   //      u32 new_head = ring_next_u32(head);
   //      si->writer_head = new_head;
   //  }
   //  si->writer_tail = new_tail;
}

static inline int 
obj_diff_writers_known(struct ObjInfo* oi, struct SubjInfo* si, u32 last_seen, 
                        u32 self_pid, u32 self_ver) {

   u32 count = (u32)oi->diff_count;
   if (!count)
      return (last_seen == objver(*oi)); 

   if (count > OBJ_DIFF_LOG_SZ)
      count = OBJ_DIFF_LOG_SZ;

   u32 head = (u32)oi->diff_head;
   if (head >= OBJ_DIFF_LOG_SZ)
      return 0;

   u32 start_pos = 0;
   int found = 0;

    /* PASS 1: find last entry with start_ver <= last_seen */
// #pragma clang loop unroll(full)
   for (int i = 0; i < OBJ_DIFF_LOG_SZ; i++) {
      if ((u32)i >= count)
         break;

      u32 idx = head + (u32)i;
      if (idx >= OBJ_DIFF_LOG_SZ)
         idx -= OBJ_DIFF_LOG_SZ;

      /* Load directly into a scalar; no pointer into map value */
      u32 start_ver = oi->diff_log[idx].start_ver;

      if (start_ver <= last_seen) {
         start_pos = (u32)i;
         found = 1;
      }
   }

   if (!found)
      start_pos = 0;

    /* PASS 2: check each writer from start_pos..count-1 */
   for (int i = 0; i < OBJ_DIFF_LOG_SZ; i++) {
      if ((u32)i >= count)
         break;
      if ((u32)i < start_pos)
         continue;

      u32 idx = head + (u32)i;
      if (idx >= OBJ_DIFF_LOG_SZ)
         idx -= OBJ_DIFF_LOG_SZ;

      /* Load fields into locals BEFORE any helper call */
      u32 writer_pid = oi->diff_log[idx].writer_pid;
      u32 writer_ver = oi->diff_log[idx].writer_ver;

      if (!writer_pid && !writer_ver)
         continue;
      /*Check if it knows it's own version*/
      if (writer_pid == self_pid) {
         if(writer_ver <= self_ver) return 1;
      }
      /*Check self diff log to find the new dependencies*/
      u32 known = subj_writer_known(si, writer_pid, writer_ver);
      if (!known) return 1;
   }
   return 1;
}

static inline void obj_diff_record_subject(struct ObjInfo* oi,
      struct SubjInfo* si) {
   u32 count = oi->diff_count;
   u32 head = oi->diff_head;
// #pragma unroll
   for (int i = 0; i < OBJ_DIFF_LOG_SZ; i++) {
      if (i >= count)
         break;
      u32 idx = head + i;
      if (idx >= OBJ_DIFF_LOG_SZ)
         idx -= OBJ_DIFF_LOG_SZ;
      struct ObjDiffEntry *entry = &oi->diff_log[idx];
      // if (!entry->writer_pid)
      //    continue;
      // subj_writer_record(si, entry->writer_pid, entry->writer_ver);
      subj_writer_record(si, 100, 200);

   }
}
#endif
static inline void
init_si(struct SubjInfo *si, u64 ts_ns) {
   reset_si(si);
   si->pad_word = 0;
   si->pad_byte = 0;
   si->tseq = ts_to_tseq(ts_ns);
   si->subj_ver = bpf_get_prandom_u32();
   // Like Objinfo, init ver is random 
}

static inline void
delete_subj(int pid) {
   // We had some logic to clean up unclosed fds of processes that exited
   // uncleanly. Unfortunately, given the lack of loops in ebpf, and that we
   // don't know of a simple way to identify unclosed fds, we had to give up.
   // cleanup_proc_fi(pid);
   subj_tab.delete(&pid);
}

static inline void
make_si(u32 pid, int per_thread_fi, int add_thread) {
      struct SubjInfo isi = {0};
      init_si(&isi, bpf_ktime_get_ns());
      if (add_thread) {
         deleted_subjinfo();
         inc_thr(isi);
      }
      if (per_thread_fi)
         set_per_thread_fi(&isi);
      subj_tab.insert(&pid, &isi);
}

///////////////////////////////////////////////////////////////////////////////
// When per_thread_fi is enabled, we lookup fileinfo using thread ids. But we
// still keep one SubjInfo for a thread group, so no changes are needed for
// SubjInfo-related routines. (In practice, processes tend to be single-threaded
// or follow the pthread model where fds are shared across threads. In both
// cases, maintaining fileinfo for the whole process is the right way.)

static inline void
add_si(u32 pid, int per_thread_fi, int add_thread) {
   inc_subj();
   struct SubjInfo *si = subj_tab.lookup(&pid);
   if (si) {
      if (add_thread) {
         u32 nthr = nthreads(*si);
         if (nthr <= MAX_THREADS)
            inc_thr(*si);
         if (nthr == MAX_THREADS) 
            subjinfo_overflow();
         if (per_thread_fi)
            set_per_thread_fi(si);
         return;
      }
      else {
         undeleted_subjinfo();
         delete_subj(pid);
      }

   }
   make_si(pid, per_thread_fi, add_thread); // @@@@ ?? Shouldn't this be in else?
}

static inline struct SubjInfo* 
lookup_or_init_si(int pid) {
   struct SubjInfo *rv = subj_tab.lookup(&pid);
   if (!rv) { 
      deleted_subjinfo();
      make_si(pid, 0, 0);
      rv = subj_tab.lookup(&pid); 
      if (!rv) 
         subjinfo_hard_fail();
   }
   return rv;
}

static inline void
dec_threads(u32 pid) {
   struct SubjInfo *si = subj_tab.lookup(&pid);
   if (si) { // If found, decrement refcount
      if (per_thread_fi(*si))
         ; // cleanup_proc_fi(gettid());
      u32 nthr = nthreads(*si);
      if (nthr < MAX_THREADS) {
         if (nthr <= 1)
            delete_subj(pid);
         else dec_thr(*si);
      }
      // If it is above the max, then we cannot rule out overflow, so we don't
      // delete. LRU should get rid of it eventually. We won't increment error
      // counts, as the error would already have been counted when the count
      // went above MAX_THREADS.
   }
   else deleted_subjinfo(); // Should have been there, but must have been 
   // evicted, or deleted prematurely due to lost increments. But we don't
   // insert a manufactured subjinfo, as we have zero info about the subject.
}

static inline void
reset_threads() {
   int pid = getpid();
   struct SubjInfo *si = subj_tab.lookup(&pid);
   if (si)
      reset_si(si);
   else {
      deleted_subjinfo();
      make_si(pid, 0, 0);
   }
}

#else

#define unlink_oi(x)

static inline void
add_si(u32 pid, int per_thread_fi, int add_thread) {
   inc_subj();
}
#endif


#if defined(ID_NOT_FD) || defined(FILTER_REP_RDWR)
struct fdkey {
   int pid;
   int fd;
};
typedef u64 SidOid;

static inline SidOid
mkSidOid(u64 sid, ObjId oid) {
   u64 a = 4180931754112693231;
   u64 b = 6142800075450824493;
   return (a+sid)*(b+oid); 
}

#ifdef INSTRUMENT_CACHED_FDINFO
BPF_TABLE("lru_hash", SidOid, ObjId, fi_instr_cache, MAX_OBJS); 
#endif
// We use a global map, as opposed to a per-subject map. The latter choice
// will require each subject's table to be large enough to accommodate the
// "biggest" subjects in terms of FD use, while a global table can be sized
// for the average subject. 

/******************************************************************************
 * Fileinfo supports suppression of repeated reads/writes on the same object.
 * New dependency based reduction is the most important and also the most
 * complex among the options. The part about incrementing object versions on
 * each write, and comparing this version with last_read field in fdi is
 * obviously correct. The second aspect of the optimization it to (i) skip
 * object version increment if the writing subject's version (last_written)
 * hasn't changed since its last write, and (ii) if the object's version is
 * upped, then updating the last_read version as well, *provided* that the
 * last_read version corresponded to the object's latest version before this
 * update. These two steps are enough to skip version generation in many cases.
 * For instance, in the case of sockets, there are usually two writers, and this
 * logic is enough to ensure that writes by one subject don't result in a new
 * version for the same subject. As a result, if one subject performs a series
 * of writes without intervening reads by the peer, the peer will see just one
 * new version at the end. A similar observation can be made about a file
 * written by one or more writers and read by one or more readers. Finally, for
 * files that are written and later read by the same process, all reads can be
 * seen as redundant and suppressed.
 *****************************************************************************/

struct fileinfo {
   ObjId oid;
#ifdef FILTER_REP_RDWR                              
   u64 last_op_time_and_status; // 1 bit cached flag, 16-bit rd_ver_thresh, 
                                // plus 47 MS bits of ns time stamp.
   u32 rdbytes; // MS 5-bits = log2(reported), LS 27 bits = unreported.
   u32 wrbytes; // So, max for unreported is 128MB, max reported ~512MB
#ifdef FILTER_DEP
   u32 last_read;    // Last object version read using this FD
   u32 last_written; // Subject's last version at the time of last write
#endif
#endif
};

BPF_TABLE("lru_hash", struct fdkey, struct fileinfo, fi_tab, MAX_FDS); 

// We use a global map, as opposed to a per-subject map. The latter choice
// will require each subject's table to be large enough to accommodate the
// "biggest" subjects in terms of FD use, while a global table can be sized
// for the average subject. 

/****************************************************************************** 
 * Similar to SubjInfo and ObjInfo maps, fileinfo maps can also get overrun by
 * activity bursts that use a large number of files. So, we again need a means
 * to promptly release these entries. One obvious place is close. But some
 * processes may exit without closing fds, so we also need to check possibly
 * open fds at the point of exit, and close them all. This was supposed to be
 * done in the cleanup_proc_fi, but has been abandoned due to complications
 * mentioned earlier.
 ******************************************************************************
 * Typically, applications use pthreads, which invokes clone with CLONE_FILES
 * flag. So, we will almost always have CLONE_FILES with CLONE_THREAD. This has
 * been confirmed for Firefox and Chrome. In this typical case, fi's can be
 * looked up using a combination of fd and pid. In the unusual cases where fds
 * are not shared across threads, we catch this by examining clone flags and
 * setting the per_thread_fi flag of the subject. For such subjects, tids are
 * used for looking up fi's.
 ******************************************************************************
 * Although fi's may be looked up using tid, note that subject version is
 * incremented for any read by any thread in a process. As such, per_thread_fi
 * is NOT a source of unsoundness, although it makes reductions less effective.
 ******************************************************************************
 * Reuse of pids will continue to be a problem in fi_tab. However, due to the
 * steps taken to remove stale entries, it can happen only if all of the
 * following conditions hold:
 *
 *   1. A process exits uncleanly (w/o closing all fds).
 *   2. Its pid is reused.
 *   3. The (fd, pid) pair survives LRU-based eviction. This is not easy: pids
 *      aren't reused until over 4M other processes have been created. Each
 *      such process will insert entries into fi_tab so the old ones should
 *      be long gone by the time of reuse, UNLESS the LRU algorithm has bugs,
 *      or doesn't even provide basic correctness such as unused entries will
 *      eventually be evicted.
 *   4. The fd is not explicitly opened but is inherited from the parent after
 *      a fork. (Or else we would have updated the fileinfo at open time.)
 *
 * For now, (3) seems to be fool-proof, and (1) is also low probability event.
 * (4) is also not high probability. So, we won't worry about reuse.
 *****************************************************************************
 * Race conditions are also possible, but they all involve threads within a
 * single process. Moreover, these threads should be concurrently reading or
 * writing the same fd. (Successful concurrent opens or closes of the same fd
 * are not possible.) Since
 *   (a) the vast majority of Linux processes are single-threaded,
 *   (b) multithreaded processes do not typically access the same fd at the
 *       same time (it would not even work correctly several years ago), and
 *   (c) one process cannot cause races involving flows of another process.
 * For these reasons, we will ignore this problem for now.
 *****************************************************************************/

#ifdef FILTER_REP_RDWR

#define bytes_rep(info) ((info) >> 27)
#define bytes_unrep(info) ((info) & ((1<<27)-1))  // LS 27 bits = bytes_unrep.
#define rdwrbytes(reported, unreported) (((reported) << 27) \
                                        | ((unreported) & ((1<<27)-1)))

#define is_cached(x) ((x).last_op_time_and_status & 0x1)
#define set_cached(x) (x).last_op_time_and_status |= 0x1

#define rd_ver_thresh(x) (((x).last_op_time_and_status >> 1) & 0xffff)
#define set_rd_ver_thresh(x, r) \
   (x).last_op_time_and_status  =  \
      ((x).last_op_time_and_status & (~(0xfffful << 1))) | (((r)&0xffff) << 1)

#define last_op_time(x) (((x).last_op_time_and_status >> 17) << 17)
#define upd_last_time(x, ts) \
   (x).last_op_time_and_status = \
      ((x).last_op_time_and_status & 0x1fffful) | ((ts) & (~(0x1fffful)))

#endif   

static inline void
fi_init(struct fileinfo* fi, ObjId oid, u64 ts, u16 rd_ver_thr,
        u32 last_read, u32 last_written) {
   fi->oid = oid;
#ifdef FILTER_REP_RDWR
   fi->last_op_time_and_status = 0;
   set_rd_ver_thresh(*fi, rd_ver_thr);
   upd_last_time(*fi, ts);
   fi->rdbytes = 0;
   fi->wrbytes = 0;
#ifdef FILTER_DEP
   fi->last_read = last_read;
   fi->last_written = last_written;
#endif
#endif
}

// Some basic operations on fi_tab. More complex operations will be defined
// after introducing maps for remembering read/write info across multiple opens.
static inline void
update_fi(int fd, struct fileinfo* fi, int pid, int reusing) {
#ifdef INSTRUMENT_CACHED_FDINFO
   SidOid po = mkSidOid(pid, fi->oid);
   if (fi_instr_cache.lookup(&po)) {
      if (!reusing)
         missed_file_reuse();
   }
   else fi_instr_cache.update(&po, &fi->oid);
#endif

   struct fdkey fdk = {pid, fd};
   fi_tab.update(&fdk, fi);
}

static inline struct fileinfo*
lookup_fi(int fd, int pid) {
   struct fdkey fdk = {pid, fd};
   return fi_tab.lookup(&fdk);
}

static inline void
copy_fi(int srcfd, int dstfd, int pid) {
   struct fdkey sfdk = {pid, srcfd};
   struct fileinfo* fi = fi_tab.lookup(&sfdk);
   if (fi) {
      struct fdkey dfdk = sfdk;
      dfdk.fd = dstfd;
      fi_tab.update(&dfdk, fi);
   }
}

static inline void
move_fi(int srcfd, int dstfd, int pid) {
   struct fdkey sfdk = {pid, srcfd};
   struct fileinfo* fi = fi_tab.lookup(&sfdk);
   if (fi) {
      struct fdkey dfdk = sfdk;
      dfdk.fd = dstfd;
      fi_tab.update(&dfdk, fi);
      fi_tab.delete(&sfdk);
   }
}

static inline void
delete_fi(int fd, int pid) {
   struct fdkey fdk = {pid, fd};
   fi_tab.delete(&fdk);
}

#ifdef FILTER_REP_OPEN
/****************************************************************************** 
 * Some objects are repeatedly used by the *very same* process. Examples: a
 * browser repeatedly accessing a web site, a server repeatedly used by the
 * same client, a temp file written and then read later by a process, etc. In
 * these cases, we can perform dependency reduction across these "sessions:"
 *
 *   (a) suppress repeated opens, just reporting the first one, and
 *   (b) treating the reads/writes across these sessions as if they happened
 *       in a single session. This allows for more aggressive reduction
 *
 * To support this, we cache fileinfo after a process closes an fd. If the same
 * process reopens this object, we reuse the cached fileinfo instead of newly
 * creating it. As a result, information such as the last version read or
 * written by the subject can be used to suppress even the very first read/write
 * in a new session. Similarly, if size-based suppression is used, then we start
 * from the previous size window rather than window=1. Hence, many more
 * read/writes will be suppressed. For this to work, fileinfo should be stashed
 * away somewhere. We can use another LRU table for this, but that table will
 * contain fileinfo of *every* closed file descriptor. Since re-opens of fds are
 * rare, and single use is common, this table will quickly fill up, and
 * candidates for reuse will likely get evicted. So we rely on two caches:
 *  
 *   -- fi_temp_cache is used to store fileinfo for closed fds. This cache is
 *      subject overruns and evictions, so we may miss opportunities for the
 *      the first reuse of the file by a process.
 *
 *   -- if a fileinfo is reopened, then it is marked. If it is closed for a 
 *      second time, it is moved to fi_reuse_cache. Since this cache contains
 *      only objects that were reopened by a process, entries in this cache
 *      are unlikely to get evicted. 
 *
 *   -- during the time fileinfo is in these caches, the object referenced by
 *      them maybe evicted from obj_tab. So, we save a copy in a second table
 *      called fi_temp_tab. (Although we prepared for the ObjInfo to be deleted,
 *      it is often the case that it is still in obj_tab. If so, we reuse it
 *      from there and simply delete the copy in fi_temp_tab. But in the rare
 *      case where it is no longer in the obj_tab, we delete from the temp_tab
 *      and reinsert it there. Note that at this point, the ObjInfo should be
 *      reset, requiring the reinitialization of many fields.
 *
 * Note that fi_temp_cache cannot be organized using fd numbers because there is
 * no relationship between fds used across reopens. So, the caches are keyed by
 * SidOid, i.e., the combination of the subject's pid and the object id. (To
 * cope with reuse of pid's, we also compare the timestamps on SubjInfo with
 * those on fileinfo --- a reuse would be characterized by the SubjInfo's
 * timestamp being later than that of fileinfo. These timestamps are incremented
 * once every ~1 minute, which is OK since pid reuse don't happen for 4M new
 * processes. We can catch reuse upto 32K minutes (about 0.8 months) --- long
 * enough that LRU should have got rid of the stale entries by then. )
 *
 * Race conditions are possible but unlikely because the caches are organized by
 * pid. In particular, a race is possible if multiple threads of the same
 * process are simultaneously reopening a file that was previously opened by the
 * subject; or one thread is trying to close and another trying to reopen. Not
 * only does this seem unlikely, it is also the case that the cache contents
 * don't get updated. For all these races, we ignore the possibility of races,
 * at least for now.
 ******************************************************************************* 
 * We did investigate an alternate design that uses (a) a two level maps fdkey
 * -> (object, subjid) -> fileinfo, and (b) used a single cache fileinfos. For a
 * few reasons, this design did not work satisfactorily, so it was abandoned. A
 * copy of this logic can be found in the file called logreduce_branch.c
 ******************************************************************************/

BPF_TABLE("lru_hash", SidOid, struct fileinfo, fi_temp_cache, TEMP_CACHE_SZ); 
BPF_TABLE("lru_hash", SidOid, struct fileinfo, fi_reuse_cache, FDI_REUSE_SZ);
BPF_TABLE("lru_hash", ObjId, struct ObjInfo, fi_temp_tab, TEMP_CACHE_SZ);

#endif

#ifdef FILTER_REP_RDWR
static inline int
lookup_cached_fi(int fd, ObjId oid, int pid, struct SubjInfo* si, bool for_rdwr) {
#ifdef FILTER_REP_OPEN
   SidOid key = mkSidOid(pid, oid);
   // First try the reuse cache
   struct fileinfo* fi = fi_reuse_cache.lookup(&key);
   if (fi) {
      if (fi->oid == oid) { // Right object
         u16 subjstart = subj_tseq(*si);
         u16 fistart = ts_to_tseq(last_op_time(*fi));
         if (fistart - subjstart < 0x8000) { 
            // valid fi: subj started first. Move it from the cache to fi_tab.
            update_fi(fd, fi, pid, 1);
            fi_reuse_cache.delete(&key);
            if (!for_rdwr)
               file_reuse_succ();
            return 1;
         }
         else {
            // fileinfo in the cache is stale, delete it.
            fi_reuse_cache.delete(&key);
            file_reuse_stale();
         }
      }
      else sidoid_collision();
   }
 
   // Didn't find in the reuse cache, so try the temp cache     
   fi = fi_temp_cache.lookup(&key);
   if (fi) {
      if (fi->oid == oid) { // Right object
         u16 subjstart = subj_tseq(*si);
         u16 fistart = ts_to_tseq(last_op_time(*fi));
         if (fistart - subjstart < 0x8000) { // valid fi: subj started first
            set_cached(*fi); // Mark so it will be put in reuse_cache in future.
            struct ObjInfo *oi = obj_tab.lookup(&fi->oid);
            if (!oi) {
               // Object deleted from obj_tab because no process has it open.
               // We lookup in the temp tab and if present, move to obj_tab.
               // Since this will be a new reference to the object, the
               // ref count should be reset to 1.
               // @@@@@ But this is broken! The temp_tab will have stale values
               // @@@@@ for object version, so is unsound to use. Should examine
               // @@@@@ the impact of this, and then remove temp_tab altogether:
               // it seems there's no way to ensure correct info in temp_tab.
               oi = fi_temp_tab.lookup(&fi->oid);
               if (oi) {
                  reset_refct(*oi);
                  obj_tab.insert(&fi->oid, oi);
                  fi_temp_tab.delete(&fi->oid);
               }
            }
            else link_oi(oi);
            if (!oi) {
               deleted_oi_tmp_cache();
               init_oi(fi->oid);
            }
            // Move fileinfo from temp_cache to fi_tab.
            update_fi(fd, fi, pid, 1);
            fi_temp_cache.delete(&key);
            if (!for_rdwr)
               file_reuse_succ();
            return 1;
         }
         else {
            // fileinfo in the cache is stale, delete it.
            fi_temp_cache.delete(&key);
            file_reuse_stale();
         }
      }
      else sidoid_collision();
   }
   if (!for_rdwr)
      file_reuse_fail();
#endif
   return 0;
}
#endif

// Some files are empty to start with, i.e., !has_unread_data. If so, we can
// initlialize fd so that the current version has already been read. Otherwise,
// we set the version in the fi to be one before the object's version.
static inline int
init_fi(int fd, ObjId oid, int pid, int has_unread_data, bool for_rdwr) {
   int rv = 0;
   struct fileinfo fi;
#ifdef FILTER_REP_RDWR
   struct SubjInfo* si = lookup_or_init_si(pid);
   if (si) {
      if (per_thread_fi(*si)) // If per_thread_fi is set then maintain fd
         pid = gettid();      // information per task, not per task group
      if (!(rv=lookup_cached_fi(fd, oid, pid, si, for_rdwr))) {
         fi_init(&fi, oid, bpf_ktime_get_ns(), (1 << VER_THR_SHIFT),
                 getobjver(oid, 1, 0)-has_unread_data, subjver(*si)-1);
         update_fi(fd, &fi, pid, 0);
      }
   }
#else
   fi_init(&fi, oid, 0, 0, 0, 0);
   update_fi(fd, &fi, pid, 0);
#endif
   return rv;
}

// init_fi should be called when creating a new fd, e.g., from open, connect,
// accept. In other contexts, we are looking up an existing fi, but we should
// call lookup_or_init because this fi may have been evicted. If so, we need
// to recompute the id for this fd and then reinitilize fi.
static inline struct fileinfo*
lookup_or_init_fi(int fd, int pid) {
   struct fileinfo *rv = lookup_fi(fd, pid);
   if (!rv) {
      deleted_fi();
      ObjId oid = fdtoid(fd, 0);
      init_fi(fd, oid, pid, 1, true);
      rv = lookup_fi(fd, pid);
      if (!rv)
         fi_hard_fail();
   }
   return rv;
}

static inline ObjId
lookup_fdtooi(int fd, int pid) {
   struct fileinfo *rv = lookup_fi(fd, pid);
   if (!rv)
      // We call this from proc(), which is invoked before writing out syscall
      // data. The fi in question must have been accessed just now, so this
      // fail is unlikely. In any case, the correct behavior is to recompute
      // the id from fd and return it.      
      return fdtoid(fd, 0);
   else return rv->oid;
}

// cleanup is called from close: since the fd is closed, we should remove
// the fi from fi_tab. (This info will will be stashed in the caches as needed.)
// When data reduction features are in effect, the last read may not have been
// reported so there may be unreported bytes read or written. This is returned
// to the caller so it can report them to the user level as additional 
// "argument" for close. 
// @@@@ But this is broken when repeated opens are suppressed, as we suppress
// @@@@ close in this case. An alternative is to report a read/write instead,
// @@@@ but we don't do this for three reasons: (a) it seems to run counter to
// @@@@ the goals of data reduction, (b) the read/write will be a "manufactured"
// @@@@ one, as it does not match the time of an actual read/write, and (c) if
// @@@@ new dependency based reduction is in play, number of bytes read/written
// @@@@ seem not critical, and hence can be skipped. BUT KEEP IN MIND THAT WE
// @@@@ IF EXPONENTIAL SIZE-BASED SCHEME IS IN PLAY, IT IS LIKELY THAT THE
// @@@@ VAST MAJORITY OF BYTES READ/WRITTEN WONT BE REPORTED because unreported
// @@@@ bytes will likely be 2x to 8x reported bytes at any time.

static inline void
cleanup_fi(int fd, int pid, long *unrep_read, long *unrep_write) {
   struct fileinfo* fi = lookup_fi(fd, pid);
   if (fi) {
#ifdef FILTER_REP_RDWR
      if (unrep_read) *unrep_read = bytes_unrep(fi->rdbytes);
      if (unrep_write) *unrep_write = bytes_unrep(fi->wrbytes);

#ifdef FILTER_REP_OPEN
      SidOid po = mkSidOid(pid, fi->oid);
      if (is_cached(*fi)) {
         fi_reuse_cache.insert(&po, fi);
         return; // @@@@!!!! Seems wrong NOT to call delete_fi
      }
      else {
         fi_temp_cache.insert(&po, fi);
         struct ObjInfo oi = unlink_oi(fi->oid);
         if (refcount(oi) < MAX_REFCT)
            fi_temp_tab.insert(&fi->oid, &oi);
      }
#else
      unlink_oi(fi->oid);
#endif      
#endif 
      delete_fi(fd, pid);
   }
}
#endif 

#ifdef FILTER_REP_RDWR

/****************************************************************************** 
 ****************************************************************************** 
 * Helper functions to support suppression of repeated reads/writes from the
 * same fd. Most of these functions are just boolean functions, but we return an
 * integer value that partially captures the reason why a read or write is being
 * flagged as useful. This debug value flows through to the user level when
 * things are appropriately configured, and can be used for testing and
 * debugging. In this case, the code + 777700000 is returned as the number of
 * bytes read. Use of 7777 is so as to stand out in the output. Note that this
 * info can be returned for those read/writes that are NOT suppressed.
 *****************************************************************************/

static inline long
too_long_time(struct fileinfo *fi) {
   if(is_remote(fi->oid)){
      return NS_TO_FOREIGN_EP_EPOCH;
   }
   return TOO_LONG_TIME;
}

static inline int
fi_too_long(struct fileinfo *fi, u64 ts) {
   // Due to lack of synchrony across cores, current CLOCK_MONOTONIC time ts can
   // be less than the last update time fi_ts of the object. Experimentally, we
   // find that this difference occurs rarely (1 in 10K), and is between a few
   // ns to 1 microsec. So we shdn't use subtraction in the condition below.
   if (ts >= last_op_time(*fi) + too_long_time(fi))
      return 1;
   else return 0;
}

static inline int
too_large_rdwr_bytes() {
   return TOO_LARGE_RDWR_BYTES;
   // At one point, we viewed this as something that can be adapted, based on
   // the current load. On second thoughts, TOO_LONG and TOO_LARGE are
   // mechanisms to bound the worst-case --- as such, it does not seem wise
   // to make them changeable.
}

static inline int
fi_enough_sz(const u32 *bytes, u64 nb) {
   u64 unreported = bytes_unrep(*bytes) + nb;
   if (unreported == 0){
      mystat.atomic_increment(ZERO_RDWR_SKIPPED);
      return 0;
   }
   if (unreported <= TOO_SMALL_RDWR_BYTES){
      mystat.atomic_increment(TOO_SMALL_SKIPPED);
      return 0;
   }
   if (unreported >= too_large_rdwr_bytes()){
      mystat.atomic_increment(TOO_LARGE_LOGGED);
      return 2;
   }

   u64 reported = 1 << bytes_rep(*bytes);
   if (unreported >= (reported * MED_RDWR_RATIO)){
      mystat.atomic_increment(MED_RDWR_LOGGED);
      return 3;
   }

   return 0;
}

static inline int
fi_enough_size(struct fileinfo *fi, u8 is_read, u64 nb) {
#ifdef FILTER_SIZE
   if (is_read) 
      return fi_enough_sz(&fi->rdbytes, nb);
   else return fi_enough_sz(&fi->wrbytes, nb);
#else
   return 0;
#endif
}

static inline u32
max_ver_diff() {
   return TOO_LARGE_VER_DIFF;
   // Again, it may be best to leave this a constant so that we bound the
   // worst-case. Maybe it is better to apply adaptation to the ratio?
}

static inline int
enough_ver_diff(u32 srcver, u32 dstver, u32 thresh) {
   u32 verdiff = srcver - dstver;
   // If srcver or dstver or both are random --- this is what happens if
   // objinfo or subjinfo is evicted and recreated --- the result is still
   // a positive number that is most likely above the threshold below. Thus,
   // these evicted cases (and many other errors), with very high probability,
   // won't compromise soundness.

   u32 allowed_ver_diff = mymin(thresh >> VER_THR_SHIFT, max_ver_diff());
   // Note: VER_THR_SHIFT is used so we can work use integer arithmetic although
   // thresh is fractional: its effective value is thresh*2^(-VER_THR_SHIFT).

   return (verdiff >= allowed_ver_diff
   );
   // Note: minimum allowed_ver_diff value is 1, so that multiplicative 
   // threshold increase will work correctly. But we want to interpret 1 to
   // mean that the allowed version difference is zero. This happens if we
   // use >= instead of > in the above comparison.
}

static inline int
fi_is_newdep(struct fileinfo *fi, u8 is_read, 
              struct SubjInfo* si, int pid, int fd) {
#ifndef FILTER_DEP
   return 0;
#else
   int rv = 1;
   if (si) {
      if (is_read) {
         struct ObjInfo* oi = lookup_or_init_oi(fi->oid, 0, 1);
         if (oi) {
           
#ifdef FILTER_DIFF
            u32 last_seen = fi->last_read;
            bpf_trace_printk("Diff enabled");
            if (obj_diff_has_history(oi, last_seen) &&
                obj_diff_writers_known(oi, si, last_seen, pid, subjver(*si)))
               rv = 0;
            else rv = rd_ver_thresh(*fi);
#else
             if (enough_ver_diff(objver(*oi), fi->last_read,
                    rd_ver_thresh(*fi))) // Adaptive threshold
                rv = rd_ver_thresh(*fi);
             else rv = 0;
#endif
         }
      }
      else if (enough_ver_diff(subjver(*si), fi->last_written,
                  1 << VER_THR_SHIFT)) // NOT using adaptive threshold for write
         rv = 4;
      else rv = 0;
   }
   return rv;
#endif
}

static inline void
fi_add_rdwr_bytes(u32* bytes, u32 nb) {
   u32 unreported = bytes_unrep(*bytes) + nb;
   u32 reported = bytes_rep(*bytes);
   *bytes = rdwrbytes(reported, unreported);
}

static inline u8
probabilistic_add(u64 newct, u8 log2ct) {
   u64 rep = 1 << log2ct;
   if (newct >= rep)
      rep += newct;
   else { 
      // We only store log(rep). Since log(rep+newct)=log(rep) in this case, a
      // deterministic approach will permanently leave rep to be the same,
      // regardless of the number of times we add some number of bytes to it.
      // Instead, the probabilistic approach below doubles rep with the
      // probability newct/rep.        
      u64 rnd = bpf_get_prandom_u32() & (rep-1);
      if (newct > rnd) rep += rep;
   }
   rep = bpf_log2l(rep)-1;
   return rep;
}

static inline u64
fi_upd_rdwr(u32* bytes, u32 nb, int newdep) {
   u64 rv = bytes_unrep(*bytes) + nb;
   u64 rep = 0;
#ifdef FILTER_SIZE
   rep = probabilistic_add(rv, bytes_rep(*bytes));
#endif
   u64 unrep = 0;
   *bytes = rdwrbytes(rep, unrep);
   return rv;
}

static inline u16
adj_ver_diff(u16 cur_thresh) {
   u32 rv = cur_thresh;
   rv *= VER_DIFF_THRESH_FAC;
   rv += (1 << (VER_THR_SHIFT-1)); // To round rather than truncate
   rv = (rv >> VER_THR_SHIFT) & 0xffff;
   // if (cur_thresh <= rv) 
      return rv;
   // else return cur_thresh; // This case seems impossible.
}

static inline u64
fi_do_rdwr(struct fileinfo *fi, u8 is_read, u64 nb, u64 ts, 
            int newdep, struct SubjInfo* si, int pid) {
   u64 rv=0;
   if (is_read)
      rv = fi_upd_rdwr(&fi->rdbytes, nb, newdep);
   else rv = fi_upd_rdwr(&fi->wrbytes, nb, newdep);
   upd_last_time(*fi, ts);

#ifdef FILTER_DEP
   if (newdep) {
      struct ObjInfo* oi = obj_tab.lookup(&fi->oid);
      if (oi) {
         if (is_read) {
            fi->last_read = (u32)objver(*oi);
            inc_subjver(*si);
#ifdef FILTER_DIFF
            obj_diff_record_subject(oi, si);
#endif
            set_rd_ver_thresh(*fi, adj_ver_diff(rd_ver_thresh(*fi)));
         }
         else {
            fi->last_written = subjver(*si);
// #ifdef FILTER_DIFF
//             subj_writer_record(si, pid, subjver(*si));
// #endif
            bool update_ver = true;
#ifdef NO_REMOTE_VER
            update_ver = !is_remote(fi->oid);
#endif
            if(update_ver){

#ifdef FILTER_DIFF
               u32 prev_version = objver(*oi);
#endif
               inc_objver(*oi);
// #ifdef FILTER_DIFF
//                obj_diff_append(oi, prev_version, pid, subjver(*si));
// #endif
         }
      }
   }
   }
#endif

   return ++rv; // Add one so it will never be zero
}

static inline u64
useful_rdwr(int fd, u64 nb, u8 is_read, u64 ts, int pid) {
   u64 rv=0; int newdep=0;
   // We may pass lots of time without logging any syscall because they are 
   // all redundant. During this time, syscalls already in buf are delayed 
   // indefinitely from being received. So, occasionally check_xmit them.
//#ifdef FLUSH_IN_RDWR
   if ((ts & 0x700) == 0) { 
      // Should hold for 1/8th of the calls; or, for 0.25us every 2us
      struct buf* b = get_cache(ts);
      if (b) {
         if (cached_toolong(b->idx, b->start_ts, ts)
#ifndef FULL_TIME
              || (MS_BITS(b->start_ts) != MS_BITS(ts))
#endif
         )
         check_xmit1(b, &b->idx, ts, 1, 0);
         unlock_cache(b);
      }
   }
//#endif
   struct SubjInfo* si = lookup_or_init_si(pid);
   if (!si) 
      mystat.atomic_increment(SUBJINFO_DELETED_RDWR);
   if ((si) && per_thread_fi(*si)) 
      pid = gettid();
   struct fileinfo* fi = lookup_or_init_fi(fd, pid);
   if (si && fi) {
      profile_fd(fd, nthreads(*si));
#if defined(FILTER_SIZE) || defined(FILTER_DEP)
      if ((rv = newdep = fi_is_newdep(fi, is_read, si, pid, fd))
          || (rv = fi_too_long(fi, ts))
          || (rv = fi_enough_size(fi, is_read, nb)))
         ;
#else
      rv = 31;
#endif

      if (rv)  {
#ifdef FILTER_REASON
         rv += 777700001;
#else
         rv = 
#endif
            fi_do_rdwr(fi, is_read, nb, ts, newdep, si, pid);
         rdwr_recorded();
      }
      else {
         rdwr_suppressed();
         if (is_read)
            fi_add_rdwr_bytes(&fi->rdbytes, nb);
         else fi_add_rdwr_bytes(&fi->wrbytes, nb);
      }
      return rv;
   }
#ifdef FILTER_REASON
   return 7777001 + 8;
#else
   return nb+1; // Our convention is to return 1+# of bytes 
#endif
}
#endif

#ifdef ID_NOT_FD
static inline u64
proc(long fd) {
   u64 rv = fd;
   if (fd >= 0) {
      int pid = getpid();
      // Since most processes tend to be single-threaded or follow the pthread 
      // model where fds are shared across threads, we use the pid to store the 
      // fd to oi lookup. This avoids having to additionally store SubjInfo for 
      // using id.
#ifdef FILTER_REP_RDWR
      struct SubjInfo* si = lookup_or_init_si(pid);
      if ((si) && per_thread_fi(*si)) 
         pid = gettid();
#endif
      ObjId oid =  lookup_fdtooi(fd, pid);
      if (oid)
         rv = oid;
   }
   return rv;
}

#else
#define proc(x) x
#endif

#ifdef FILTER_SC_FLOOD
struct sc_flood_alert {
   u8 action;
   u16 sc;
   u64 so;
   u64 ts_ns;
   u64 count;
   u64 cpu_ns;
   u64 wall_ns;
   u64 sentinel_count; // syscalls from the high-suspicion set (kill, mprotect, etc.)
};

struct proc_window {
   u64 count;        // surviving syscalls in current window
   u64 cpu_ns;       // on-CPU ns accumulated in current window
   u64 win_start;    // window start timestamp (ns)
   u64 total_count;  // monotonic syscall count for userspace delta windows
   u64 total_cpu_ns; // monotonic CPU ns for userspace delta windows
   u64 last_count;         // completed kernel-window syscall count
   u64 last_cpu_ns;        // completed kernel-window CPU ns
   u64 last_win_start;     // completed kernel-window start timestamp
   u64 last_win_end;       // completed kernel-window end timestamp
   u64 last_sentinel_count;// completed kernel-window sentinel syscall count
   u64 sentinel_count;     // count of high-suspicion syscalls (kill, mprotect, etc.) this window
   u8 alerted;       // 1 if an alert is already pending for this window
   u8 pad[7];
};

struct on_cpu_entry {
   u64 ts_ns;
   u32 tgid;
};

enum flood_dbg_idx {
   FDBG_ROOT_BYPASS = 0,
   FDBG_PROC_INIT,
   FDBG_OC_MISSING,
   FDBG_ZERO_CPU_WINDOW,
   FDBG_WINDOW_ROLL,
   FDBG_ALERT_EMIT,
   FDBG_SYSCALL_SEEN,
   FDBG_SWITCH_CPU_ADD,
   FDBG_MIN_GUARD_SKIP,
};

BPF_TABLE("lru_hash", u32, struct proc_window, proc_state, MAX_TASKS);
BPF_HASH(on_cpu_since, u32, struct on_cpu_entry, MAX_TASKS);
BPF_ARRAY(flood_dbg, u64, 9);

BPF_TABLE("hash", u32, struct sc_flood_alert, sc_flood_alerts, MAX_TASKS);

TRACEPOINT_PROBE(sched, sched_switch) {
   u64 now = bpf_ktime_get_ns();
   u32 prev_tid = args->prev_pid;
   u32 next_tid = args->next_pid;

   struct on_cpu_entry *t0 = on_cpu_since.lookup(&prev_tid);
   if (t0 && t0->tgid) {
      u64 delta = now - t0->ts_ns;
      struct proc_window *w = proc_state.lookup(&t0->tgid);
      if (w) {
         __sync_fetch_and_add(&w->cpu_ns, delta);
         __sync_fetch_and_add(&w->total_cpu_ns, delta);
         flood_dbg.atomic_increment(FDBG_SWITCH_CPU_ADD);
      }
   }

   struct on_cpu_entry e = {};
   e.ts_ns = now;
   e.tgid = 0; // Patched by the next syscall from this tid.
   on_cpu_since.update(&next_tid, &e);
   return 0;
}

// Syscalls that are rarely called at high rates in benign workloads but are
// the primary tools in adversarial floods (signal storms, mprotect/mmap ROP
// setup, privilege-escalation probing).  A separate, lower density threshold
// is applied to this set so moderate-rate sentinel floods are caught even when
// total syscall density stays below FLOOD_THETA.
static inline int
is_sentinel_sc(u16 sc) {
   switch (sc) {
   // case 9:   /* mmap      */
   case 10:  /* mprotect  */
   case 56:  /* clone     */
   case 57:  /* fork      */
   case 58:  /* vfork     */
   // case 59:  /* execve    */
   case 62:  /* kill      */
   case 90:  /* chmod     */
   case 91:  /* fchmod    */
   case 105: /* setuid    */
   case 106: /* setgid    */
   case 200: /* tkill     */
   case 234: /* tgkill    */
   // case 268: /* fchmodat  */
   // case 322: /* execveat  */
   case 435: /* clone3    */
      return 1;
   default:
      return 0;
   }
}

static inline int
suppress_flood_sc(u16 sc, u32 pid, int fd, u64 ts_ns)
{
   (void)fd;

   // Do not suppress activity from the root user.
   if ((bpf_get_current_uid_gid() & 0xffffffff) == 0) {
      flood_dbg.atomic_increment(FDBG_ROOT_BYPASS);
      return 0;
   }
   flood_dbg.atomic_increment(FDBG_SYSCALL_SEEN);

   struct proc_window *w = proc_state.lookup(&pid);
   if (!w) {
      struct proc_window fresh = {};
      fresh.win_start = ts_ns;
      proc_state.update(&pid, &fresh);
      flood_dbg.atomic_increment(FDBG_PROC_INIT);
      w = proc_state.lookup(&pid);
      if (!w)
         return 0;
   }

   // Patch tgid into on_cpu_since so sched_switch can attribute cpu time to
   // the correct process group.  Do NOT accumulate cpu_ns here: sched_switch
   // already does that accurately.  Adding inter-syscall wall-clock deltas
   // would inflate cpu_ns for I/O-bound processes (blocked time != CPU time),
   // making benign multi-threaded workloads appear to have lower  than they
   // actually do and corrupting the density signal.
   u32 tid = (u32)gettid();
   struct on_cpu_entry *oc = on_cpu_since.lookup(&tid);
   if (oc) {
      if (oc->tgid == 0)
         oc->tgid = pid;
   }
   else flood_dbg.atomic_increment(FDBG_OC_MISSING);

   if (is_sentinel_sc(sc))
      __sync_fetch_and_add(&w->sentinel_count, 1);

   // Fast sentinel trigger: do not wait for the full 100ms window when a task is
   // already burning CPU on attack-typical syscalls.  All timing/count inputs
   // come from kernel state (bpf_ktime_get_ns and proc_state).
   if (!w->alerted &&
       w->cpu_ns >= FLOOD_MIN_SENTINEL_CPU_NS &&
       w->sentinel_count >= FLOOD_MIN_SENTINEL_COUNT) {
      u64 elapsed_ns = ts_ns - w->win_start;
      if (elapsed_ns >= FLOOD_SENTINEL_FAST_MIN_NS) {
         u64 s_lhs = w->sentinel_count * 1000000000ULL;
         u64 s_rhs = (u64)FLOOD_THETA_SENTINEL * w->cpu_ns;
         if (s_lhs > s_rhs) {
            struct sc_flood_alert alert = {};
            alert.action = 1;
            alert.sc = 0;
            alert.so = 0;
            alert.ts_ns = ts_ns;
            alert.count = w->count;
            alert.cpu_ns = w->cpu_ns;
            alert.wall_ns = elapsed_ns;
            alert.sentinel_count = w->sentinel_count;
            sc_flood_alerts.update(&pid, &alert);
            w->alerted = 1;
            flood_dbg.atomic_increment(FDBG_ALERT_EMIT);
         }
      }
   }

   if (ts_ns - w->win_start > FLOOD_W_NS) {
      u64 completed_count = w->count;
      u64 completed_cpu_ns = w->cpu_ns;
      u64 completed_sentinel_count = w->sentinel_count;
      u64 completed_win_start = w->win_start;
      u64 completed_wall_ns = ts_ns - completed_win_start;
      flood_dbg.atomic_increment(FDBG_WINDOW_ROLL);
      if (w->cpu_ns > 0) {
         if (w->cpu_ns >= FLOOD_MIN_CPU_NS && w->count >= FLOOD_MIN_COUNT) {
            // count * 1e9 would overflow only above ~18B syscalls/window.
            u64 lhs = w->count * 1000000000ULL;
            u64 rhs = (u64)FLOOD_THETA * w->cpu_ns;
            if (lhs > rhs) {
               if (!w->alerted) {
                  struct sc_flood_alert alert = {};
                  alert.action = 1;
                  alert.sc = 0;
                  alert.so = 0;
                  alert.ts_ns = ts_ns;
                  alert.count = w->count;
                  alert.cpu_ns = w->cpu_ns;
                  alert.wall_ns = completed_wall_ns;
                  alert.sentinel_count = completed_sentinel_count;
                  sc_flood_alerts.update(&pid, &alert);
                  w->alerted = 1;
                  flood_dbg.atomic_increment(FDBG_ALERT_EMIT);
               }
            }
            else {
               u64 rel_rhs = (u64)FLOOD_THETA_REL * w->cpu_ns;
               if (lhs <= rel_rhs)
                  w->alerted = 0;
            }
         }
         else flood_dbg.atomic_increment(FDBG_MIN_GUARD_SKIP);

         // Sentinel density check: independent lower threshold applied only to
         // attack-typical syscalls (kill, mprotect, etc.).  Fires even when
         // total density < FLOOD_THETA, catching moderate-rate sentinel floods
         // that benign programs cannot produce at high cpu_util.
         if (!w->alerted &&
             w->cpu_ns >= FLOOD_MIN_SENTINEL_CPU_NS &&
             w->sentinel_count >= FLOOD_MIN_SENTINEL_COUNT) {
            u64 s_lhs = w->sentinel_count * 1000000000ULL;
            u64 s_rhs = (u64)FLOOD_THETA_SENTINEL * w->cpu_ns;
            if (s_lhs > s_rhs) {
               struct sc_flood_alert alert = {};
               alert.action = 1;
               alert.sc = 0;
               alert.so = 0;
               alert.ts_ns = ts_ns;
               alert.count = w->count;
               alert.cpu_ns = w->cpu_ns;
               alert.wall_ns = completed_wall_ns;
               alert.sentinel_count = completed_sentinel_count;
               sc_flood_alerts.update(&pid, &alert);
               w->alerted = 1;
               flood_dbg.atomic_increment(FDBG_ALERT_EMIT);
            }
         }
      }
      else flood_dbg.atomic_increment(FDBG_ZERO_CPU_WINDOW);
      w->last_count = completed_count;
      w->last_cpu_ns = completed_cpu_ns;
      w->last_win_start = completed_win_start;
      w->last_win_end = ts_ns;
      w->last_sentinel_count = completed_sentinel_count;
      w->count = 0;
      w->cpu_ns = 0;
      w->sentinel_count = 0;
      w->win_start = ts_ns;
   }

   __sync_fetch_and_add(&w->count, 1);
   __sync_fetch_and_add(&w->total_count, 1);

   return 0;
}
static inline int
flood_sc_suppressed(u16 sc, int fd)
{
   return suppress_flood_sc(sc, getpid(), fd, bpf_ktime_get_ns());
}
#else
static inline int
flood_sc_suppressed(u16 sc, int fd)
{
   (void)sc;
   (void)fd;
   return 0;
}
#endif
/*****************************************************************************
 * END OF DATA REDUCTION RELATED FUNCTIONS.
 *****************************************************************************
 * From here on, we define functions that are directly used by syscall handlers.
 * Basically, logic that will be used in multiple syscall handlers is factored
 * into functions with a similar name, such as store_open_args, log_open_exit,
 * pipe_enter, pipe_exit, etc. These functions, in turn, use another level of
 * helpers related to data reduction, e.g., init_file_fi and init_pipe_fi.
 ****************************************************************************/

static inline int
init_file_fi(int fd, ObjId* data, int dlen, int pid, int has_unread) {
   // dlen should be 8 if we don't want file modification time. If dlen == 12
   // then file modification time (32-bits, seconds) is included.
   int rv = 0;
   u64 oid;
   int *mtime=NULL;
#ifdef USE_MTIME
   if (dlen == 12)
      mtime = &data[2];
#endif

#if defined(ID_NOT_FD) || defined(FILTER_REP_RDWR)
   oid = fdtoid(fd, NULL);
   *(u64*)data = oid;
   rv = init_fi(fd, oid, pid, has_unread, false);
#endif
   return rv;
}

static inline void
init_pipe_fi(int fd1, int fd2, ObjId* data, int pid) {
#if defined(ID_NOT_FD) || defined(FILTER_REP_RDWR)
   u64 oid = fdtoid(fd1, NULL);
   *data = oid;
   init_fi(fd1, oid, pid, 0, false);
   init_fi(fd2, oid, pid, 0, false);
#endif
}

static inline void
store_open_args(u16 sc, const char* fn, int at_fd, int flags, int mode) {
   int wt = (flags & (O_APPEND | O_WRONLY | O_RDWR))? WT_OPENWR : WT_OPENRD;
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= wt) {
      if (flood_sc_suppressed(sc, at_fd))
         return;
      arg3_record((long)fn, at_fd, ((u64)mode << 32) | flags, gettid());
   }
}

// @@@@ We get too many arg lookup fails for openat (~10%) --- most noticeable
// @@@@ on a short run with firefox on nytimes or washington post. This error is
// @@@@ not seen on longer runs, presumably because the number of opens falls
// @@@@ below 0.2% of syscalls (the threshold for flagging this err) by then.
// @@@@ (Interestingly, firefox causes these errors but chrome doesn't.)
static inline void
log_open_exit(void *ctx, int sc, long ret, int sign_bytes) {
   char *fn;
   long at_fd;
   long md_flags;
   int useful=1;
   int pid = getpid();

   ObjId data=0;
   if (arg3_retrieve_and_delete(ctx, (long*)&fn, &at_fd, &md_flags, gettid(), sc)) {
      if (flood_sc_suppressed(sc, at_fd))
         return;
      if (!is_err(ret)) {
         int may_read = !(md_flags & O_WRONLY);   // We MUST test this way since
         int has_no_data = (md_flags & O_EXCL) || // O_RDONLY = 0.
            ((md_flags & (O_WRONLY|O_RDWR)) && (md_flags & O_TRUNC));
         useful = !init_file_fi(ret, &data, 8, pid, 
                                may_read && !has_no_data);
      }
#ifndef REPORT_OPEN_ERRS
      else return;
#endif

      if (!useful) {
#if (PRINTK_LOG_LEVEL > 4)
         bpf_trace_printk(" open reused: pid=%d, file=%s", pid, fn);
#endif
         return;
      }

      int wt = (md_flags & (O_APPEND|O_WRONLY|O_RDWR))? WT_OPENWR : WT_OPENRD;
      log_sc_str_long5(ctx, sc, OPEN_EX, wt, OPEN_EX_SB, fn, md_flags, at_fd, 
                        ret, proc(at_fd), 
#ifdef ID_NOT_FD
                       data);
#else
      ret);
#endif
   }
}

/****************************************************************************** 
 ******************************************************************************
 * pipe and socketpair take an array[2] as argument and fill them with fds.   *
 * We need to store the address of this array at the entry in a map. This map *
 * needs to be global because the return can go to a different CPU. On the    *
 * exit event, we need to read at this cached address and retrieve the fds.   *
 * We wrap this extra functionality into two helper functions pipe_enter and  *
 * that are used for pipe, pipe2 and socketpair.                              *
 *****************************************************************************/
static inline void
pipe_enter(u16 sc, int* fds) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_PIPE) {
      if (flood_sc_suppressed(sc, 0))
         return;
      arg_record((u64)fds, gettid());
   }
}

static inline void
pipe_exit(void *ctx, int sc, char scnm, int sign_bytes, long ret) {
   ObjId oid=0;
   int err = is_err(ret);
   int* fdaddr;
   int tid, pid;
   gettidpid(&tid, &pid);

   if (arg_retrieve_and_delete(ctx, (u64*)&fdaddr, tid, sc)) {
      if (flood_sc_suppressed(sc, 0))
         return;
//       long fds;
//       if (!err) {
//          if (bpf_probe_read(&fds, 8, fdaddr)) {
//             err = 1;
//             pipe_read_data_err();
//          }
//          else ret = fds;
//       }

//       if (!err) 
//          init_pipe_fi(ret&0xffffffff, (int)(ret>>32), &oid, pid);
// #ifdef IGNORE_FAILED_CALLS
//       if (err)
//          return;
// #endif

      log_sc_long1(ctx, sc, scnm, WT_PIPE, sign_bytes, ret); 
      // @@@@ Broken when IDs rather than FDs are used. But this is moot
      // since we disable logging of pipe syscall in ID mode.
   }
}

/****************************************************************************** 
 ******************************************************************************
 * Now we are onto the main task: writing the handlers for each system call   *
 * entry and exit. @@@@ TODO: investigate:                                    *
 *                                                                            *
 *   (a) additional tracepoints and/or LSM hooks that can be helpful to track *
 *                                                                            *
 *   (b) or, these points may be more convenient because they operate on data *
 *       that is already in kernel space, and is hence less prone to errors   *
 *       such as pagefaults, or race conditions.                              *
 *                                                                            *
 * We start with functions for opening a file. We record a open as an openat, *
 * adding AT_FDCWD as an extra argument                                       *
 *****************************************************************************/
#ifdef LOG_OPEN
TRACEPOINT_PROBE(syscalls, sys_enter_open) {
   store_open_args(args->__syscall_nr, args->filename, AT_FDCWD, args->flags, args->mode);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_open) {
   log_open_exit(args, args->__syscall_nr, args->ret, OPEN_EX_SB);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
   store_open_args(args->__syscall_nr, args->filename, (int)args->dfd, args->flags, args->mode);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
   log_open_exit(args, args->__syscall_nr, args->ret, OPEN_EX_SB);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_creat) {
   store_open_args(args->__syscall_nr, args->pathname,AT_FDCWD,O_CREAT|O_WRONLY|O_TRUNC,args->mode);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_creat) {
   log_open_exit(args, args->__syscall_nr, args->ret, OPEN_EX_SB);
   return 0;
}

///////////////////////////////////////////////////////////////////////////
// Truncate is rare enough that we omit repeated read/write optimizations. 
// We also omit oids because our current oid computation requires fds.
TRACEPOINT_PROBE(syscalls, sys_enter_truncate) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_TRUNC) 
      arg3_record((long)args->path, (long)args->length, 0, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_truncate) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_TRUNC) {
      char* path;
      long length;
      long l3;
      if (arg3_retrieve_and_delete(args, (long*)(&path), &length, &l3, gettid(), 
                                   args->__syscall_nr)) {
         
#ifdef IGNORE_FAILED_CALLS
      if (is_err(args->ret))
         return 0;
#endif
         log_sc_str_long2(args, args->__syscall_nr, TRUNC_EX, WT_TRUNC,
                          TRUNC_EX_SB, path, length, args->ret);

      }
         
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_ftruncate) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_TRUNC)
      arg3_record(args->__syscall_nr, args->fd, args->length, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_ftruncate) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   long fd;
   long length, _ign;
   if (ll && ll->log_wt <= WT_TRUNC
          && arg3_retrieve_and_delete(args, &_ign, &fd, &length, gettid(), 
                                      args->__syscall_nr)) {
#ifdef IGNORE_FAILED_CALLS
      if (is_err(args->ret))
         return 0;
#endif
      log_sc_long3(args, args->__syscall_nr, FTRUNC_EX, WT_TRUNC, FTRUNC_EX_SB,
                   proc(fd), length, (fd << 1) | (args->ret & 0x1));

   }
     
   return 0;
}
#endif

TRACEPOINT_PROBE(syscalls, sys_enter_close) {
   long unreported_read=0, unreported_write=0;
#if defined(ID_NOT_FD) || defined(FILTER_REP_RDWR)
   cleanup_fi(args->fd, getpid(), &unreported_read, &unreported_write);
#endif

// @@@@ If unreported read, (and/or write) submit a read (and/or write) event

#ifdef LOG_CLOSE
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CLOSE) 
      log_sc_long3(args, args->__syscall_nr, CLOSE_EN, WT_CLOSE, CLOSE_EN_SB,
                   (int)args->fd, unreported_read, unreported_write);
#endif
   return 0;
}

// Nothing is lost by leaving out this.
/*
#ifdef LOG_CLOSE  
#ifdef LOG_CLOSE_EXIT
TRACEPOINT_PROBE(syscalls, sys_exit_close) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CLOSE_EX)
      log_sc_exit(args->__syscall_nr, CLOSE_EX, args->ret);
   return 0;
}
#endif
#endif
*/

/****************************************************************************** 
 ******************************************************************************
 * Now we are onto a bunch of functions that change the meaning of file       *
 * descriptors, such as dup. Also included in this group is fcntl, which can  *
 * be used in place of dup. Because fcntl can be very frequent, we only track *
 * fcntl calls with the DUP operation code. The rest are ignored.             *
 *****************************************************************************/
#ifdef LOG_DUP
static inline void
dup_entry(int fd) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_DUP) {
      if (flood_sc_suppressed(0, fd))
         return;
      arg_record(fd, gettid());
   }
}

static inline void
dup_exit(void *ctx, int sc, char scnm, int scwt, int sign_bytes,
          u64 ret, int errsc) {
   long in_fd;
   int tid, pid;
   gettidpid(&tid, &pid);
   if (arg_retrieve_and_delete(ctx, (u64*)&in_fd, tid, errsc)) {
      int newfd = ret;
#ifdef IGNORE_FAILED_CALLS
      if (is_err(ret))
         return;
#endif
      if (flood_sc_suppressed(sc, in_fd))
         return;
      log_sc_long2(ctx, sc, scnm, scwt, sign_bytes, in_fd, newfd);

#ifdef FILTER_REP_RDWR
      if (!is_err(newfd)) {
         if (scnm == DUP_EX)
            copy_fi(in_fd, newfd, pid);
         else move_fi(in_fd, newfd, pid);
      }
#endif
   }
}

TRACEPOINT_PROBE(syscalls, sys_enter_dup) {
   dup_entry(args->__syscall_nr, args->fildes);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_dup) {
   dup_exit(args, args->__syscall_nr, DUP_EX, WT_DUP, DUP_EX_SB,
             args->ret, args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_dup2) {
   dup_entry(args->__syscall_nr, args->oldfd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_dup2) {
   dup_exit(args, args->__syscall_nr, DUP2_EX, WT_DUP, DUP2_EX_SB,
             args->ret, args->__syscall_nr);
   return 0;
}

// We will record dup2 and dup3 as dup2, ignoring the flag argument of dup3.
TRACEPOINT_PROBE(syscalls, sys_enter_dup3) {
   dup_entry(args->__syscall_nr, args->oldfd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_dup3) {
   dup_exit(args, args->__syscall_nr, DUP2_EX, WT_DUP, DUP2_EX_SB,
             args->ret, args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fcntl) { // Log only if it is DUP operation
   u64 cmd = args->cmd;
   if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC)
      dup_entry(args->__syscall_nr, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fcntl) {
   dup_exit(args, args->__syscall_nr, DUP_EX, WT_DUP, DUP_EX_SB, 
            args->ret, 600);
   return 0;
}
#endif

#ifdef LOG_PIPE
TRACEPOINT_PROBE(syscalls, sys_enter_pipe) {
   pipe_enter(args->__syscall_nr, args->fildes);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pipe) {
   pipe_exit(args, args->__syscall_nr, PIPE_EX, PIPE_EX_SB, args->ret);
   return 0;
}

//@@@@ Protocol info is not being sent. fix.
TRACEPOINT_PROBE(syscalls, sys_enter_socketpair) {
   pipe_enter(args->__syscall_nr, args->usockvec);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_socketpair) {
   pipe_exit(args, args->__syscall_nr, SOCKPAIR_EX, SOCKPAIR_EX_SB, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pipe2) {
   pipe_enter(args->__syscall_nr, args->fildes);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pipe2) {
   pipe_exit(args, args->__syscall_nr, PIPE_EX, PIPE_EX_SB, args->ret);
   return 0;
}

/* Disable: no good reason to support, plus it is not tested through
TRACEPOINT_PROBE(syscalls, sys_enter_socket) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SOCKET)
      log_sc_long3(args->__syscall_nr, SOCKET_EN, WT_SOCKET, args->family, 
        args->type, args->protocol);
   return 0;
}
*/
#endif

/****************************************************************************** 
 ******************************************************************************
 * Next are several network-related opertions. Many of them need to obtain    *
 * the socket address of the peer. As before, we use a hash map to record the *
 * address of the sockaddr structure, and then read from this location at the *
 * system call exit. A helper function store_saddr is used at the entry, and  *
 * log_sc_with_saddr at the exit. These helpers are reused across several     *
 * network-related system calls such as recvfrom, accept, getpeername, etc.   *
 *****************************************************************************/
static inline void
store_saddr_arg(u16 sc, int scwt, struct sockaddr* saddr, int* slen, long fd) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  if (ll && ll->log_wt <= scwt) {
     if (flood_sc_suppressed(sc, fd))
        return;
     arg3_record((long)saddr, (long)slen, fd, gettid());
  }
}

static inline void
log_sc_exit_with_saddr(void *ctx, int sc, char scnm, int scwt, int sign_bytes,
                       long ret, int flag, int errsc) {
   // flag=1 means accept, flag=0 means getpeername or recvfrom
   ObjId oid=0;
   void* saddr;
   long alen;
   long fd;
   int slen=0;
   int useful=1;
   int tid = gettid();
   if (arg3_retrieve_and_delete(ctx, (long*)&saddr, (long*)&alen, &fd, tid, errsc)) {
      if (flood_sc_suppressed(sc, fd))
         return;
      // For syscalls that reach here, it is OK if we don't log error returns
      if (!is_err(ret)) {
         if (flag) {
#if defined(ID_NOT_FD) || defined(FILTER_REP_RDWR)
            oid = fdtoid(ret, 0);
            useful = !init_fi(ret, oid, getpid(), 1, false);
#if (PRINTK_LOG_LEVEL > 4)
            if (!useful)
               bpf_trace_printk("accept reused: pid=%d, oid=%lx", getpid(), oid);
#endif
#endif
         }
         if (useful) {
            if (saddr && alen) {
               if (bpf_probe_read((void*)&slen, 4, (void*)alen)) {
                  saddr_read_data_err();
                  slen = 0;
               }
            }

            if (log_sc_data_long3(ctx, sc, scnm, scwt, sign_bytes, saddr, slen, fd, ret,
#ifdef ID_NOT_FD
                                    oid))
#else
                                    fd))
#endif
               saddr_data_err();
         }
      }
#ifdef REPORT_OPEN_ERRS
      else {
         slen = 0;
         log_sc_data_long3(ctx, sc, scnm, scwt, saddr, slen, fd, ret, 0);
      }
#endif
   }
}

#ifdef LOG_NET_OPEN
TRACEPOINT_PROBE(syscalls, sys_enter_accept) {
   store_saddr_arg(args->__syscall_nr, WT_ACCEPT, args->upeer_sockaddr,
                   args->upeer_addrlen, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept) {
   int sc = args->__syscall_nr;
   log_sc_exit_with_saddr(args, sc, ACCEPT_EX, WT_ACCEPT, ACCEPT_EX_SB,
                          args->ret, 1, sc);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept4) {
   store_saddr_arg(args->__syscall_nr, WT_ACCEPT, args->upeer_sockaddr,
                   args->upeer_addrlen, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept4) {
   int sc = args->__syscall_nr;
   log_sc_exit_with_saddr(args, sc, ACCEPT_EX, WT_ACCEPT, ACCEPT_EX_SB,
                          args->ret, 1, sc);
   return 0;
}

// We don't log socket, but do cleanup the returned fd.
TRACEPOINT_PROBE(syscalls, sys_exit_socket) {
#if defined(ID_NOT_FD) || defined(FILTER_REP_RDWR)
   cleanup_fi(args->ret, getpid(), 0, 0);
#endif
   return 0;
}

/****************************************************************************** 
 ******************************************************************************
 * Connect, bind and sendto are similar to the above functions with one       *
 * difference: aockaddr is already known, and is not returned by the syscall. *
 *****************************************************************************/

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
   int fd = (int)args->fd;
   if (flood_sc_suppressed(args->__syscall_nr, fd))
      return 0;
   arg3_record((long)args->uservaddr, (long)args->addrlen, fd, gettid());
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_connect) {
   void* saddr;
   long addrlen;
   long fd;
   int useful=1;
   if (arg3_retrieve_and_delete(args, (long*)&saddr, &addrlen, &fd, gettid(), 
                                args->__syscall_nr)) {
      if (flood_sc_suppressed(args->__syscall_nr, fd))
         return 0;
      ObjId id=fd; 
      if (!is_err(args->ret)) {
#if defined(ID_NOT_FD) || defined(FILTER_REP_RDWR)
         id = fdtoid(fd, 0);
         useful = !init_fi(fd, id, getpid(), 1, false);
#if (PRINTK_LOG_LEVEL >= 4)
         if (!useful)
            bpf_trace_printk("connect reused: pid=%d, fd=%d, oid=%lx", 
                             getpid(), fd, id);
         else bpf_trace_printk("connect new: pid=%d, fd=%d, oid=%lx", 
                               getpid(), fd, id);
#endif      
#endif
      }
      if (useful
#ifndef REPORT_OPEN_ERRS
          && !is_err(args->ret)
#endif
                                 ) {
         if (log_sc_data_long3(args, args->__syscall_nr, CONNECT_EX, WT_CONNECT,
                                 CONNECT_EX_SB,saddr, (int)addrlen, fd, id, 
                                 args->ret))
            conn_data_err();
      }
   }
   return 0;
}

#ifndef LOG_REP_RDWR
TRACEPOINT_PROBE(syscalls, sys_enter_getpeername) {
   store_saddr_arg(args->__syscall_nr, WT_GETPEER, args->usockaddr,
                   args->usockaddr_len, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_getpeername) {
   int sc = args->__syscall_nr;
   log_sc_exit_with_saddr(args, sc, GETPEER_EX, WT_GETPEER, GETPEER_EX_SB,
                          args->ret, 0, sc);
   return 0;
}
#endif

TRACEPOINT_PROBE(syscalls, sys_enter_bind) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_BIND) {
      if (flood_sc_suppressed(args->__syscall_nr, args->fd))
         return 0;
      arg3_record((long)args->umyaddr, args->addrlen, args->fd, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_bind) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   long umyaddr, addrlen, fd;
   if (ll && ll->log_wt <= WT_BIND)
      if (arg3_retrieve_and_delete(args, &umyaddr, &addrlen, &fd, gettid(), 
                                   args->__syscall_nr)) {
         if (flood_sc_suppressed(args->__syscall_nr, fd))
            return 0;
#ifdef IGNORE_FAILED_CALLS
         if (!is_err(args->ret)
             && log_sc_data_long2(args, args->__syscall_nr, BIND_EX, WT_BIND,
                                  BIND_EX_SB, (void*)umyaddr, addrlen, fd,
                                  args->ret))
#else
         if (log_sc_data_long2(args, args->__syscall_nr, BIND_EX, WT_BIND,
                               BIND_EX_SB, (void*)umyaddr, addrlen, fd,
                               args->ret))
#endif
                                // fd is not connected to anything so proc(fd)
         bind_data_err();      // is likely useless. Might as well send just fd. 
                                   }
   return 0;
}
#endif

/****************************************************************************** 
 ******************************************************************************
 * Next are several system calls that are read-like. They are quite simple to *
 * handle, but do need the extra checks/calls for supporting repeated read    *
 * suppression optimization.                                                  *
 *****************************************************************************/
#ifdef LOG_READ
// We only record the fd and return value for all flavors of read. Other
// arguments, such as the write offset, are being ignored.

static inline void
read_entry(int fd) {
   int tid = gettid();
   if (getpid() == EAUDIT_PID) return;
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READ)
         arg_record(fd, tid);
}

static inline void
read_entry1(u16 sc, void *addr, void* addr_len, int fd) {
   int tid = gettid();
   if (getpid() == EAUDIT_PID) return;
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READ) {
      if (!addr || !addr_len)
         arg_record(fd, tid);
      else store_saddr_arg(sc, WT_RECVFROM, addr, addr_len, fd);
   }
}

static inline void
log_read(void *ctx, int sc, int scnm, int sign_bytes, int fd, long ret) {
   if (is_err(ret)) {
#ifdef REPORT_RDWR_ERRS
#ifdef IGNORE_FAILED_CALLS
      return;
#endif
      log_sc_long2(ctx, sc, scnm, WT_READ, sign_bytes, fd, proc(fd), ret);
#endif
   }
   else {
#ifdef FILTER_REP_RDWR
      u64 ts = bpf_ktime_get_ns();
      ret = useful_rdwr(fd, ret, 1, ts, getpid());
      if (ret-- > 0)
#endif
         log_sc_long3(ctx, sc, scnm, WT_READ, sign_bytes, fd, proc(fd), ret);
   }
}

static inline int
read_exit(void *ctx, int sc, int scnm, int sign_bytes, long ret, int errsc) {
   long fd; 
   int tid = gettid();
   int success = arg_retrieve_and_delete(ctx, (u64*)&fd, tid, errsc);
   
   if (success) {
      log_read(ctx, sc, scnm, sign_bytes, fd, ret);

   }
      
   return success;
}

static inline void
read_exit1(void *ctx, int sc, int scnm, int scwt, int sign_bytes, long ret) {
   if (!read_exit(ctx, sc, READ_EX, READ_EX_SB, ret, 600)) // suppress errmsg if arg not found
      log_sc_exit_with_saddr(ctx, sc, scnm, scwt, sign_bytes, ret, 0, sc);
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
   read_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_readv) {
   read_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_recvmsg) {
   read_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_recvmmsg) {
   read_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pread64) {
   read_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_preadv) {
   read_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_preadv2) {
   read_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
   read_entry1(args->__syscall_nr, args->addr, args->addr_len, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READEX)
      read_exit(args, args->__syscall_nr, READ_EX, READ_EX_SB, args->ret, 
             args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_readv) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READEX)
      read_exit(args, args->__syscall_nr, READ_EX, READ_EX_SB, args->ret, 
             args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvmsg) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READEX)
      read_exit(args, args->__syscall_nr, READ_EX, READ_EX_SB, args->ret,
             args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvmmsg) {
   read_exit(args, args->__syscall_nr, READ_EX,READ_EX_SB, args->ret, args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pread64) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READEX)
      read_exit(args, args->__syscall_nr, READ_EX, READ_EX_SB, args->ret,
             args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_preadv) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READEX)
      read_exit(args, args->__syscall_nr, READ_EX, READ_EX_SB, args->ret,
             args->__syscall_nr);
   return 0; 
}

TRACEPOINT_PROBE(syscalls, sys_exit_preadv2) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READEX)
      read_exit(args, args->__syscall_nr, READ_EX, READ_EX_SB, args->ret,
             args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_READEX)
      read_exit1(args, args->__syscall_nr, RECVFROM_EX, WT_RECVFROM, READ_EX_SB,
              args->ret);
   return 0;
}

#endif

/****************************************************************************** 
 ******************************************************************************
 * Next are several system calls that are write-like, and their handling is   *
 * very similar to that of reads.                                             *
 *****************************************************************************/
#ifdef LOG_WRITE
// We only record the fd and return value for all flavors of read. Other
// arguments, such as the write offset, are being ignored.

static inline void
write_entry(int fd) {
   int tid = gettid();
   if (getpid() == EAUDIT_PID) return;
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_WRITE)
      arg_record(fd, tid);
}

static inline void
write_entry1(void* addr, int len, int fd) {
   int tid = gettid();
   if (getpid() == EAUDIT_PID) return;
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_WRITE) {
      if (!addr || !len) 
         arg_record(fd, tid);
      else arg3_record((long)addr, len, fd, tid);
   }
}

static inline void
log_write(void *ctx, int sc, int scnm, int sign_bytes, int fd, long ret) {
   if (is_err(ret)) {
#ifdef REPORT_RDWR_ERRS
#ifdef IGNORE_FAILED_CALLS
      return;
#endif
      log_sc_long3(ctx, sc, scnm, WT_WRITE, sign_bytes, fd, proc(fd), ret);
#endif
   }
   else {
#ifdef FILTER_REP_RDWR
      u64 ts = bpf_ktime_get_ns();
      ret = useful_rdwr(fd, ret, 0, ts, getpid());
      if (ret-- > 0) 
#endif
         log_sc_long3(ctx, sc, scnm, WT_WRITE, sign_bytes, fd, proc(fd), ret);
   }
}

static inline int
write_exit(void *ctx, int sc, int scnm, int sign_bytes, long ret, int errsc) {
   long fd; 
   int tid = gettid();
   int success = arg_retrieve_and_delete(ctx, (u64*)&fd, tid, errsc);
   if (success)
      log_write(ctx, sc, scnm, sign_bytes, fd, ret);
   return success;
}

static inline void
write_exit1(void *ctx, int sc, int scnm, int scwt, int sign_bytes, long ret) {
   if (!write_exit(ctx, sc, WRITE_EX, WRITE_EX_SB, ret, 600)) { // suppress errmsg if arg unfound
      // Control reaches here on sendto when the socket is not connected. 
      // It is unclear if dependency optimization is feasible here -- normally
      // we use it for connected sockets, and the peer info is somehow used
      // in deriving id. It may not be possible to derive that here, which 
      // would mean no dependency optimization. That's why we dont call 
      // exit_with_saddr here, instead reimplementing a subset of that function
      void* saddr;
      long addrlen;
      long fd;
      int tid = gettid();
      if (arg3_retrieve_and_delete(ctx, (long*)&saddr, &addrlen, &fd, tid, sc)
#ifndef REPORT_RDWR_ERRS
          && !is_err(ret)
#endif
                          ) {
         if (flood_sc_suppressed(sc, fd))
            return;
         if (addrlen < 0) addrlen=0;
         if (log_sc_data_long2(ctx, sc, scnm, scwt, sign_bytes,
                               saddr, addrlen, fd, ret))
                   // fd is unconnected, similar to bind; so send fd, not id.
            sendto_data_err();
      }
   }
}

static inline void sendfile64_entry(int in_fd, int out_fd) {
  int tid = gettid();
  if (getpid() == EAUDIT_PID)
    return;
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  if (ll && ll->log_wt <= WT_SENDFILE64) {
    long all_fd = (((long)in_fd) << 32) + out_fd;
    arg_record(all_fd, tid);
  }
}

static inline int sendfile64_exit(void *ctx, int sc, int scnm, int sign_bytes,
                                  long ret) {
   u64 all_fd;
   int success = arg_retrieve_and_delete(ctx, &all_fd, gettid(), sc);
   if (success) {
      int in_fd = all_fd >> 32;
      int out_fd = all_fd & ((1l << 32) - 1);
      log_read(ctx, sc, READ_EX, READ_EX_SB, in_fd, ret);
      log_write(ctx, sc, WRITE_EX, WRITE_EX_SB, out_fd, ret);
   }
   return success;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendfile64) {
  sendfile64_entry(args->in_fd, args->out_fd);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendfile64) {
  sendfile64_exit(args, args->__syscall_nr, READ_EX, READ_EX_SB, args->ret);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_copy_file_range) {
  sendfile64_entry(args->fd_in, args->fd_out);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_copy_file_range) {
  sendfile64_exit(args, args->__syscall_nr, READ_EX, READ_EX_SB, args->ret);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
   write_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_writev) {
   write_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendmsg) {
   write_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendmmsg) {
   write_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pwrite64) {
   write_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pwritev) {
   write_entry(args->fd);
   return 0; // offset is not an important argument.
}

TRACEPOINT_PROBE(syscalls, sys_enter_pwritev2) {
   write_entry(args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
   write_entry1(args->addr, args->addr_len, args->fd);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_write) {
   write_exit(args, args->__syscall_nr, WRITE_EX, WRITE_EX_SB, args->ret,
              args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_writev) {
   write_exit(args, args->__syscall_nr, WRITE_EX, WRITE_EX_SB, args->ret,
              args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendmsg) {
   write_exit(args, args->__syscall_nr, WRITE_EX, WRITE_EX_SB, args->ret,
              args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendmmsg) {
   write_exit(args, args->__syscall_nr, WRITE_EX, WRITE_EX_SB, args->ret,
              args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pwrite64) {
   write_exit(args, args->__syscall_nr, WRITE_EX, WRITE_EX_SB, args->ret,
              args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_pwritev) {
   write_exit(args, args->__syscall_nr, WRITE_EX, WRITE_EX_SB, args->ret,
              args->__syscall_nr);
   return 0; 
}

TRACEPOINT_PROBE(syscalls, sys_exit_pwritev2) {
   write_exit(args, args->__syscall_nr, WRITE_EX, WRITE_EX_SB, args->ret,
              args->__syscall_nr);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendto) {
   write_exit1(args, args->__syscall_nr, SENDTO_EX, WT_SENDTO, SENDTO_EX_SB,
                args->ret);
   return 0;
}
#endif

/****************************************************************************** 
 ******************************************************************************
 * Now, onto mmap and mprotect. Only file-backed mmaps are needed to capture  *
 * provenance, so we omit other types of mmaps, UNLESS they set execute perm. *
 * In this case, we record it even if it is not file-backed, since it may be  *
 * used to load or inject code. For mprotect, we only record them if they are *
 * being used for code loading, i.e., have exec perm set.                     *
 *****************************************************************************/
#ifdef LOG_MMAP
TRACEPOINT_PROBE(syscalls, sys_enter_mprotect) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int wt;
   if (ll && ll->log_wt <= WT_MMAP) {
      if (flood_sc_suppressed(args->__syscall_nr, 0))
         return 0;
      // Normally, log only if security-relevant: execute permission
      int mmap_imp = (args->prot & PROT_EXEC);

      if (!mmap_imp
#ifdef LOG_MMAPALL 
          && ll->log_wt > WT_MMAPALL
#endif
      )
         return 0;

      long prot = args->prot;
      // encode protection bits the same was as file permissions
      prot = (((prot & PROT_READ) !=0) << 2) |
         (((prot & PROT_WRITE)!=0) << 1) |
         ((prot & PROT_EXEC) !=0);

      arg3_record(args->start, args->len, prot, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mprotect) {
   long start, len, prot;
   if (arg3_retrieve_and_delete(args, &start, &len, &prot, gettid(), 600)
#ifndef REPORT_MMAP_ERRS
       && !is_err(args->ret)
#endif
                            ) {
      if (flood_sc_suppressed(args->__syscall_nr, 0))
         return 0;
      log_sc_long3(args, args->__syscall_nr, MPROTECT_EX, WT_MMAP,
                    MPROTECT_EX_SB, start, len, (args->ret<<32) | prot);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MMAP) {
      if (flood_sc_suppressed(args->__syscall_nr, args->fd))
         return 0;
      int file_backed = ((args->fd >= 0) && !(args->flags & MAP_ANONYMOUS));
      int exec_perm = (args->prot & PROT_EXEC);
      int mmap_imp = file_backed || exec_perm;

      if (!mmap_imp
#ifdef LOG_MMAPALL 
          && ll->log_wt > WT_MMAPALL
#endif
      )
         return 0;


      long prot = args->prot;
      // encode protection bits the same was as file permissions
      prot = (((prot & PROT_READ) !=0) << 2) |
         (((prot & PROT_WRITE)!=0) << 1) |
         ((prot & PROT_EXEC) !=0);
      long flags = args->flags; // Note: flags has int type

      flags = (flags << 32) | prot;
      long scwt = mmap_imp? WT_MMAP : WT_MMAPALL;
      arg5_record(scwt, args->addr, args->len, flags, args->fd, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mmap) {
   int z = 0; 
   long addr, len, flags, scwt, fd;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MMAP) {
      if (!arg5_retrieve_and_delete(args, &scwt,&addr,&len,&flags,&fd, gettid(), 600)) 
         return 0;
#ifdef IGNORE_FAILED_CALLS
      if (is_err(args->ret))
         return 0;
#endif
      if (flood_sc_suppressed(args->__syscall_nr, fd))
         return 0;
      log_sc_long5(args, args->__syscall_nr, MMAP_EX, scwt, MMAP_EX_SB,
                   proc((long)fd), addr, len, flags, args->ret);
      // @@@@ We are not sending the fd, only proc(fd). Leaving it that way since
      // @@@@ the chance of mmap on unobserved open is a very rare case.
   }
   return 0;
}
#endif

/****************************************************************************** 
 ******************************************************************************
 * Next are several file-name related syscalls such as link, unlink, symlink, *
 * rename, mkdir, and so on.                                                  *
 *****************************************************************************/

#ifdef LOG_FILENAME_OP
static inline void
log_unlink(void *ctx, int sc, long pathname, long fd, long ret) {
#ifdef IGNORE_FAILED_CALLS
      if (is_err(ret))
         return;
#endif
   log_sc_str_long3(ctx, sc, UNLINK_EX, WT_UNLINK, UNLINK_EX_SB,
                   (char*)pathname, fd, proc(fd), ret);
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_UNLINK) {
      if (flood_sc_suppressed(args->__syscall_nr, AT_FDCWD))
         return 0;
      arg3_record((long)args->pathname, AT_FDCWD, 0, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_unlink) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long pathname, fd, _ign;
   if (ll && ll->log_wt <= WT_UNLINK && 
         arg3_retrieve_and_delete(args, &pathname, &fd, &_ign, gettid(), sc)) {
      if (flood_sc_suppressed(sc, fd))
         return 0;
      log_unlink(args, sc, pathname, fd, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_UNLINK) {
      if (flood_sc_suppressed(args->__syscall_nr, args->dfd))
         return 0;
      arg3_record((long)args->pathname, args->dfd, 0, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_unlinkat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long pathname, fd, _ign;
   if (ll && ll->log_wt <= WT_UNLINK && 
         arg3_retrieve_and_delete(args, &pathname, &fd, &_ign, gettid(), sc)) {
      if (flood_sc_suppressed(sc, fd))
         return 0;
      log_unlink(args, sc, pathname, fd, args->ret);
   }
   return 0;
}

static inline void
log_mkdir(void *ctx, int sc, long pathname, long fd, long mode, long ret) {
#ifdef IGNORE_FAILED_CALLS
      if (is_err(ret))
         return;
#endif   
   log_sc_str_long3(ctx, sc, MKDIR_EX, WT_MKDIR, MKDIR_EX_SB,
                    (char*)pathname, fd, proc(fd), 
                    (mode << 32)|(ret&0xffffffff));
}

TRACEPOINT_PROBE(syscalls, sys_enter_mkdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MKDIR) {
      if (flood_sc_suppressed(args->__syscall_nr, AT_FDCWD))
         return 0;
      arg3_record((long)args->pathname, AT_FDCWD, args->mode, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mkdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long pathname, fd, mode;
   if (ll && ll->log_wt <= WT_MKDIR && 
         arg3_retrieve_and_delete(args, &pathname, &fd, &mode, gettid(), sc)) {
      if (flood_sc_suppressed(sc, fd))
         return 0;
      log_mkdir(args, sc, pathname, fd, mode, args->ret);
   }
      
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mkdirat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MKDIR) {
      if (flood_sc_suppressed(args->__syscall_nr, args->dfd))
         return 0;
      arg3_record((long)args->pathname, args->dfd, args->mode, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mkdirat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long pathname, fd, mode;
   if (ll && ll->log_wt <= WT_MKDIR && 
         arg3_retrieve_and_delete(args, &pathname, &fd, &mode, gettid(), sc)) {
      if (flood_sc_suppressed(sc, fd))
         return 0;
      log_mkdir(args, sc, pathname, fd, mode, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_rmdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_RMDIR) {
      if (flood_sc_suppressed(args->__syscall_nr, AT_FDCWD))
         return 0;
      arg_record((long)args->pathname, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_rmdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   u64 pathname;
   if (ll && ll->log_wt <= WT_RMDIR && 
         arg_retrieve_and_delete(args, &pathname, gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
   if (is_err(args->ret))
      return 0;
#endif           
      if (flood_sc_suppressed(sc, AT_FDCWD))
         return 0;
      log_sc_str_long1(args, sc, RMDIR_EX, WT_RMDIR, RMDIR_EX_SB, 
                      (char*)pathname, args->ret);
   }
      
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_chdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CHDIR) {
      if (flood_sc_suppressed(args->__syscall_nr, AT_FDCWD))
         return 0;
      arg_record((long)args->filename, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_chdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   u64 filename;
   if (ll && ll->log_wt <= WT_CHDIR &&
         arg_retrieve_and_delete(args, &filename, gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
   if (is_err(args->ret))
      return 0;
#endif
   if (flood_sc_suppressed(sc, AT_FDCWD))
      return 0;
   log_sc_str_long1(args, sc, CHDIR_EX, WT_CHDIR, CHDIR_EX_SB,
                      (char*)filename, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchdir) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CHDIR) {
      if (flood_sc_suppressed(args->__syscall_nr, args->fd))
         return 0;
      arg_record(args->fd, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchdir) {
   int z = 0;
   u64 fd;
   int sc = args->__syscall_nr;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt<=WT_CHDIR && arg_retrieve_and_delete(args, &fd, 
                        gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
   if (is_err(args->ret))
      return 0;
#endif
   if (flood_sc_suppressed(sc, fd))
      return 0;
   log_sc_long3(args, sc, FCHDIR_EX, WT_CHDIR, FCHDIR_EX_SB,
                   fd, proc(fd), args->ret);
   }
      
   return 0;
}

static inline void 
log_link(void *ctx, int sc, long oldnm, long newnm, long fd1, long fd2, long fl, long ret) {
#ifdef IGNORE_FAILED_CALLS
   if (is_err(ret))
      return;
#endif   
   log_sc_str2_long5(ctx, sc, LINK_EX, WT_LINK, LINK_EX_SB,
                     (char*)oldnm, (char*)newnm, fd1, fd2,
                     (fl<<32)|(ret&0xffffffff), proc(fd1), proc(fd2));
}

TRACEPOINT_PROBE(syscalls, sys_enter_link) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_LINK) {
      if (flood_sc_suppressed(args->__syscall_nr, AT_FDCWD))
         return 0;
      arg5_record((u64)args->oldname, (u64)args->newname, AT_FDCWD, 
                  AT_FDCWD, AT_FDCWD, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_link) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long oldname, newname, fd1, fd2, flag;
   if (ll && ll->log_wt <= WT_LINK && 
       arg5_retrieve_and_delete(args, &oldname,&newname,&fd1,&fd2,&flag, gettid(), sc)) {
      if (flood_sc_suppressed(sc, fd1))
         return 0;
      log_link(args, sc, oldname, newname, fd1, fd2, flag, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_linkat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_LINK) {
      if (flood_sc_suppressed(args->__syscall_nr, args->olddfd))
         return 0;
      arg5_record((u64)args->oldname, (u64)args->newname, args->olddfd, 
                  args->newdfd, args->flags, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_linkat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long oldname, newname, fd1, fd2, flag;
   if (ll && ll->log_wt <= WT_LINK && 
       arg5_retrieve_and_delete(args, &oldname, &newname,&fd1,&fd2,&flag,gettid(), sc)) {
      if (flood_sc_suppressed(sc, fd1))
         return 0;
      log_link(args, sc, oldname, newname, fd1, fd2, flag, args->ret);
   }
   return 0;
}

static inline void
log_symlink(void *ctx, int sc, long oldname, long newname, long fd, long ret) {
#ifdef IGNORE_FAILED_CALLS
   if (is_err(ret))
      return;
#endif   
   log_sc_str2_long3(ctx, sc, SYMLINK_EX, WT_SYMLINK, SYMLINK_EX_SB,
                      (const char *)oldname, (const char *)newname, fd, proc(fd)
                        , ret);

}

TRACEPOINT_PROBE(syscalls, sys_enter_symlink) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SYMLINK) {
      if (flood_sc_suppressed(args->__syscall_nr, AT_FDCWD))
         return 0;
      arg3_record((long)args->oldname, (long)args->newname, AT_FDCWD, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_symlink) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long oldname, newname, dir_fd;
   if (ll && ll->log_wt <= WT_SYMLINK &&
         arg3_retrieve_and_delete(args, &oldname, &newname, &dir_fd, gettid(), sc)) {
      if (flood_sc_suppressed(sc, dir_fd))
         return 0;
      log_symlink(args, sc, oldname, newname, dir_fd, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_symlinkat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SYMLINK) {
      if (flood_sc_suppressed(args->__syscall_nr, args->newdfd))
         return 0;
      arg3_record((long)args->oldname, (long)args->newname,args->newdfd,gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_symlinkat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long oldname, newname, dir_fd;
   if (ll && ll->log_wt <= WT_SYMLINK &&
         arg3_retrieve_and_delete(args, &oldname, &newname, &dir_fd, gettid(), sc)) {
      if (flood_sc_suppressed(sc, dir_fd))
         return 0;
      log_symlink(args, sc, oldname, newname, dir_fd, args->ret);
   }
   return 0;
}

static inline void
log_rename(void *ctx, int sc, long oldnm, long newnm, long ofd, long nfd, long fl, long ret) {
#ifdef IGNORE_FAILED_CALLS
   if (is_err(ret))
      return;
#endif
   log_sc_str2_long5(ctx, sc, RENAME_EX, WT_RENAME, RENAME_EX_SB, (const char*)oldnm, 
                     (const char*)newnm, ofd, nfd, (fl<<32)|(ret&0xffffffff),
                     proc(ofd), proc(nfd));
}

TRACEPOINT_PROBE(syscalls, sys_enter_rename) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_RENAME) {
      if (flood_sc_suppressed(args->__syscall_nr, AT_FDCWD))
         return 0;
      arg5_record((long)args->oldname, (long)args->newname, AT_FDCWD, 
                  AT_FDCWD, 0, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_rename) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long oldname, newname, f1, f2, f3;
   if (ll && ll->log_wt <= WT_RENAME &&
      arg5_retrieve_and_delete(args, &oldname, &newname,&f1,&f2,&f3, gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
   if (is_err(args->ret))
      return 0;
#endif
      if (flood_sc_suppressed(sc, f1))
         return 0;
      log_rename(args, sc, oldname, newname, f1, f2, f3, args->ret);
   }
      
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_RENAME) {
      if (flood_sc_suppressed(args->__syscall_nr, args->olddfd))
         return 0;
      arg5_record((long)args->oldname, (long)args->newname, args->olddfd, 
                  args->newdfd, 0, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_renameat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long oldname, newname, f1, f2, f3;
   if (ll && ll->log_wt <= WT_RENAME &&
         arg5_retrieve_and_delete(args, &oldname, &newname,&f1,&f2,&f3, gettid(), sc)) {
      if (flood_sc_suppressed(sc, f1))
         return 0;
      log_rename(args, sc, oldname, newname, f1, f2, f3, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_RENAME) {
      if (flood_sc_suppressed(args->__syscall_nr, args->olddfd))
         return 0;
      arg5_record((long)args->oldname, (long)args->newname, args->olddfd, 
                  args->newdfd, args->flags, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_renameat2) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long oldname, newname, f1, f2, f3;
   if (ll && ll->log_wt <= WT_RENAME &&
         arg5_retrieve_and_delete(args, &oldname, &newname,&f1,&f2,&f3, gettid(), sc)) {
      if (flood_sc_suppressed(sc, f1))
         return 0;
      log_rename(args, sc, oldname, newname, f1, f2, f3, args->ret);
   }
   return 0;
}

static inline void
log_mknod(void *ctx, int sc, long filename, long mode, long dev, long fd, long ret) {
#ifdef IGNORE_FAILED_CALLS
   if (is_err(ret))
      return;
#endif   
   log_sc_str_long4(ctx, sc, MKNOD_EX, WT_MKNOD, MKNOD_EX_SB, (const char*)filename, 
                    fd, dev, (mode << 8)|(ret&0xff), proc(fd));
}

TRACEPOINT_PROBE(syscalls, sys_enter_mknod){
    int z = 0;
    struct log_lv *ll = log_level.lookup(&z);
    if (ll && ll->log_wt <= WT_MKNOD) {
      if (flood_sc_suppressed(args->__syscall_nr, AT_FDCWD))
         return 0;
      arg3_record((long)args->filename, args->mode, args->dev, gettid());
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mknod) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long filename, mode, dev;
   if (ll && ll->log_wt <= WT_MKNOD &&
       arg3_retrieve_and_delete(args, &filename, &mode, &dev, gettid(), sc)) {
      if (flood_sc_suppressed(sc, AT_FDCWD))
         return 0;
      log_mknod(args, sc, filename, mode, dev, AT_FDCWD, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mknodat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_MKDIR) {
      if (flood_sc_suppressed(args->__syscall_nr, args->dfd))
         return 0;
      arg3_record((long)args->filename, (args->dfd<<32)|args->mode, 
                  args->dev, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mknodat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long filename, mode, dev;
   if (ll && ll->log_wt <= WT_MKNOD &&
       arg3_retrieve_and_delete(args, &filename, &mode, &dev, gettid(), sc)) {
      if (flood_sc_suppressed(sc, mode>>32))
         return 0;
      log_mknod(args, sc, filename, mode&0xffffffff, dev, mode>>32, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_tee) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_TEE) {
      if (flood_sc_suppressed(args->__syscall_nr, args->fdin))
         return 0;
      arg3_record(args->fdin, args->fdout, args->len, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_tee) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long fdin, fdout, len;
   if (ll && ll->log_wt <= WT_TEE &&
       arg3_retrieve_and_delete(args, &fdin, &fdout, &len, gettid(), sc)) {
      if (flood_sc_suppressed(sc, fdin))
         return 0;
      log_read(args, sc, READ_EX, READ_EX_SB, fdin, args->ret);
      log_write(args, sc, WRITE_EX,WRITE_EX_SB, fdout, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mount) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  if (ll && ll->log_wt <= WT_MOUNT) {
      if (flood_sc_suppressed(args->__syscall_nr, 0))
         return 0;
      arg5_record((long)args->dev_name, (long)args->dir_name, (long)args->type,
                  args->flags, 0, gettid());
  }
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mount) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
  long dev_name, dir_name, type, flags, _ign;
  if (ll && ll->log_wt <= WT_MOUNT &&
      arg5_retrieve_and_delete(args, &dev_name,&dir_name,&type,&flags,&_ign,gettid(),sc)) {
#ifdef IGNORE_FAILED_CALLS
   if (is_err(args->ret))
      return 0;
#endif
      if (flood_sc_suppressed(sc, 0))
         return 0;
      log_sc_str3_long2(args, sc, MOUNT_EX, WT_MOUNT, MOUNT_EX_SB, (const char*)dev_name, 
                   (const char*)dir_name, (const char*)type, flags, args->ret);
      }
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_umount) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  if (ll && ll->log_wt <= WT_MOUNT) {
   if (flood_sc_suppressed(args->__syscall_nr, 0))
      return 0;
   arg3_record((long)args->name, args->flags, 0, gettid());
  }
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_umount) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  int sc = args->__syscall_nr;
  long name, flags, _ign;
  if (ll && ll->log_wt <= WT_MOUNT &&
         arg3_retrieve_and_delete(args, &name, &flags, &_ign, gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
   if (is_err(args->ret))
      return 0;
#endif
   if (flood_sc_suppressed(sc, 0))
      return 0;
   log_sc_str_long2(args, sc, UMOUNT_EX, WT_MOUNT, UMOUNT_EX_SB, 
                       (const char*)name, flags, args->ret);
   }
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_splice) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SPLICE) {
      if (flood_sc_suppressed(args->__syscall_nr, args->fd_in))
         return 0;
      arg3_record(args->len, args->fd_in, args->fd_out, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_splice) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long len, fd_in, fd_out;
   if (ll && ll->log_wt <= WT_SPLICE &&
       arg3_retrieve_and_delete(args, &len, &fd_in, &fd_out, gettid(), sc)) {
      if (flood_sc_suppressed(sc, fd_in))
         return 0;
      log_read(args, sc, READ_EX, READ_EX_SB, fd_in, args->ret);
      log_write(args, sc, WRITE_EX, WRITE_EX_SB, fd_out, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_vmsplice) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_VMSPLICE) {
      if (flood_sc_suppressed(args->__syscall_nr, args->fd))
         return 0;
      arg3_record(args->fd, args->flags, 0, gettid());
   }
      
   return 0;
}

// @@@@ To handle this properly, we need to look up kernel data structures to
// @@@@ determine if this has been opened for read or write, and record as
// @@@@ a read or write.
TRACEPOINT_PROBE(syscalls, sys_exit_vmsplice) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long fd, flags, _ign;
   if (ll && ll->log_wt <= WT_VMSPLICE &&
         arg3_retrieve_and_delete(args, &fd, &flags, &_ign, gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
   if (is_err(args->ret))
      return 0;
#endif
   if (flood_sc_suppressed(sc, fd))
      return 0;
   log_sc_long3(args, sc, VMSPLICE_EX, WT_VMSPLICE, VMSPLICE_EX_SB,
                    fd, proc(fd), args->ret);
   }
   return 0;
}

#endif

/****************************************************************************** 
 ******************************************************************************
 * Next are several process-related syscalls such as kill, ptrace, and so on. *
 *****************************************************************************/

///////////////////////////////////////////////////////////////////////////////
// These are important: let us stick to old scheme (log entry+exit), in case 
// the exit is delayed and may impact the logger.

static inline void 
log_kill_entry(void *ctx, int sc, long pid, int sig) {
   if (sig > 0) {// zero signal is never sent, and can be used to 
         // check for process existence (man page). Suppress it or else 
         // some programs (e.g., tail -f --pid) explode with kills.
      arg3_record(pid, sig, sc, gettid());
      // logging has been moved to exits.
   }
}
BPF_HASH(intervals, u64, u64, 1000000); 
BPF_HASH(last_ts, u32, u64, 1000000);
BPF_ARRAY(prev_count, u64, 1); 

TRACEPOINT_PROBE(syscalls, sys_enter_kill) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_KILL) {
#ifdef FLUSH_CACHE_2
      if (args->sig == 0 && getpid() == EAUDIT_PID) {
         u64 ts = bpf_ktime_get_ns();
   u64 *prev = last_ts.lookup(&z);
   u64 *prev_sc_count = prev_count.lookup(&z);
   u64* curr_sc_count = curr_scc.lookup(&z);
   if(curr_sc_count && prev_sc_count){
      // bpf_trace_printk("Current SN: %llu",*curr_sc_count);
      // bpf_trace_printk("Prev SN: %llu", *prev_sc_count);
  
      u64 diff = *curr_sc_count - *prev_sc_count;
      prev_count.update(&z, curr_sc_count);
      // if(curr_sc_count) bpf_trace_printk("Diff: %llu", diff);

      if(prev) {
         u64 delta = ts - *prev;
         intervals.update(&ts, &delta);
       }
       if(diff < NUMCPU){
         // bpf_trace_printk("Trigger A2");
         for (int j=0; j < NUMCPU; j++)
            flush_cache2(j, ts);
         last_ts.update(&z, &ts);
       }
         
   }
      }
#endif
#ifdef FILTER_SC_FLOOD
      if (suppress_flood_sc(args->__syscall_nr, getpid(), 0, bpf_ktime_get_ns()))
      return 0;
#endif

      log_kill_entry(args, args->__syscall_nr, args->pid, args->sig);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_tkill) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_KILL)
      if (args->sig > 0) {

#ifdef FILTER_SC_FLOOD
      if (suppress_flood_sc(args->__syscall_nr, getpid(), 0, bpf_ktime_get_ns()))
      return 0;
#endif
      // zero signal is never sent, and can be used to 
         // check for process existence (man page). Suppress it or else 
         // some programs (e.g., tail -f --pid) explode with kills.
         log_kill_entry(args, args->__syscall_nr, (args->pid << 32), args->sig);         
      } 
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_tgkill) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_KILL)
      if (args->sig > 0){ // zero signal is never sent, and can be used to 
         // check for process existence (man page). Suppress it or else 
         // some programs (e.g., tail -f --pid) explode with kills.
#ifdef FILTER_SC_FLOOD
      if (suppress_flood_sc(args->__syscall_nr, getpid(), 0, bpf_ktime_get_ns()))
      return 0;
#endif
         log_kill_entry(args, args->__syscall_nr, 
                        ((args->pid)<<32)|args->tgid, args->sig);
   }
   return 0;
}

static inline void
handle_kill_exit(void *ctx, long ret) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   long pid, sig, sc_orig;
   if (ll && ll->log_wt <= WT_KILL && 
       arg3_retrieve_and_delete(ctx, &pid, &sig, &sc_orig, gettid(), 600)) {
#ifdef IGNORE_FAILED_CALLS
      if (is_err(ret))
         return;
#endif
#ifdef FILTER_SC_FLOOD
      if (suppress_flood_sc(sc_orig, getpid(), 0, bpf_ktime_get_ns()))
      return;
#endif
      log_sc_long2(ctx, sc_orig, KILL_EN, WT_KILL, KILL_EN_SB, pid, sig);
      log_sc_long1(ctx, 600, KILL_EX, 0, KILL_EX_SB, ret);
   }
}

TRACEPOINT_PROBE(syscalls, sys_exit_kill) {
   handle_kill_exit(args, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_tkill) {
   handle_kill_exit(args, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_tgkill) {
   handle_kill_exit(args, args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_PTRACE) {
      if (flood_sc_suppressed(args->__syscall_nr, 0))
         return 0;
      log_sc_long2(args, args->__syscall_nr, PTRACE_EN, WT_PTRACE, PTRACE_EN_SB,
                   args->request, args->pid);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_ptrace) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_PTRACE) {
#ifdef IGNORE_FAILED_CALLS
   if (is_err(args->ret))
      return 0;
#endif
   if (flood_sc_suppressed(args->__syscall_nr, 0))
      return 0;
   log_sc_long1(args, 600, PTRACE_EX, 0, PTRACE_EX_SB, args->ret);
   }
   return 0;
}

/****************************************************************************** 
 ******************************************************************************
 * Next are several operations to change file permissions.                    *
 *****************************************************************************/

#ifdef LOG_PERM_OP
static inline void
log_chmod(void *ctx, int sc, long filename, long fd, long mode, long flags, long ret) {
 
   log_sc_str_long4(ctx, sc, CHMOD_EX, WT_CHMOD, CHMOD_EX_SB,
                    (const char *)filename, 
                    fd, mode, (flags<<8)|ret, proc(fd));
}

TRACEPOINT_PROBE(syscalls, sys_enter_chmod) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CHMOD) {
      if (flood_sc_suppressed(args->__syscall_nr, AT_FDCWD))
         return 0;
      arg3_record((long)args->filename, args->mode, AT_FDCWD, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_chmod) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long filename, mode, fd;
   if (ll && ll->log_wt <= WT_CHMOD &&
         arg3_retrieve_and_delete(args, &filename, &mode, &fd, gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
   if (is_err(args->ret))
      return 0;
#endif  
            if (flood_sc_suppressed(sc, fd))
               return 0;
            log_chmod(args, sc, filename, fd, mode, 0, args->ret);
         }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_CHMOD) {
      if (flood_sc_suppressed(args->__syscall_nr, args->dfd))
         return 0;
      arg3_record((long)args->filename, args->mode, 
         (args->dfd<<32)/*|(args->flag&0xffffffff)*/, gettid());
   }
         // @@@@ flags may be available in a future version. Until then,
         // @@@@ leave this commented out.
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchmodat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long filename, mode, dfd;
   if (ll && ll->log_wt <= WT_CHMOD &&
         arg3_retrieve_and_delete(args, &filename, &mode, &dfd, gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
      if (is_err(args->ret))
         return 0;
#endif   
      if (flood_sc_suppressed(sc, dfd>>32))
         return 0;
      log_chmod(args, sc, filename, dfd>>32, mode, dfd&0xffffffff, args->ret);
      }
      
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchmod) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FCHMOD) {
      if (flood_sc_suppressed(args->__syscall_nr, args->fd))
         return 0;
      arg3_record(args->fd, args->mode, 0, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchmod) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long fd, mode, _ign;
   if (ll && ll->log_wt <= WT_FCHMOD &&
         arg3_retrieve_and_delete(args, &fd, &mode, &_ign, gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
      if (is_err(args->ret))
         return 0;
#endif
      if (flood_sc_suppressed(sc, fd))
         return 0;
      log_sc_long3(args, sc, FCHMOD_EX, WT_FCHMOD, FCHMOD_EX_SB, mode, proc(fd), 
                     (fd<<8)|((char)args->ret));
   }
      
   return 0;
}

static inline void
log_chown(void *ctx, int sc, long fd, long file, long user, long group, 
          long fl, long ret) {
#ifdef IGNORE_FAILED_CALLS
   if (is_err(ret))
      return;
#endif
   log_sc_str_long5(ctx, sc, CHOWN_EX, WT_CHOWN, CHOWN_EX_SB, 
                    (const char*)file, fd, user, group, 
                    proc(fd), (fl<<8)|((char)ret));
}


TRACEPOINT_PROBE(syscalls, sys_enter_chown) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  if (ll && ll->log_wt <= WT_CHOWN) {
   if (flood_sc_suppressed(args->__syscall_nr, AT_FDCWD))
      return 0;
   arg3_record((long)args->filename, args->user, 
               args->group, gettid());
  }
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_chown) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  int sc = args->__syscall_nr;
  long filename, user, group;
  if (ll && ll->log_wt <= WT_CHOWN &&
      arg3_retrieve_and_delete(args, &filename, &user, &group, gettid(), sc)) {
     if (flood_sc_suppressed(sc, AT_FDCWD))
        return 0;
     log_chown(args, sc, AT_FDCWD, filename, user, group, 0, args->ret);
  }
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_lchown) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  if (ll && ll->log_wt <= WT_LCHOWN) {
   if (flood_sc_suppressed(args->__syscall_nr, AT_FDCWD))
      return 0;
   arg3_record((long)args->filename, args->user, args->group, gettid());
  }
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_lchown) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  int sc = args->__syscall_nr;
  long filename, user, group;
  if (ll && ll->log_wt <= WT_LCHOWN &&
         arg3_retrieve_and_delete(args, &filename, &user, &group, gettid(), sc)){
#ifdef IGNORE_FAILED_CALLS
      if (is_err(args->ret))
         return 0;
#endif
      if (flood_sc_suppressed(sc, AT_FDCWD))
         return 0;
      log_chown(args, sc, AT_FDCWD, filename, user, group,AT_SYMLINK_NOFOLLOW,
               args->ret);

   }
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchownat) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  if (ll && ll->log_wt <= WT_CHOWN) {
   if (flood_sc_suppressed(args->__syscall_nr, args->dfd))
      return 0;
   arg5_record((long)args->filename, (int)args->dfd,
               args->user, args->group, args->flag, gettid());
  }
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchownat) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  int sc = args->__syscall_nr;
  long filename, user, group;
  long dfd, flags;
  if (ll && ll->log_wt <= WT_CHOWN &&
      arg5_retrieve_and_delete(args, &filename,&dfd,&user,&group,&flags, gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
      if (is_err(args->ret))
         return 0;
#endif
      if (flood_sc_suppressed(sc, dfd))
         return 0;
      log_chown(args, sc, dfd, filename, user, group, flags, args->ret);
      }
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchown) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  if (ll && ll->log_wt <= WT_FCHOWN) {
   if (flood_sc_suppressed(args->__syscall_nr, args->fd))
      return 0;
   arg3_record(args->fd, args->user, args->group, gettid());
  }
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchown) {
  int z = 0;
  struct log_lv *ll = log_level.lookup(&z);
  int sc = args->__syscall_nr;
  long fd, user, group;
  if (ll && ll->log_wt <= WT_FCHOWN &&
      arg3_retrieve_and_delete(args, &fd, &user, &group, gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
      if (is_err(args->ret))
         return 0;
#endif
      if (flood_sc_suppressed(sc, fd))
         return 0;
      log_sc_long4(args, sc, FCHOWN_EX, WT_FCHOWN, FCHOWN_EX_SB, user, group, 
                 (fd<<8)|((char)args->ret), proc(fd));
   }
  return 0;
}

/****************************************************************************** 
 ******************************************************************************
 * Next are several operations related to uid/gid change for processes.       *
 * We encode them all into two operations: setresuid and setresgid.           *
 *****************************************************************************/
TRACEPOINT_PROBE(syscalls, sys_enter_setresuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETUID) {
      if (flood_sc_suppressed(args->__syscall_nr, 0))
      return 0;
      arg3_record(args->ruid, args->euid, args->suid, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setreuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETUID) {
      if (flood_sc_suppressed(args->__syscall_nr, 0))
      return 0;
      arg3_record(args->ruid, args->euid, INVAL_UID, gettid());
   }   
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETUID) {
      if (flood_sc_suppressed(args->__syscall_nr, 0))
      return 0;
      arg3_record(INVAL_UID, args->uid, INVAL_UID, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setresuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long ruid, euid, suid;
   if (ll && ll->log_wt <= WT_SETUID && 
       arg3_retrieve_and_delete(args, &ruid, &euid, &suid, gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
      if (is_err(args->ret))
         return 0;
#endif
      if (flood_sc_suppressed(args->__syscall_nr, 0))
      return 0;
      log_sc_long4(args, sc, SETUID_EX, WT_SETUID, SETUID_EX_SB,
                   ruid, euid, suid, args->ret);
       }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setreuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long ruid, euid, suid;
   if (ll && ll->log_wt <= WT_SETUID &&
         arg3_retrieve_and_delete(args, &ruid, &euid, &suid, gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
      if (is_err(args->ret))
         return 0;
#endif
      if (flood_sc_suppressed(args->__syscall_nr, 0))
      return 0;
      log_sc_long4(args, sc, SETUID_EX, WT_SETUID, SETUID_EX_SB,
                   ruid, euid, suid, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setuid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long a1, a2, a3;
   if (ll && ll->log_wt <= WT_SETUID &&
         arg3_retrieve_and_delete(args, &a1, &a2, &a3, gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
      if (is_err(args->ret))
         return 0;
#endif
      if (flood_sc_suppressed(args->__syscall_nr, 0))
      return 0;
      log_sc_long4(args, sc, SETUID_EX, WT_SETUID, SETUID_EX_SB,
                   a1, a2, a3, args->ret);
   }
      
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setresgid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETGID) {
      if (flood_sc_suppressed(args->__syscall_nr, 0))
         return 0;
      arg3_record(args->rgid, args->egid, args->sgid, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setregid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETGID) {
      if (flood_sc_suppressed(args->__syscall_nr, 0))
         return 0;
      arg3_record(args->rgid, args->egid, INVAL_UID, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_setgid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_SETGID) {
      if (flood_sc_suppressed(args->__syscall_nr, 0))
         return 0;
      arg3_record(INVAL_UID, args->gid, INVAL_UID, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setresgid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long a1, a2, a3;
   if (ll && ll->log_wt <= WT_SETGID &&
         arg3_retrieve_and_delete(args, &a1, &a2, &a3, gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
      if (is_err(args->ret))
         return 0;
#endif
      if (flood_sc_suppressed(sc, 0))
         return 0;
      log_sc_long4(args, sc, SETGID_EX, WT_SETGID, SETGID_EX_SB,
                   a1, a2, a3, args->ret);
}
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setregid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long a1, a2, a3;
   if (ll && ll->log_wt <= WT_SETGID &&
         arg3_retrieve_and_delete(args, &a1, &a2, &a3, gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
      if (is_err(args->ret))
         return 0;
#endif
      if (flood_sc_suppressed(sc, 0))
         return 0;
      log_sc_long4(args, sc, SETGID_EX, WT_SETGID, SETGID_EX_SB,
                   a1, a2, a3, args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_setgid) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long a1, a2, a3;
   if (ll && ll->log_wt <= WT_SETGID &&
         arg3_retrieve_and_delete(args, &a1, &a2, &a3, gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
      if (is_err(args->ret))
         return 0;
#endif
      if (flood_sc_suppressed(sc, 0))
         return 0;
      log_sc_long4(args, sc, SETGID_EX, WT_SETGID, SETGID_EX_SB,
                   a1, a2, a3, args->ret);
   }
      
   return 0;
}
#endif

/****************************************************************************** 
 ******************************************************************************
 * Process creation and deletion operations. The first group conains fork,    *
 * vfork and clone, while the latter contains exit and exit_group . We record *
 * record some extra information for these syscalls, specifically, uids+gids. *
 *****************************************************************************/

#ifdef LOG_PROC_OP
TRACEPOINT_PROBE(syscalls, sys_enter_fork) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK) {
      if (flood_sc_suppressed(args->__syscall_nr, 0))
         return 0;
      arg_record(0, gettid());
      // log_sc_long0(args, args->__syscall_nr, FORK_EN, WT_FORK, FORK_EN_SB);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_vfork) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK) {
      if (flood_sc_suppressed(args->__syscall_nr, 0))
         return 0;
      arg_record(0, gettid());
      // log_sc_long0(args, args->__syscall_nr, FORK_EN, WT_FORK, FORK_EN_SB);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_clone) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK) {
#ifdef FILTER_SC_FLOOD
      if (suppress_flood_sc(args->__syscall_nr, getpid(), 0, bpf_ktime_get_ns()))
      return 0;
#endif      
      arg_record(args->clone_flags, gettid());
      // Defer logging to sys_exit_clone
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_clone3) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK) {
      long flags = 0; // zero is probably a good default
      bpf_probe_read_user(&flags, 8, args->uargs);
#ifdef FILTER_SC_FLOOD
      if (suppress_flood_sc(args->__syscall_nr, getpid(), 0, bpf_ktime_get_ns()))
      return 0;
#endif      
      arg_record(flags, gettid());
      // Defer logging to sys_exit_clone3
   }
   return 0;
}

/*
  Note that clone can return in the child before it returns in the parent. Only
  the parent gets the return value as the child pid, and the child does not
  know anything about its parent from the return code of fork/clone. This can
  be inconvenient when processing syscall data, as we will have to process
  data from a child before we have constructed much information about the child,
  such as the parent id, or the file descriptors inherited from the parent.
  The following options are available to supply the missing information:

  1. the cloner can provide a poiner argument such that the kernel writes to
     this memory location before clone returns to child. However, the parent
     may not provide a valid pointer, so the kernel does not store this info
     and hence we cannot access this info.

  2. We can go to the task struct and ask for the parent process (as shown in
     the code below that is commented out) but if the CLONE_PARENT flag is set,
     the parent will be the parent process of the cloner, and NOT the cloner.
     (It is possible that there are other cases as well, e.g., in the presence
     of a ptrace.)

  3. We can rely on the tgid of the cloner and clonee being the same. However,
     if the CLONE_THREAD flag is not set, clonee will go into its own
     thread group, so its tgid will become different from that of the cloner.

  There seems to be one mechanism to overcome all this, which is to use the
  real_parent field of the task_struct. This field is not well documented, but
  what little information is available suggests that it is exactly what we need.
  We pick it up, and pack it along with the return value, which must be 32-bit
  for fork/exec. 
*/
// Sometimes, clone returns a strange number instead of a thread id. Could
// it be some PID namespace issues? Best to add parent pid info (or 
// something else) to reliably relate parent to child. Alternatively,
// look at the scheduler hook (see examples/ directory here).

static inline void
log_sc_exit_with_ids(void *ctx, long sc, char scnm, int sign_bytes, long ret) {
   u64 flags=0;
   int tid, pid;
   gettidpid(&tid, &pid);
   int clone = arg_retrieve_and_delete(ctx, &flags, tid, 600);
   int scwt = 0;
   if (flood_sc_suppressed(sc, 0))
      return;
  
   if (!is_err(ret)) {
       if (scnm == CLONE_EX) {
           log_sc_long1(ctx, sc, CLONE_EN, WT_FORK, CLONE_EN_SB, flags);
       } else if (scnm == FORK_EX) {
           log_sc_long0(ctx, sc, FORK_EN, WT_FORK, FORK_EN_SB);
       }
   }

   if (!is_err(ret) && ((scnm == FORK_EX) || (scnm == CLONE_EX))) {
      if (ret != 0)  {// parent process
         scwt = WT_CRITICAL;
         if (clone && (flags & CLONE_THREAD)) {
            if (!(flags & CLONE_FILES)) {
               add_si(pid, 1, 1);
            }
            else add_si(pid, 0, 1);
         }
      }
      else {
         scwt = WT_IMPORTANT;
         if (tid == pid) // Not a thread, so create subjinfo for the new pid
            add_si(pid, 0, 0);
      }
   }

   // In all other cases, SubjInfo has already been created.
   struct task_struct *t = (struct task_struct *)bpf_get_current_task();
   long parent_tid = t->real_parent->pid;
   ret = (ret & 0xffffffff) | (parent_tid << 32);
   
   if(is_err(ret))
      return;
   // bpf_get_current_uid_gid() returns real userid. Who needs that?
   // So we need to navigate task_struct get the effective uid/gid
   u64 uidgid = t->cred->egid.val;
   uidgid = (uidgid << 32) | t->cred->euid.val;

   long cgroup = bpf_get_current_cgroup_id();
   
   log_sc_long3(ctx, 600, scnm, scwt, sign_bytes, uidgid, cgroup, ret);
   // Previously, weight was zero, but this can cause long delays for the
   // exit event to get to the user level. This can lead to errors in
   // matching fork entries and exits, which, in turn, has the potential
   // for misattribution or mishandling of syscalls.
}

TRACEPOINT_PROBE(syscalls, sys_exit_fork) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK)
      log_sc_exit_with_ids(args, args->__syscall_nr, FORK_EX, FORK_EX_SB,
                            args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_vfork) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK)
      log_sc_exit_with_ids(args, args->__syscall_nr, FORK_EX, FORK_EX_SB,
                            args->ret);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_clone) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK) {
      if (flood_sc_suppressed(args->__syscall_nr, 0))
         return 0;
      log_sc_exit_with_ids(args, args->__syscall_nr, CLONE_EX, CLONE_EX_SB,
                            args->ret);
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_clone3) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FORK)
      log_sc_exit_with_ids(args, args->__syscall_nr, CLONE_EX, CLONE_EX_SB,
                            args->ret);
   return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_exit) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
#ifdef FILTER_DEP
   dec_threads(getpid());
#endif
   if (ll && ll->log_wt <= WT_EXIT)
      log_sc_long1(args, args->__syscall_nr, EXIT_EN, WT_EXIT, EXIT_EN_SB,
                   args->error_code);
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_exit_group) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
#ifdef FILTER_DEP
   delete_subj(getpid());
#endif
   if (ll && ll->log_wt <= WT_EXIT)
      log_sc_long1(args, args->__syscall_nr, EXITGRP_EN, WT_EXIT, EXITGRP_EN_SB,
                   args->error_code);
   return 0;
}

/******************************************************************************* 
 *******************************************************************************
 * Finally, execve. It is the most complex of syscalls because of many         *
 * indirectly referenced arguments (argv and env strings). The complexities    *
 * associated with them are discussed further below. There is also another     *
 * difficulty relating to hitting the verifier's limits on code size/number    *
 * of branches in the code. We should solve this problem by using tail calls,  *
 * or better, by putting ourselves in multiple execve-related hooks, and       *
 * splitting up the recording work across these hooks. Some of these hooks     *
 * may also have the advantage that the data is already in kernel memory and   *
 * is hence immune to the errors mentioned below (or race conditions.          *
 ******************************************************************************* 
 * If the parent forks and then uses read-only arguments to execve, reading    *
 * these args in an ebpf probe can result in pagefaults due to lazy copying    *
 * of page tables from parent to child. Since pagefault handlers are disabled  *
 * when executing probes, we get errors. These errors contribute to string,    *
 * argv and data errs below. See the following link for more explanation:      *
 *                                                                             *
https://lists.iovisor.org/g/iovisor-dev/topic/accessing_user_memory_and/21386221
 *                                                                             *
 * One work-around suggested is to read the data at the exit of system call.   *
 * I would have thought that the memory has been overwritten by the time       *
 * execve returns. Indeed, the test so far suggests that this is the case, so  *
 * we need to look at other hooks where the data may have been copied over     *
 * from the user level, such as the scheduler's execve, or one of LSM hooks.   *
 ******************************************************************************/
static inline void 
log_execve(void *ctx, int sc, const char* fn, const char* const *argv, 
           const char* const *envp, long fd, long flags) {
   u16 i, hdr; struct buf *b; 
#ifdef LOG_ENV
   char scnm=EXECVEE_EN;
#else
   char scnm=EXECVE_EN;
#endif
   if ((b = init(sc, scnm, WT_EXECVE, &i, &hdr))) {
#ifdef FILTER_SC_FLOOD
      b->staging_start = i;   // Mark where payload begins (after header)
      b->staging_hdr = hdr;   // Remember hdr byte position (patched by add_long3)
      b->execve_staging = 1;  // Tell tail calls to stage instead of finish
#endif
      add_long3(b, flags, fd, proc(fd), &i, hdr);
      add_string(b, fn, &i);
#ifdef LOG_ENV
      b->nargpos = i;
      i += 2;
      u16 argv_count = add_str_array0_16(b, argv, &i);
      b->nargvl = argv_count;
      if(argv_count < 16) { //If no ARGV are remaining to log, tail call ENVP
            goto tailcall_envp;
      }
      b->idx = i;
      b->argv = argv + argv_count; //Increase the pointer to next 16 arguments
      b->envp = envp;
      tailcall.call(ctx, 0);
    
      tailcall_envp:
         b->idx = i;
         if(b->nargpos < BUFSIZE -200){
            b->d[b->nargpos] = (char)(b->nargvl & 0xff);
            b->d[b->nargpos+1] = (char)(b->nargvl >> 8 & 0xff);
         }
         b->envp = envp;
         tailcall.call(ctx, 1);
         // If tailcall fails, execution falls through! We MUST append a
         // 2-byte ENVP count of 0 so the parser isn't misaligned.
         if (i < BUFSIZE - 200) {
             b->d[i] = 0;
             b->d[i+1] = 0;
             i += 2;
         }
#else
      // This is the best we have been able to do: increasing array sizes, 
      // even by one, causes verification failure with an unhelpful message
      // "argument list too long." Multiple attempts, such as removing some
      // condition checks etc have yielded no progress. Indeed, typically things
      // get worse. 
      add_str_array0_32(b, argv, &i);
#endif
#ifdef FILTER_SC_FLOOD
      if (b->execve_staging) {
          b->execve_staging = 0;
          // Stage the payload (non-LOG_ENV path finishes here)
          int scratch_z = 0;
          struct staged_execve *entry = execve_scratch.lookup(&scratch_z);
          if (entry) {
              int tid = gettid();
              u16 start = b->staging_start;
              if (start >= BUFSIZE) start = 0;
              u16 len = i - start;
              if (len <= STAGED_EXECVE_SIZE) {
                  // Ensure start + len doesn't exceed buf->d bounds
                  u32 avail = BUFSIZE - start;
                  if (len > avail)
                      len = avail;
                  entry->len = len;
                  entry->sign_bytes = 712;
                  // Save the hdr byte (arg-width bits patched by add_long3)
                  if (b->staging_hdr < BUFSIZE)
                      entry->hdr_byte = b->d[b->staging_hdr];
                  if (len > 0) {
                      u32 sz = len;
                      if (sz > STAGED_EXECVE_SIZE) sz = STAGED_EXECVE_SIZE;
                      bpf_probe_read_kernel(entry->d, sz, &b->d[start]);
                  }
                  execve_stage.update(&tid, entry);
                  // Rollback
                  if (hdr >= 9) b->idx = hdr - 9;
                  else b->idx = 0;
                  b->weight -= WT_EXECVE;
                  unlock_cache(b);
                  return;
              }
          }
      }
#endif
      finish(b, i, ctx, 712);
   }
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
   // u64 pidtid = bpf_get_current_pid_tgid(); 
   // u64 fn = (u64)args->filename;
   // execve.update(&pidtid, &fn);

   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_EXECVE) {
#ifdef FILTER_SC_FLOOD
      if (suppress_flood_sc(args->__syscall_nr, getpid(), 0, bpf_ktime_get_ns()))
         return 0;
#endif
      log_execve(args, args->__syscall_nr, args->filename, 
                 args->argv, args->envp, AT_FDCWD, 0);
   }
      
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
   int z = 0;
   long fd = proc(args->fd);
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_EXECVE) {
#ifdef FILTER_SC_FLOOD
      if (suppress_flood_sc(args->__syscall_nr, getpid(), fd, bpf_ktime_get_ns()))
         return 0;
#endif
      log_execve(args, args->__syscall_nr, args->filename, 
              args->argv, args->envp, fd, args->flags);
   }
      
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_EXECVE) {
#ifdef FILTER_SC_FLOOD
      // Replay staged execve entry if the syscall succeeded
      int tid = gettid();
      struct staged_execve *staged = execve_stage.lookup(&tid);
      if (staged) {
          if (!is_err(args->ret)) {
              u16 ri, rhdr;
              struct buf *rb;
#ifdef LOG_ENV
              char rscnm = EXECVEE_EN;
#else
              char rscnm = EXECVE_EN;
#endif
              rb = init(args->__syscall_nr, rscnm, WT_EXECVE, &ri, &rhdr);
              if (rb) {
                  if (ri >= BUFSIZE) ri = 0;
                  u32 sz = staged->len;
                  if (sz > STAGED_EXECVE_SIZE) sz = STAGED_EXECVE_SIZE;
                  u32 ri_u32 = ri;
                  if (ri_u32 <= BUFSIZE - STAGED_EXECVE_SIZE) {
                      if (sz > 0)
                          bpf_probe_read_kernel(&rb->d[ri_u32], sz, staged->d);
                      ri_u32 += sz;
                      // Restore the hdr byte (arg-width encoding) into the fresh header
                      rb->d[rhdr] = staged->hdr_byte;
                      finish(rb, ri_u32, args, staged->sign_bytes);
                  } else {
                      if (rhdr >= 9) rb->idx = rhdr - 9;
                      else rb->idx = 0;
                      rb->weight -= WT_EXECVE;
                      unlock_cache(rb);
                  }
              }
          }
          execve_stage.delete(&tid);
      }
#endif
      log_sc_exit_with_ids(args, args->__syscall_nr, EXECVE_EX, 
                           EXECVE_EX_SB, args->ret);
   }
#ifdef FILTER_REP_RDWR
   reset_threads();
#endif
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_execveat) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_EXECVE) {
#ifdef FILTER_SC_FLOOD
      // Replay staged execveat entry if the syscall succeeded
      int tid = gettid();
      struct staged_execve *staged = execve_stage.lookup(&tid);
      if (staged) {
          if (!is_err(args->ret)) {
              u16 ri, rhdr;
              struct buf *rb;
#ifdef LOG_ENV
              char rscnm = EXECVEE_EN;
#else
              char rscnm = EXECVE_EN;
#endif
              rb = init(args->__syscall_nr, rscnm, WT_EXECVE, &ri, &rhdr);
              if (rb) {
                  if (ri >= BUFSIZE) ri = 0;
                  u32 sz = staged->len;
                  if (sz > STAGED_EXECVE_SIZE) sz = STAGED_EXECVE_SIZE;
                  u32 ri_u32 = ri;
                  if (ri_u32 <= BUFSIZE - STAGED_EXECVE_SIZE) {
                      if (sz > 0)
                          bpf_probe_read_kernel(&rb->d[ri_u32], sz, staged->d);
                      ri_u32 += sz;
                      // Restore the hdr byte (arg-width encoding) into the fresh header
                      rb->d[rhdr] = staged->hdr_byte;
                      finish(rb, ri_u32, args, staged->sign_bytes);
                  } else {
                      if (rhdr >= 9) rb->idx = rhdr - 9;
                      else rb->idx = 0;
                      rb->weight -= WT_EXECVE;
                      unlock_cache(rb);
                  }
              }
          }
          execve_stage.delete(&tid);
      }
#endif
      log_sc_exit_with_ids(args, args->__syscall_nr, EXECVE_EX, 
                           EXECVE_EX_SB, args->ret);
   }
#ifdef FILTER_REP_RDWR
   reset_threads();
#endif
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_init_module){
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if(ll && ll->log_wt <= WT_INITMOD) {
      if (flood_sc_suppressed(args->__syscall_nr, 0))
         return 0;
      arg_record((long)args->uargs, gettid());
   }
      return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_init_module) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   u64 uargs;
   if (ll && ll->log_wt <= WT_INITMOD &&
         arg_retrieve_and_delete(args, &uargs, gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
      if (is_err(args->ret))
         return 0;
#endif
      if (flood_sc_suppressed(sc, 0))
         return 0;
      log_sc_str_long1(args, sc, INITMOD_EX, WT_INITMOD, INITMOD_EX_SB,
                       (const char*)uargs,args->ret);
   }
      
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_finit_module) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   if (ll && ll->log_wt <= WT_FINITMOD) {
      if (flood_sc_suppressed(args->__syscall_nr, 0))
         return 0;
      arg3_record((long)args->uargs, args->fd, 
                  args->flags, gettid());
   }
   return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_finit_module) {
   int z = 0;
   struct log_lv *ll = log_level.lookup(&z);
   int sc = args->__syscall_nr;
   long uargs, fd, flags;
   if (ll && ll->log_wt <= WT_FINITMOD && 
       arg3_retrieve_and_delete(args, &uargs, &fd, &flags, gettid(), sc)) {
#ifdef IGNORE_FAILED_CALLS
      if (is_err(args->ret))
         return 0;
#endif
      if (flood_sc_suppressed(sc, fd))
         return 0;
      log_sc_str_long4(args, sc, FINITMOD_EX, WT_FINITMOD, FINITMOD_EX_SB,
                       (const char*)uargs, 
                       fd, flags, args->ret, proc(fd));
   }
      
   return 0;
}
#endif
