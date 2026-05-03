#ifndef EAUDITK_H
#define EAUDITK_H

#define MAX_SLEN 128 // Max size of string argument fetched from process memory
#define MAX_DLEN 128 // Max size of data arguments fetched from process memory
#define MAX_ARG  512 // Max arguments that can be logged in execve syscall
//#define BUFSIZE 2 * TX_THRESH + 223 * MAX_DLEN // Shd be big enough for execve
#define BUFSIZE (16*1024 - 128) // This size ensures that the total cache size
// will be <= 16K. This 16K bounds also limits max complexity of execve logging.

#define TOTAL_KEYS 262144UL
#define KEY_SIZE 16  
#define QUARTER_POINT (TOTAL_KEYS / 4)     
#define HALF_POINT (TOTAL_KEYS / 2)     
#define THREE_QUARTER_POINT (3 * TOTAL_KEYS / 4)  

/*******************************************************************************
 * Maps that can be queried by the user level to determine status and stats *
 ********************************************************************************/
enum StatIdx {
  RB_FAIL = 0,
  RB_BYTES = 1,
  RB_MSGS = 2,
  RB_WAKEUPS = 3,
  FN_ERR = 4,
  DATA_ERR = 5,
  ARGV_ERR = 6,
  FCNTL_ERR = 7,
  SADDR_ERR = 8,
  PIPE_ERR = 9,
  MMAP_ERR = 10,
  RDWR_RECORDED = 11,
  RDWR_SUPPRESSED = 12,
  FN_TRUNC_ERR = 13,
  DATA_TRUNC_ERR = 14,
  DATA_READ_OK = 15,
  OPEN_DATA_ERR = 16,
  SADDR_DATA_ERR = 17,
  CONN_DATA_ERR = 18,
  SENDTO_DATA_ERR = 19,
  BIND_DATA_ERR = 20,
  PIPE_READ_DATA_ERR = 21,
  SADDR_READ_DATA_ERR = 22,
  FD_UNFOUND_ERR = 23,
  INODE_UNFOUND_ERR = 24,
  FILE_UNFOUND_ERR = 25,
  PIPE_UNFOUND_ERR = 26,
  SOCK_UNFOUND_ERR = 27,
  FDTOID_ERRS = 28,
  FDTOID_CALLS = 29,
  SUBJINFO_ERR = 30,
  SUBJINFO_DELETED = 31,
  SUBJINFO_UNDELETED = 32,
  SUBJINFO_OVERFLOW = 33,
  NUM_SUBJ_CREATED = 34,
  OBJINFO_ERR = 35,
  OBJINFO_DELETED = 36,
  OBJINFO_OVERFLOW = 37,
  // NUM_OBJ_CREATED=,
  FILE_REUSE_SUCC = 38,
  FILE_REUSE_FAIL = 39,
  FILE_REUSE_MISSED = 40,
  FILEINFO_DELETED = 41,
  FDINFO_DELETED = 42,
  FILE_REUSE_STALE = 43,
  FILEINFO_ERR = 44,
  SIDOID_COLLISION = 45,
  PER_THR_FI_SUBJ = 46,
  DELETED_OI_IN_TMP_CACHE = 47,
  LOCK_FAIL_LOST_SYSCALLS = 48,
  UNEXP_MAP_LOOKUP_FAIL = 49,
  UNEXP_ARG_LOOKUP_FAIL = 50,
  NONLOCAL_CACHE_FLUSHES = 51,
  NONLOCAL_CACHE_CHECKS = 52,
  MED_RDWR_LOGGED = 53,
  TOO_LARGE_LOGGED = 54,
  TOO_SMALL_SKIPPED = 55,
  ZERO_RDWR_SKIPPED = 56,
  SUBJINFO_DELETED_RDWR = 57,
  SIGN_FAIL = 58,
  MAX_STAT = 59
};

// Dynamic congestion control: setting log_wt to w will cause syscalls with
// weights < w to be dropped. See further down for syscall weights. Congestion
// control is indiscriminate, try "FILTER REPEATED OPERATIONS" first.

#ifdef __KERNEL__
struct log_lv {
  u32 log_wt;
};

struct buf {
  u16 idx;
  u32 keyidx;
  u16 nargvl;
  u16 nenvpl;
  u16 nargpos;
  u32 current_sn;
  u16 msglen;
  u32 weight;
  const char *const *envp;
  const char *const *argv;
  const u64 *msgp;
  u32 *msgp1;
  u64 v0;
  u64 v1;
  u64 v2;
  u64 v3;
  u32 rv1;
  u32 rv2;
  u64 k11;
  u64 k12;
  u64 k1;
  u64 k2;
  u16 word_count;
#ifdef FILTER_SC_FLOOD
  u16 staging_start;   // Offset in d[] where execve payload begins (after header)
  u16 staging_hdr;     // Offset of hdr byte in d[] patched by add_long3 (to save arg widths)
  u8  execve_staging;  // 1 = tail calls should stage instead of finish
#endif
  u64 current_ts;
  u64 lock;
  u64 start_ts;
  u64 tsrec;       // No fields between tsrec and d: tsrec to d[idx] transmitted
  char d[BUFSIZE]; // to user level, so such fields will corrupt the message.
};

struct adaptive_latency {
  int qlen;
  int prev_qlen;
  // add other needed fields.
};

struct hashkey{
  u64 keys[TOTAL_KEYS][2];
};

struct bank_state {
  u32 current_bank;
  u32 next_bank;
};

BPF_ARRAY(msgs_rcvd, long, 1);
BPF_ARRAY(tx_fac, u32, 1);
BPF_ARRAY(mystat, u64, MAX_STAT);
BPF_ARRAY(log_level, struct log_lv, 1); // For dynamic control of events to log
BPF_ARRAY(count, u64, 400);    // To track # of system call entries
BPF_ARRAY(errcount, u64, 400); // # arg retrieval error for each syscall
BPF_ARRAY(countexit, u64, 1);  // To track # combined system call exits
BPF_PROG_ARRAY(tailcall, 33);  // For storing key value pair for tail call

#ifdef TAMPER_DETECT
BPF_ARRAY(keyset0, struct hashkey, 1);
BPF_ARRAY(keyset1, struct hashkey, 1);
BPF_ARRAY(current_bank, u64, 1);
BPF_ARRAY(basekey, struct hashkey, 1);
BPF_ARRAY(initkey, struct hashkey, 1);
BPF_ARRAY(bank_state, struct bank_state, 1);
BPF_ARRAY(next_bank, u64, 1);
BPF_ARRAY(keygen_signal, u16, 1);
BPF_ARRAY(is_initkey, u16, 1);
#endif

#ifdef PERCPU_CACHE
BPF_PERCPU_ARRAY(buf, struct buf, 1);
#else
BPF_ARRAY(buf, struct buf, NUMCPU + 1);
#endif

BPF_RINGBUF_OUTPUT(events, RINGBUF_PAGES);

#ifdef FILTER_SC_FLOOD
// Per-TID staging buffer for deferring execve entry logging to exit.
// Stores the marshalled payload (everything after the init() header).
#define STAGED_EXECVE_SIZE 3500
struct staged_execve {
    u16 len;                        // Number of payload bytes staged
    u16 sign_bytes;                 // For finish() at replay time
    u8  hdr_byte;                   // b->d[hdr] value (arg-width bits written by add_long3)
    char d[STAGED_EXECVE_SIZE];     // Marshalled entry payload (after init() header)
};
BPF_TABLE("lru_hash", u32, struct staged_execve, execve_stage, 256);
BPF_PERCPU_ARRAY(execve_scratch, struct staged_execve, 1); // Scratch space (avoids stack)
#endif

#endif
/******************************************************************************
 * Weights of various system calls are specified below. They refer to constant *
 * values defined in the Python program that includes/compiles this program. *
 ******************************************************************************/
/*************** Privilege escalation and process interference ***************/
#define WT_EXECVE WT_CRITICAL
#define WT_SETUID WT_CRITICAL
#define WT_KILL WT_CRITICAL
#define WT_PTRACE WT_CRITICAL
#define WT_FINITMOD WT_CRITICAL
#define WT_INITMOD WT_CRITICAL
#define WT_MOUNT WT_CRITICAL
#define WT_FORK WT_CRITICAL // Changed from IMPORTANT so as to minimize the
// likelihood of errors in matching entries and exits. Such errors can cause
// misattribution of syscalls and other potential problems.

/********************** Process provenance and loading ***********************/
#define WT_SETGID WT_IMPORTANT
#define WT_MMAP WT_IMPORTANT
#define WT_CHDIR WT_IMPORTANT
#define WT_EXIT WT_IMPORTANT

/********************** File name and attribute change ***********************/
#define WT_UNLINK WT_IMPORTANT
#define WT_RMDIR WT_IMPORTANT
#define WT_RENAME WT_IMPORTANT
#define WT_LINK WT_IMPORTANT
#define WT_SYMLINK WT_IMPORTANT
#define WT_CHMOD WT_IMPORTANT
#define WT_FCHMOD WT_IMPORTANT
#define WT_FCHOWN WT_IMPORTANT
#define WT_LCHOWN WT_IMPORTANT
#define WT_CHOWN WT_IMPORTANT
/******************* Data endpoint creation/modification *********************/
#define WT_OPENWR WT_ENDPOINT
#define WT_TRUNC WT_ENDPOINT
#define WT_MKDIR WT_ENDPOINT
#define WT_MKNOD WT_ENDPOINT
#define WT_ACCEPT WT_ENDPOINT
#define WT_CONNECT WT_ENDPOINT
#define WT_SPLICE WT_ENDPOINT
#define WT_VMSPLICE WT_ENDPOINT
#define WT_TEE WT_ENDPOINT
/********************* Unconnected network reads and writes ******************/
#define WT_RECVFROM WT_DGRAM
#define WT_SENDTO WT_DGRAM

/************************* File descriptor tracking **************************/
#define WT_OPENRD WT_FDTRACK
#define WT_DUP WT_FDTRACK
#define WT_PIPE WT_FDTRACK
#define WT_SOCKPAIR WT_FDTRACK
#define WT_SOCKET WT_FDTRACK
/****************** Read, write and other low-priority events ****************/
#define WT_BIND WT_RDWR
#define WT_GETPEER WT_RDWR

#define WT_READ WT_RDWR
#define WT_WRITE WT_RDWR
#define WT_SENDFILE64 WT_RDWR
#define WT_COPY_FILE_RANGE WT_RDWR
/************************ Some exits we *could* ignore  **********************/
#define WT_READEX WT_UNIMPORTANT
#define WT_WRITEX WT_UNIMPORTANT
#define WT_CLOSE WT_UNIMPORTANT
#define WT_MMAPALL WT_UNIMPORTANT

/* On Linux, close is frequent, never fails if FD is valid, so best to ignore */
#define WT_CLOSE_EX WT_REDUNDANT
//-------------------------------------------------------------------------------
// Events subject to logging are defined below. Note that events outside of this
// specification are not even intercepted, so we avoid the base overhead of
// interception (which is non-negligible). Obviously, dynamic control is not
// applicable to events that aren't even intercepted.
//

// Top-level grouping of system calls, you can enable/disable groups at once.

#define LOG_FILENAME_OP // These affect names, incl: mkdir, rename, unlink, etc.
#define LOG_PROC_CONTROL // Ops for one process to modify another: kill, ptrace,...
#define LOG_PERM_OP      // Permission-related: chmod, chown, setuid, ...
#define LOG_PROC_OP      // Other process ops, e.g., fork, execve, exit, ...
#define LOG_READ         // File and network input operations.
#define LOG_WRITE        // File and network output operations.

#define LOG_ENV // Whether to log environment variables on execve

#define LOG_MMAP // Reads on mmapped files don't need syscalls, so you
                 // to track file-based mmaps to know all read/writes.

#define LOG_OPEN     // -- These create file fds
#define LOG_NET_OPEN // -- These create socket fds
#define LOG_DUP      // -- These change fd associations
#define LOG_PIPE     // -- These create connected fds (incl. sockets)

// More detailed ifdefs that haven't been covered above.

//#define LOG_MMAPALL    // LOG_MMAP logs file-backed and execute permission mmaps.
//  To also log mmaps used for mem. alloc, enable this.
#define LOG_CLOSE       // These remove fds, enable if useful resource release.

//-------------------------------------------------------------------------------
//
// Miscellaneous definitions for timestamp manipulation
//
#define MS_BIT_SHIFT 24 // Can be 24 or 32. Other values are NOT PERMITTED.

#define getInt24(b0, b1, b2, b3) (((int)b2 << 16) | ((int)b1 << 8) | b0)
#define getInt32(b0, b1, b2, b3) ((getInt24(b1, b2, b3, 0) << 8) | b0)
#define MY_CAT1(x, y) MY_CAT2(x, y)
#define MY_CAT2(x, y) x##y

#define MS_BITS(x) ((x) & ~((1l << MS_BIT_SHIFT) - 1))
#define LS_BITS(x) ((x) & ((1l << MS_BIT_SHIFT) - 1))
#define TS_RECORD(x) (x | MY_CAT1(getInt, MS_BIT_SHIFT)(TSMS_EN, '%', '.', 'x'))
#define CHK_TSREC(p)                                                           \
  (*p == TSMS_EN && *(p + 1) == '%' && *(p + 2) == '.' &&                      \
   (MS_BIT_SHIFT == 24 || *(p + 3) == 'x'))
#define GET_TSREC(p) MS_BITS(*(uint64_t *)(p))

#define FULL_TIME
//-------------------------------------------------------------------------------
//
//  Char. codes for syscalls. Codes for entry (exit) end with _EN (resp., _EX)
//

#define CTRL(x) (x-0x40)

#define ARG_LOOKUP_ERR 'A'
#define ACCEPT_EX    'a'
#define BIND_EX      'b'
#define CLOSE_EN     'C'
#define CHDIR_EX     'c'
#define CHMOD_EX     CTRL('C') // chmod and fchmodat
#define DUP2_EX      'D' // dup, dup2, fcntl-based dup; also dup3
#define DUP_EX       'd'
#define FCHDIR_EX    CTRL('D')
#define EXECVE_EN    'E'
#define EXECVE_EX    'e'
#define EXECVEE_EN   CTRL('E')
#define FORK_EN      'F' // fork and vfork
#define FORK_EX      'f'
#define FCHMOD_EX    CTRL('F')
#define SETGID_EX    'G' // setresgid, setregid, setgid
#define GETPEER_EX   'g'
#define LCHOWN_EX    'H' 
#define INITMOD_EX   'I' // init_module
#define FINITMOD_EX  'i' // finit_module
#define PTRACE_EN    'J'
#define PTRACE_EX    'j'
#define KILL_EN      'K' // kill, tkill, tgkill
#define KILL_EX      'k'
#define TS_KERN      CTRL('K')
#define CLONE_EN     'L' // clone and clone3
#define CLONE_EX     'l'
#define LINK_EX      CTRL('L') // link and linkat
#define MOUNT_EX     'M'
#define MKDIR_EX     'm' // mkdir and mkdirat
#define MMAP_EX      CTRL('M')
#define RENAME_EX    'N' // rename and renameat; also renameat2
#define CONNECT_EX   'n'
#define MKNOD_EX     CTRL('N') // mknod , mknodat
#define CHOWN_EX     'O'
#define OPEN_EX      'o' // open, openat, creat
#define FCHOWN_EX    CTRL('O')
#define PREAD_EX     'P' // Also preadv, preadv2
#define PIPE_EX      'p' // Also pipe2
#define MPROTECT_EX  CTRL('P')
#define RMDIR_EX     'R'
#define READ_EX      'r' // Also readv, recvmsg, recvmmsg
#define ERR_REP      CTRL('R')
#define SYMLINK_EX   'S' // symlink and symlinkat
#define SENDTO_EX    's'
#define SOCKPAIR_EX  CTRL('S')
#define FTRUNC_EX    'T'
#define TRUNC_EX     't'
#define TS_DIFF      CTRL('T')
#define SETUID_EX    'U' // setresuid, setreuid, setuid
#define UNLINK_EX    'u' // unlink and unlinkat
#define UMOUNT_EX    CTRL('U')
#define VMSPLICE_EX  'V'
#define RECVFROM_EX  'v'
#define PWRITE_EX    'W' // Also pwritev and pwritev2
#define WRITE_EX     'w' // Also writev, sendmsg, sendmmsg
#define EXIT_EN      'X' // exit
#define EXITGRP_EN   'x' // exit_group
#define TSMS_EN      'y'

#define is_err(ret)                                                            \
  ((-4095 <= ret) && (ret <= -1)) // Interprets syscall ret code.

// Macros related to how id's encode the underlying resource type.

#define FILE_ID                 1
#define PIPE_ID             0b000
#define SELF_NET_ID         0b010
#define LOCAL_NET_ID        0b100
#define FOREIGN_NET_ID      0b110

#define fdtype(id) ((id) & 1? 1 : ((id) & 0x7))
#define isfile(id) (fdtype(id) == FILE_ID)
#define ispipe(id) (fdtype(id) == PIPE_ID)
#define is_self(id) (fdtype(id) == SELF_NET_ID)
#define is_remote(id) (fdtype(id) == FOREIGN_NET_ID)

#define mkid(type, id) \
   (((type)==FILE_ID)? (((id) << 1) | 1) : (((id)<<3)|(type)))
#define getid(id)  (id & 1? (id >> 1) : (id >> 3))

#define INVAL_UID -1
#endif

// Number of bytes that can be signed for system calls.
#define ACCEPT_EX_SB     8
#define BIND_EX_SB       24
#define CHDIR_EX_SB      16
#define CHMOD_EX_SB      32
#define CHOWN_EX_SB      16
#define CLONE_EN_SB      8
#define CLONE_EX_SB      8
#define CLOSE_EN_SB      8
#define CONNECT_EX_SB    24
#define DUP2_EX_SB       16
#define DUP_EX_SB        16
#define EXECVE_EN_SB     64
#define EXECVE_EX_SB     8
#define EXECVEE_EN_SB    64
#define EXIT_EN_SB       8
#define EXITGRP_EN_SB    8
#define FCHDIR_EX_SB     32
#define FCHMOD_EX_SB     16
#define FCHOWN_EX_SB     16
#define FINITMOD_EX_SB   48
#define FORK_EN_SB       8
#define FORK_EX_SB       8
#define FTRUNC_EX_SB     8
#define GETPEER_EX_SB    8
#define INITMOD_EX_SB    8
#define KILL_EN_SB       8
#define KILL_EX_SB       8
#define LCHOWN_EX_SB     32
#define LINK_EX_SB       32
#define MKDIR_EX_SB      32
#define MKNOD_EX_SB      32
#define MMAP_EX_SB       8
#define MPROTECT_EX_SB   8
#define MOUNT_EX_SB      32
#define OPEN_EX_SB       16
#define PIPE_EX_SB       32
#define PREAD_EX_SB      8
#define PTRACE_EN_SB     16
#define PTRACE_EX_SB     8
#define PWRITE_EX_SB     32
#define READ_EX_SB       16
#define RECVFROM_EX_SB   8
#define RENAME_EX_SB     32
#define RMDIR_EX_SB      16
#define SENDTO_EX_SB     16
#define SETGID_EX_SB     8
#define SETUID_EX_SB     16
#define SOCKPAIR_EX_SB   32
#define SYMLINK_EX_SB    32
#define TRUNC_EX_SB      24
#define TS_KERN_SB       32
#define UMOUNT_EX_SB     32
#define UNLINK_EX_SB     16
#define VMSPLICE_EX_SB   32
#define WRITE_EX_SB      8
