#!/usr/bin/python3
# User-space logger bootstrap.

import sys, platform, os, getopt, ctypes
import random, traceback

import signal
import time
import subprocess
import os
import resource
import threading
import math

from bcc import BPF
from time import sleep

def eprint(*args, **kwargs):
    if (globals().get("FLOOD_COMPACT_DEBUG", False)
            and args
            and isinstance(args[0], str)
            and args[0].startswith("[flood]")
            and not args[0].startswith("[flood] root_throttle")):
        return
    print(*args, file=sys.stderr, **kwargs)

#################################################################
# Parse command-line options
#################################################################
def usage():
  lines = ["Usage: " + sys.argv[0] + " <arguments>",
"   -h or --help: print this usage message",
"   -b <bufsz>: max cache size (range: 0.01 to 12KB)",
"   -c [s<n>|o<n>|f<n>]: set the size of the cache (1<<n).",
"       Use this option multiple times to specify multiple parameters.",
"       s<int>: subject cache size exponent",
"       o<int>: object cache size exponent",
"       f<int>: fdinfo and reuse cache size exponent",
"   -C: use percpu message caches", 
"   -d: debug dependencies", 
"   --dlw: Disable last writer feature",
"   --dadpcgroup: disable adaptive polling (use with -P)",
"   -f[doOs][g<n>|m<n>]: turn on filtering of repeated operations.",
"     Use this option multiple times to specify multiple parameters.",
"      d: dependency preserving reduction of reads/write",
"      g<fac>: scale dependency threshold by <fac> (e.g., 1.05) after each read",
"      m<lev>: set maximum value for ver difference threshold (default: 1)",
"      o: dependency preserving reduction across opens, plus above",
"      O: additional instrumentation, plus above",
"      s: reduce based on # of bytes written",
"   -F <int>: Use idle cache flushing algorithm given by <int>",
"          0: no flushing, 1: old algorithm, 2: polling-based, 3: Combined ",
"   -H: use umac3 as mac algorithm for detection",
"   -i: use file descriptors instead of ids.",
"   -m <prefix> or --machine-friendly <prefix>: machine-friendly output format ",
"       where <prefix> is added to parameter names in output", 
"   --no-rem-ver: Disables updating versions for remote objects",
"   -p: add a 8-bit processor id to each record",
"   -P[cg<n>]: turn on cgroup based flood protection. ",
"     cg<n>: set flood cgroup Q_max quota to <n>.",
"   -r <rbufsz>: specify (in MB) ring buffer size (range: 2^n for n in 0..6)",
"   -s: print a summary of system calls made",
"   -S [t<n>|l<n>|s<n>|r<n>]: control the safety valves when reduction is on.",
"       Use this option multiple times to specify multiple parameters.",
"       t<time>: too_long time threshold in s",
"       l<bytes>: too_large byte size exponent (1<<l)",
"       s<bytes>: too_small byte size",
"       r<int>: unreported/reported bytes ratio",
"   -t <time>: max time messages can be cached (range 1K to 16M nanoseconds)",
"   -u[mor]: report unsuccessful system calls.",
"         m: unsuccessful mprotects", 
"         o: unsuccessful opens (includes accepts, connects, etc.)",
"         r: unsuccessful read/writes",
"   -v<level>: set verbosity 0: silent 1: error 2: warning 3: info 4+: debug",
"   -w <winsz>: set ring-buffer push interval (useful range: 1 to 16)", 
"******* Options following a \"--\" are passed to the user level agent *******",
  ];
  eprint("\n".join(lines));
  os._exit(1)

# Set up a few parameters needed by the eBPF probe

# Global options on the use of sequence numbers, caches, etc.
#-------------------------------------------------------------------------------
long_seqnum = False     # True: use 32-bit seq#, else 16-bit sequence #s.
incl_procid = False     # Whether to include a 1-bit CPU # in syscall records
percpu_cache = False    # False: use PERCPU_MAPS for caches, else use normal maps.
max_cache_time = 1<<24  # Force clearing of msg cache after this much time, even
# if it's below size/weight threshold. It is meaningful only if !percpu_cache. 

# Performance-related parameters
#-------------------------------------------------------------------------------
# perf_fac sets the (initial) size (in KB) and weight threshold (approximate
# unit: number of execve calls in the buffer) for the per-CPU cache, i.e., the
# size/weight of cache before it is queued on ring buffer. Additionally, if the
# weight threshold is crossed, ring buffer call will have the wakeup flag set.
# Default perf_fac setting is in the range of p=100 --- somewhat larger for some
# applications, and possibly lower for others. This is because perf_fac is in
# KB, while p is set in number of syscalls.

perf_fac       = 2  # Similar to p parameter.
ringbuf_size   = 64 # in MB
push_interval  = 5  # w parameter value
flush_algo     = 3
tamper_detect  = False
hash_algo      = "umac3" # umac3 as default hashing algorithm
# True: read/writes report a unique id for each file; False: report fd argument.
#-------------------------------------------------------------------------------
ID_NOT_FD                 = True

# @@@@ These masks need to be inferred automatically, based on network config.
# The default values below are likely meaningless. (Used in id generation to
# determine if an IP address is local to an enterprise or remote. This affects
# how frequently we generate a new id for the same network endpoint.)
IP4NETMASK1=0
IP4NETMASK2=0
IP4NETMASK3=0
IP4NETADDR1=1
IP4NETADDR2=1
IP4NETADDR3=1
NS_TO_LOCAL_EP_EPOCH   = 36 # about 1.15 minutes
NS_TO_FOREIGN_EP_EPOCH = 40 # about 18.3 minutes

# Parameters related to suppression of repeated reads and writes.
#-------------------------------------------------------------------------------
filter_rw = False         # no reduction of any kind if this flag is false
filter_dep = False        # dependency based reduction
filter_size = False       # reduction based on # of bytes written
filter_sc_flood = False   # except rdwr, other system calls can generate high
                          # load. We suppress this flooding attack.
debug_dep = False         # Turns on FILTER_REASON to be set in ebpf probe: this
# causes file ids to be replaced by codes indicating reason for recording an op.

# Parameters for finer grained control on dependency reduction.
# @@@@ For simplicity during testing/performance eval, leave these to be
# very large. But later, tune to be more useful/balanced.
TOO_LONG_TIME             = int(1e16) # This is forever!!!
too_long_1s_multiplier    = int(1e9)
# If this much time has passed, force recording next read/write
MED_RDWR_RATIO            =         4; # call it k
# Report each time the total number of bytes increases by 2^k
TOO_LARGE_RDWR_BYTES      =     1<<22; # Should be about 2^{kn} and < 128M
# Force reporting of every read/write larger than this threshold
TOO_SMALL_RDWR_BYTES      =      2048; # Ignore size consideration below this
# If unreported bytes is less than this, ignore the call. (Size-unrelated
# reduction settings may still cause reporting.)

# Parameters related to ADAPTIVE DEPENDENCY based reduction. Read/writes recorded
# if version difference exceeds a threshold. This threshold starts with 1, gets
# multiplied by ver_diff_thresh_fac each time a flow is registered. Threshold
# is capped at too_large_ver_dif. 
#-------------------------------------------------------------------------------
ver_diff_thresh_fac = 1.01; # Threshold incr by this factor on each read or 
too_large_ver_diff = 1;     # write, maxing out at too_large_ver_diff. Setting
                            # it to 1 disables adaptive. ver_thr_shift is used
ver_thr_shift = 11;         # so all arithmetic is on integers.

# Parameters that control repeated open optimization
#-------------------------------------------------------------------------------
filter_open = False       # suppress repeated opens of same file by one process
filter_instrument = False # whether to collect additional statistics on the
# effectiveness of various caches used to implement suppression of opens.
filter_diffpropagation = False # whether to include the difference of the updates
# for last writer propagation.
filter_lastpath = False # whether to include that last path information for
# last writer propagation.
# Parameters to disable/enable features
#-------------------------------------------------------------------------------
disable_lastwriter = False
update_remote_versions = True
disable_adaptive_cgroup = False
# Weights of different system call groups. 
#-------------------------------------------------------------------------------
WT_THRESH      = (1<<10)
WT_CRITICAL    = (WT_THRESH+1)
WT_IMPORTANT   = (WT_THRESH >> 1)
WT_ENDPOINT    = (WT_THRESH >> 5)
WT_DGRAM       = (WT_THRESH >> 6)
WT_FDTRACK     = (WT_THRESH >> 7)
WT_RDWR        = (WT_THRESH >> 8)
WT_UNIMPORTANT = (WT_THRESH >> 9)
WT_REDUNDANT   = (WT_THRESH >> 10)

# The following are used to set the sizes of various caches. Should tune further
# after some deployment experience.
#-------------------------------------------------------------------------------
max_tasks = 1<<13;
max_objs = 1<<16;
max_fds  = 1<<14;
temp_cache_sz = 1<<14;
fdi_reuse_sz = 1<<14;

# Syscall flood mitigation via userspace throttling.
#-----------------------------------------------------------------------------
if os.environ.get("EAUDIT_FLOOD_CGROUP"):
    FLOOD_CGROUP_PATH = os.environ.get("EAUDIT_FLOOD_CGROUP")
elif os.path.exists("/sys/fs/cgroup/cpu"):
    FLOOD_CGROUP_PATH = "/sys/fs/cgroup/cpu/eaudit_flood"
elif os.path.exists("/sys/fs/cgroup/cpu,cpuacct"):
    FLOOD_CGROUP_PATH = "/sys/fs/cgroup/cpu,cpuacct/eaudit_flood"
else:
    FLOOD_CGROUP_PATH = "/sys/fs/cgroup/eaudit_flood"

# Density-based throttling parameters (syscalls per CPU-second).
# B = empirical benign ceiling (highest sustained density a benign workload exhibits).
# C = pipeline drain rate (above which the audit pipeline starts losing events).
# A = attacker-induced peak rate under unconstrained Attack-2 floods.
# Calibrated on our test platform; override per deployment.
FLOOD_B = 500_000
FLOOD_C = 1_000_000
FLOOD_A = 22_000_000   # informational; not used in the formula, kept for documentation
FLOOD_X = 4            # margin factor: theta sits 1/X of the way from B toward C
FLOOD_W_NS = 100_000_000  # 100 ms window
# Minimum accumulated CPU time before a density measurement is considered valid.
# Short bursts (e.g., connection setup in a web server) can have instantaneous
# rho >> theta but are not sustained attacks.  Requiring at least this much CPU
# time per window prevents one-shot bursts from triggering false alerts while
# still catching attackers that run continuously (they accumulate this in <10ms).
FLOOD_MIN_CPU_NS = 1_000_000  # 1 ms minimum CPU time before density check
FLOOD_MIN_COUNT = 1000        # Ignore tiny one-shot syscall bursts.
# Benign threshold: read/write/open-heavy workloads topped out below this in
# calibration.  Raise it if legitimate high-throughput programs (databases,
# streaming encoders) still get flagged on this host.
FLOOD_THETA = 100_000
# Sentinel syscalls (kill, mprotect, mmap, clone, fork, vfork, execve,
# execveat, setuid, setgid, tkill, tgkill, clone3) are rarely called at high
# rates by benign programs.  A separate, lower density threshold lets us catch
# moderate-rate sentinel floods (e.g. a kill() storm at 1000 calls/CPU-second)
# without lowering the main FLOOD_THETA and throttling legitimate I/O-heavy
# workloads.  The kernel emits a candidate alert when sentinel density exceeds
# FLOOD_THETA_SENTINEL; userspace validates with FLOOD_AGG_MIN_SENTINEL_RHO +
# cpu_util before moving the process to the flood cgroup.
FLOOD_THETA_SENTINEL = 2000        # kernel: emit alert if sentinel_rho > this
FLOOD_MIN_SENTINEL_COUNT = 3   # ignore windows with fewer sentinel calls
# Fast sentinel path: allow attack-typical syscalls to alert before the full
# 100ms window rolls.  This uses kernel timestamps/counters only.
FLOOD_MIN_SENTINEL_CPU_NS = 100_000      # 0.1ms CPU is enough for sentinel-only alerts
FLOOD_SENTINEL_FAST_MIN_NS = 1_000_000   # 1ms of kernel-window elapsed time
FLOOD_THETA_SENTINEL_REL = max(1, FLOOD_THETA_SENTINEL // 2)
# Userspace sanity gate for sentinel alerts.  Should be >= FLOOD_THETA_SENTINEL
# so that kernel candidates are not accepted wholesale; set equal by default.
FLOOD_AGG_MIN_SENTINEL_RHO = FLOOD_THETA_SENTINEL
# Group-level sentinel rate above which a parent tree is throttled even when
# no individual child crosses FLOOD_AGG_MIN_SENTINEL_RHO on its own.
# Calibrate: a 384-thread kill-flood produces ~50K-100K sentinel calls/sec
# collectively; a make -j384 build produces <10K sentinel calls/sec.
FLOOD_AGG_MIN_GROUP_SENTINEL_WALL_RATE = 10_000
FLOOD_AGG_SENTINEL_TRIGGER_WINDOWS = 1
FLOOD_ALPHA = 0.2
if FLOOD_ALPHA <= 0:
    FLOOD_ALPHA = 1.0
# Release only after the workload has returned to the benign region for several
# windows.  Using A here is backwards: A is the attacker peak, so almost every
# throttled attack window would look "recovered" and cause release/re-trigger
# oscillation.
FLOOD_THETA_REL = 100
if FLOOD_THETA_REL < 1:
    FLOOD_THETA_REL = 1
FLOOD_AGG_MIN_CHILDREN = 3
# A child qualifies as a "direct contributor" when its per-CPU syscall density
# (rho) is suspicious AND it is actually CPU-saturated during the window.
# The cpu_util check (cpu_ns/wall_ns) is the key discriminator: benign I/O-heavy
# processes (e.g. tar) block on disk ~30-50% of the time, giving cpu_util 50-70%;
# an attacker calling kill() in a tight loop burns almost all of its CPU, giving
# cpu_util 90%+.  Requiring both rho > 100K AND cpu_util > 80% cleanly separates
# the two without ever touching each other's region in the data.
FLOOD_AGG_MIN_RHO = 100_000
FLOOD_AGG_MIN_CPU_UTIL = 0.80       # 80% cpu_ns/wall_ns; kill≈92%, tar≈54-74%
# Distributed fanout is a group-level signal: no one child has to cross the
# per-pid density threshold if the subtree as a whole is already suspicious.
FLOOD_AGG_MIN_GROUP_WALL_RATE = FLOOD_C
# Some adversarial syscalls consume enough CPU that CPU-normalized rho can stay
# below theta even while wall-clock event volume overwhelms the audit pipeline.
# A child can therefore also qualify as misbehaving by its own wall-clock rate,
# but the parent still needs at least FLOOD_AGG_MIN_CHILDREN such children.
FLOOD_AGG_MIN_CHILD_WALL_RATE = 100_000
# High-fanout attack (e.g. run_kill 384): each child makes so few syscalls per
# window (count < FLOOD_MIN_COUNT) that it is filtered from distributed_contributors,
# yet the collective group wall rate still overwhelms the pipeline.  When a root
# has at least this many active children AND group_wall_rate exceeds the threshold,
# treat it as a distributed flood regardless of per-child count.
FLOOD_AGG_HIGH_FANOUT_CHILDREN = 3
# Slow distributed attack (e.g. run_kill 384 20844): each child generates so
# few syscalls per window that group_wall_rate stays below 1M, but killcode
# children run for tens of seconds and therefore each complete multiple 100ms
# kernel windows.  info["children"] only holds processes with last_win_end > 0
# (alive > FLOOD_W_NS = 100ms), so short-lived benign children (run_tar 384 1,
# each tar exits in ~10ms) are naturally absent.  Throttle when this long-lived
# child count exceeds the floor, regardless of per-child or group rate.
FLOOD_AGG_LONG_LIVED_FANOUT_CHILDREN = 50
FLOOD_AGG_RELEASE_WINDOWS = 3
# Require this many consecutive overloaded kernel windows before committing to
# aggregate throttling.  Benign bursty workloads (e.g. tar, database flush) can
# momentarily look like floods for 1-2 windows and then recover; attackers
# sustain the signal indefinitely.  Set equal to FLOOD_AGG_RELEASE_WINDOWS so
# trigger and release are symmetric (both require ~300 ms of sustained state).
FLOOD_AGG_TRIGGER_WINDOWS = 3

# cgroup_q_max is the upper bound for the adaptive quota rule and the first
# finite quota applied after a process is moved into the flood cgroup.
cgroup_q_max = 200000          # Default Q_max: 2.0 CPUs
CGROUP_PERIOD = 100000         # cgroup v2 period (always 100ms)
# Linux rejects CFS quotas below 1ms. This is not a policy Q_min; it is only
# the smallest value we can legally write to cpu.max/cpu.cfs_quota_us.
CGROUP_QUOTA_WRITE_MIN = 1000

_throttled_procs = {} # PID -> {current_quota, last_rho}
_total_throttled_procs = 0
_flood_cgroup_ready = False
_flood_alerts_map = None
_proc_state_map = None
_flood_dbg_map = None
_flood_poller = None
_flood_stop = threading.Event()
_current_cgroup_quota = 0         # Currently applied quota in cpu.max
_flood_debug_last_ns = 0
_flood_sample_last_ns = 0
_aggregate_debug_last_ns = 0
_aggregate_root_quota = {}
_aggregate_release_streak = {}
_aggregate_trigger_streak = {}  # root_pid -> consecutive overloaded-window count (pre-throttle)
_aggregate_root_mode = {}       # root_pid -> "sentinel" or "density"
_fast_root_alerts = {}  # (root_pid, uid) -> alerts from the last kernel 100ms
_proc_kernel_window_seen = {}
_throttle_kernel_window_seen = {}  # PID -> last completed kernel window consumed by throttling
_flood_sample_kernel_window_seen = {}
_FLOOD_SAMPLE_NAME_ENV = (
    os.environ.get("EAUDIT_FLOOD_SAMPLE_NAMES")
    if os.environ.get("EAUDIT_FLOOD_SAMPLE_NAMES") is not None
    else os.environ.get("EAUDIT_WATCH_NAMES", "")
)
FLOOD_SAMPLE_NAMES = {
    name.strip()
    for name in _FLOOD_SAMPLE_NAME_ENV.split(",")
    if name.strip()
}
# Default to compact flood logs: suppress noisy proc_state/aggregate/quota
# chatter. Set EAUDIT_FLOOD_COMPACT=0 to enable all flood debug output.
# Set EAUDIT_FLOOD_WINDOW=1 to enable per-process window density samples.
FLOOD_COMPACT_DEBUG = (
    os.environ.get("EAUDIT_FLOOD_COMPACT", "1").lower()
    not in ("0", "false", "")
)
FLOOD_WINDOW_DEBUG = (
    os.environ.get("EAUDIT_FLOOD_WINDOW", "0").lower()
    not in ("0", "false", "")
)
FLOOD_TOTAL_SAMPLE_ONLY = (
    os.environ.get("EAUDIT_FLOOD_TOTAL_SAMPLE_ONLY", "0").lower()
    not in ("0", "false", "")
)

# Other key parameters that don't need further documentation.
#-------------------------------------------------------------------------------
machine_friendly = ""

# Some parameters useful for debugging and/or to get more info
#-------------------------------------------------------------------------------
verbosity = 2
prt_summary = False
REPORT_MMAP_ERRS          = False
REPORT_RDWR_ERRS          = False
REPORT_OPEN_ERRS          = False
#parameters for key generation
#-------------------------------------------------------------------------------
KEY_SIZE = 16
# TOTAL_KEYS = 1048576
TOTAL_KEYS = 65536
clib = "./ecapd.so"
ebpf_prog = "eauditk.c"

try:
    opts, user_args = getopt.getopt(sys.argv[1:], "b:CdF:f:iHhl:m:P:pr:st:u:v:w:S:c:I:",
                               ["help", "dlw", "no-rem-ver", "dadpcgroup"])

    for opt, val in opts:
        if opt == "-b":
            perf_fac = float(val);
            if perf_fac < 0.01 or perf_fac > 12:
                eprint("Invalid value for per-cpu buffer size (0.01 to 12)")
                sys.exit(1)
        elif opt == "-c":
            if val.find("s") >= 0:
                exp = int(val[val.find("s")+1:])
                max_tasks = 1<<exp
            elif val.find("o") >= 0:
                exp = int(val[val.find("o")+1:])
                max_objs = 1<<exp
            elif val.find("f") >= 0:
                exp = int(val[val.find("f")+1:])
                max_fds = 1<<exp
                temp_cache_sz = max_fds
                fdi_reuse_sz = max_fds
        elif opt == "-C":
            percpu_cache = not percpu_cache;
        elif opt == "-d":
            debug_dep=True
        elif opt == "--dlw":
            disable_lastwriter = True
        elif opt == "--dadpcgroup":
            disable_adaptive_cgroup = True

        elif opt == "-f":
            filter_rw = True; 
            if val.find("d") >= 0:
                filter_dep = True
                # filter_sc_flood = True
            if val.find("o") >= 0 or val.find("O") >= 0:
                filter_dep = filter_open = True
                # filter_sc_flood = True
                # filter_diffpropagation = True
                if val.find("O") >= 0:
                    filter_instrument = True;
            if val.find("s") >= 0:
                filter_size = True;
            # Each -f can have at most one of the following options
            if val.find("g") >= 0:
                ver_diff_thresh_fac = float(val[val.find("g")+1:])
            elif val.find("m") >= 0:
                too_large_ver_diff = int(val[val.find("m")+1:])
            if val.find("u") >= 0:
                filter_dep = filter_diffpropagation = True;
                eprint("Diff propagation enabled");
            if val.find("p") >= 0:
                filter_lastpath = True;
        elif opt == "-F":
                flush_algo = int(val);
                if (flush_algo < 0 or flush_algo > 3):
                    eprint("Invalid cache flushing option");
        elif opt in {"-h", "--help"}:
            usage()
        elif opt == "-H":
            tamper_detect = True
            hash_algo = "UMAC3"
        elif opt == "-i":
            ID_NOT_FD=False
        elif opt == "-l":
            clib = val
        elif opt in {"-m", "--machine-friendly"}:
            machine_friendly = val
        elif opt == "--no-rem-ver":
            update_remote_versions = False
        elif opt == "-p":
            incl_procid = not incl_procid
        elif opt == "-P":
             filter_sc_flood = True
             filter_rw = True  # Required for subject tracking infrastructure
             if val.startswith("cg"):
                  try:
                      cgroup_q_max = int(val[2:])
                  except ValueError:
                      eprint("Invalid -P format. Use -Pcg<number>.")
                      sys.exit(1)
             else:
                  eprint("Invalid -P format. Use -Pcg<number>.")
                  sys.exit(1)

        elif opt == "-r":
            ringbuf_size = int(val);
            if ringbuf_size not in {1,2,4,8,16,32,64,96,128,160,192,224,256,1024}:
                eprint("Ring buffer size should be 1,2,4,8,16, or 32n for n<=8")
                sys.exit(1)
        elif opt == "-s":
            prt_summary = True
        elif opt == "-S":
            if val.find("t") >= 0:
                too_long = float(val[val.find("t")+1:])
                TOO_LONG_TIME = int(too_long_1s_multiplier * too_long)
            elif val.find("r") >= 0:
                MED_RDWR_RATIO = int(val[val.find("r")+1:]) - 1
                if MED_RDWR_RATIO < 1 or MED_RDWR_RATIO > 63:
                    eprint("For -Sr, use any integral ratio between 2 and 64");
            elif val.find("l") >= 0:
                exp = int(val[val.find("l")+1:])
                TOO_LARGE_RDWR_BYTES = 1<<exp
            elif val.find("s") >= 0:
                TOO_SMALL_RDWR_BYTES = int(val[val.find("s")+1:])
        elif opt == "-t":
            max_cache_time = int(val)
            if max_cache_time < 1000:
                eprint("maximum message cache time must be over 1000")
                max_cache_time = 1000;
            if max_cache_time > (1 << 24):
                eprint("maximum message cache time must be under 16M")
                max_cache_time = 1 << 24;
        elif opt == "-u":
            if val.find("m") >= 0:
                REPORT_MMAP_ERRS=True
            if val.find("o") >= 0:
                REPORT_OPEN_ERRS=True
            if val.find("r") >= 0:
                REPORT_RDWR_ERRS=True                
        elif opt == "-v":
            verbosity = int(val)
        elif opt == "-w":
            push_interval = int(val);
            if push_interval < 1 or push_interval > 16:
                eprint("Invalid value for ring buffer push interval (1..16)")
                sys.exit(1)
        else: usage()

except getopt.GetoptError as err:
    eprint(err)
    usage()

except:
    eprint("Invalid options.");
    usage()

if (clib is None):
    eprint("Do not invoke directly; use the provided wrapper script")
    sys.exit(1)

if (too_large_ver_diff < 1 or too_large_ver_diff >= 64):
   eprint("Maximum version difference threshold should in the range 1-63");
   sys.exit(1)

if (too_large_ver_diff >= 32):
    ver_thr_shift = 10;

if (ver_diff_thresh_fac >= 2.0):
    eprint("Overflow:  parameter to -g option should be less than 2.0");
    sys.exit(1);

ver_diff_thresh_fac = round(ver_diff_thresh_fac * (1 << ver_thr_shift))
if (ver_diff_thresh_fac <= (1 << ver_thr_shift)):
    eprint("Underflow: parameter to -g option should be at least %g" %
           (1 + 1.0/(1<<ver_thr_shift)));
    sys.exit(1);

#################################################################
# Set up the C++ library to which we output ebpf data
#################################################################
try:
    provider = ctypes.cdll.LoadLibrary(clib)
except OSError:
    eprint("Unable to load the system C library")
    traceback.print_exc(file=sys.stderr)
    sys.exit()

logprinter = provider.logprinter
logprinter.argtypes = [ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64]
logprinter.restype = ctypes.c_long

init_logger = provider.init_logger
init_logger.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_char_p)]
init_logger.restype = ctypes.c_long

nread = provider.nread
nread.argtypes = None
nread.restype = ctypes.c_long

nwritten = provider.nwritten
nwritten.argtypes = None
nwritten.restype = ctypes.c_long

do_write = provider.dowrite
do_write.argtypes = None
do_write.restype = ctypes.c_long

ncalls = provider.calls
ncalls.argtypes = None
ncalls.restype = ctypes.c_long

end_op = provider.end_op
end_op.argtypes = None
end_op.restype = ctypes.c_long

#################################################################
# Set up support functions needed before we load the ebpf code
#################################################################
class GracefulKiller:
    kill_now = False
    def __init__(self):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, *args):
        self.kill_now = True

    def ignore_sig(self, *args):
        pass

killer = GracefulKiller()

def ppf2(n):
    if (n < 10):
        return "0" + str(n)
    else: return str(n)

def pp(n):
    if n < 1000: return str(n);
    if n < 1000000: return str(n//1000)+"."+ ppf2((n % 1000)//10)+"K"
    if n < 1000000000: return str(n//1000000)+"."+ppf2((n % 1000000)//10000)+"M"
    if n < 1000000000000: 
        return str(n//1000000000)+"."+ppf2((n % 1000000000)//10000000)+"G"

################################################################################
# Set up functions to add flooding process into throttled CGROUP
################################################################################

def _flood_cpu_quota_path():
    """Return the active CPU quota file and whether it uses the cgroup v1 layout."""
    quota_v1 = os.path.join(FLOOD_CGROUP_PATH, "cpu.cfs_quota_us")
    period_v1 = os.path.join(FLOOD_CGROUP_PATH, "cpu.cfs_period_us")
    if os.path.exists(quota_v1) or os.path.exists("/sys/fs/cgroup/cpu"):
        return (quota_v1, period_v1), True
    return (os.path.join(FLOOD_CGROUP_PATH, "cpu.max"), None), False


def _write_flood_cpu_quota(quota):
    """Write the shared flood-cgroup CPU quota for either cgroup v1 or v2."""
    (quota_path, period_path), is_v1 = _flood_cpu_quota_path()
    if quota != "max":
        quota = max(int(quota), CGROUP_QUOTA_WRITE_MIN)
    if is_v1:
        with open(quota_path, "w", encoding="utf-8") as quota_file:
            quota_file.write("-1\n" if quota == "max" else f"{quota}\n")
        with open(period_path, "w", encoding="utf-8") as period_file:
            period_file.write(f"{CGROUP_PERIOD}\n")
        return

    with open(quota_path, "w", encoding="utf-8") as quota_file:
        quota_file.write(f"{quota} {CGROUP_PERIOD}\n")


def _flood_parent_procs_path():
    """Return the parent cgroup's process file used to release throttled tasks."""
    return os.path.join(os.path.dirname(FLOOD_CGROUP_PATH.rstrip("/")), "cgroup.procs")


def _ensure_flood_cgroup():
    """Create the shared flood cgroup and initialize its CPU quota."""
    global _flood_cgroup_ready

    if _flood_cgroup_ready:
        return True

    try:
        os.makedirs(FLOOD_CGROUP_PATH, exist_ok=True)
    except OSError as exc:
        eprint(f"Failed to create flood cgroup at {FLOOD_CGROUP_PATH}: {exc}")
        return False

    # Clean up leftover child cgroup directories from old tier system.
    # cgroup v2 "no internal processes" rule: can't write PIDs to a parent
    # that has child sub-cgroups. Remove heavy/, moderate/, low/ if they exist.
    for old_child in ["heavy", "moderate", "low"]:
        old_path = os.path.join(FLOOD_CGROUP_PATH, old_child)
        if os.path.isdir(old_path):
            try:
                # First move any processes out of the child cgroup
                child_procs = os.path.join(old_path, "cgroup.procs")
                parent_procs = os.path.join(FLOOD_CGROUP_PATH, "cgroup.procs")
                if os.path.exists(child_procs):
                    with open(child_procs, "r") as f:
                        for line in f:
                            pid_str = line.strip()
                            if pid_str:
                                try:
                                    with open(parent_procs, "w") as pf:
                                        pf.write(f"{pid_str}\n")
                                except OSError:
                                    pass
                os.rmdir(old_path)
                eprint(f"[flood] Cleaned up old child cgroup: {old_path}")
            except OSError as exc:
                eprint(f"[flood] Warning: could not remove old child cgroup {old_path}: {exc}")

    # Start unrestricted; finite Q_max is applied only after the first alert.
    try:
        _write_flood_cpu_quota("max")
        eprint(f"[flood] Cgroup initialized: {FLOOD_CGROUP_PATH} cpu_quota=max/{CGROUP_PERIOD}")
    except OSError as exc:
        eprint(f"Unable to configure cpu quota for flood cgroup: {exc}")
        return False

    _flood_cgroup_ready = True
    return True

import queue
from collections import defaultdict

_cgroup_write_queue = queue.Queue()
_parent_flood_counts = defaultdict(int)
_parent_throttled = set()
_pid_root_parent = {}
_parent_active_children = defaultdict(set)
_PROTECTED_PARENTS = {"bash", "sh", "zsh", "sshd", "systemd", "tmux", "screen", "sudo", "su", "init"}

def _get_process_info(pid):
    """Retrieve Tgid, PPid, and process Name from /proc/<pid>/status"""
    try:
        tgid = ppid = name = None
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("Name:"):
                    name = line.split()[1].strip()
                elif line.startswith("Tgid:"):
                    tgid = int(line.split()[1])
                elif line.startswith("PPid:"):
                    ppid = int(line.split()[1])
                if tgid is not None and ppid is not None and name is not None:
                    break
        return tgid, ppid, name
    except (FileNotFoundError, IndexError, OSError, ValueError):
        return None, None, None

def _get_process_uid(pid):
    """Return the real UID from /proc/<pid>/status, or None if the task vanished."""
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("Uid:"):
                    return int(line.split()[1])
    except (FileNotFoundError, IndexError, OSError, ValueError):
        return None
    return None


def _process_is_active(pid):
    """Return false for missing or zombie processes."""
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("State:"):
                    parts = line.split()
                    return len(parts) < 2 or parts[1] != "Z"
    except (FileNotFoundError, IndexError, OSError, ValueError):
        return False
    return True


def _read_proc_children(pid):
    """Read direct children from procfs without scanning all /proc."""
    children_path = f"/proc/{pid}/task/{pid}/children"
    try:
        with open(children_path, "r", encoding="utf-8") as children_file:
            data = children_file.read().strip()
    except OSError:
        return []
    if not data:
        return []
    children = []
    for pid_str in data.split():
        try:
            child_pid = int(pid_str)
        except ValueError:
            continue
        if child_pid > 0:
            children.append(child_pid)
    return children


def _queue_root_descendants(root_pid, mode):
    """Immediately enqueue all current descendants of a throttled root."""
    queued = 0
    seen = set()
    stack = [root_pid]
    while stack and len(seen) < max_tasks:
        parent_pid = stack.pop()
        for child_pid in _read_proc_children(parent_pid):
            if child_pid in seen:
                continue
            seen.add(child_pid)
            stack.append(child_pid)
            if child_pid == os.getpid() or not _process_is_active(child_pid):
                continue
            if child_pid in _parent_active_children[root_pid]:
                continue
            _parent_active_children[root_pid].add(child_pid)
            _pid_root_parent[child_pid] = root_pid
            child_info = _throttled_procs.setdefault(child_pid, {
                "current_quota": cgroup_q_max,
                "last_rho": 0,
                "aggregate_root": root_pid,
            })
            child_info["aggregate_root"] = root_pid
            child_info["mode"] = mode
            _cgroup_write_queue.put(child_pid)
            queued += 1
    if _parent_active_children[root_pid]:
        _parent_flood_counts[root_pid] = len(_parent_active_children[root_pid])
    return queued


def _cgroup_writer_worker():
    """Background thread that batch-migrates PIDs to the flood cgroup."""
    cgroup_procs_path = os.path.join(FLOOD_CGROUP_PATH, "cgroup.procs")
    while not _flood_stop.is_set():
        # Block for the first PID, then drain whatever is already queued.
        # Do not wait to fill a batch: aggregate throttling is latency-sensitive.
        batch = []
        while len(batch) < 64:
            try:
                if not batch:
                    batch.append(_cgroup_write_queue.get(timeout=0.1))
                else:
                    batch.append(_cgroup_write_queue.get_nowait())
            except queue.Empty:
                break

        if not batch:
            continue

        for pid in batch:
            try:
                t1 = time.monotonic_ns()
                with open(cgroup_procs_path, "w") as f:
                    f.write(f"{pid}\n")
                t2 = time.monotonic_ns()
                eprint(f"[flood] cgroup migrate pid={pid} write_ms={(t2-t1)/1_000_000:.3f}")
            except ProcessLookupError:
                pass
            except OSError as exc:
                eprint(f"Failed to throttle PID {pid}: {exc}")
            finally:
                _cgroup_write_queue.task_done()

def _untrack_child_from_parent(pid):
    """Remove a child PID from parent flood accounting when it is released or exits."""
    root_pid = _pid_root_parent.pop(pid, None)
    if root_pid is None:
        return

    active_children = _parent_active_children.get(root_pid)
    if active_children is None:
        return

    active_children.discard(pid)
    if active_children:
        _parent_flood_counts[root_pid] = len(active_children)
    else:
        _parent_active_children.pop(root_pid, None)
        _parent_flood_counts.pop(root_pid, None)

def _find_root_coordinator(pid):
    """Find the highest non-protected ancestor used for aggregate throttling."""
    tgid, ppid, name = _get_process_info(pid)
    if tgid is None:
        return None, None, None, None, None

    current_ancestor = tgid if tgid != pid else ppid
    root_coordinator_pid = None
    root_coordinator_name = None

    while current_ancestor and current_ancestor > 1:
        _, a_ppid, a_name = _get_process_info(current_ancestor)
        if not a_name or (a_name in _PROTECTED_PARENTS and a_name != name):
            break
        root_coordinator_pid = current_ancestor
        root_coordinator_name = a_name
        current_ancestor = a_ppid

    return root_coordinator_pid, root_coordinator_name, tgid, ppid, name

def _apply_dynamic_quota(new_quota, force=False, reason=""):
    """Dynamically update cpu.max of the shared flood cgroup without moving processes."""
    global _current_cgroup_quota

    if not force and new_quota == _current_cgroup_quota:
        return

    try:
        t1 = time.monotonic_ns()
        _write_flood_cpu_quota(new_quota)
        _current_cgroup_quota = new_quota
        t2 = time.monotonic_ns()
        (quota_path, _period_path), _is_v1 = _flood_cpu_quota_path()
        actual = "unread"
        try:
            with open(quota_path, "r", encoding="utf-8") as quota_file:
                actual = quota_file.read().strip()
        except OSError as exc:
            actual = f"read_error:{exc}"
        suffix = f" reason={reason}" if reason else ""
        eprint(
            f"[flood] quota update quota={new_quota}/{CGROUP_PERIOD} "
            f"actual='{actual}' path={quota_path} write_ms={(t2-t1)/1_000_000:.3f}{suffix}"
        )
    except OSError as e:
        eprint(f"[flood] Failed to update cpu_quota to {new_quota}: {e}")

def _release_pid_cgroup(pid):
    """Move a pid out of the flood cgroup once it stops flooding."""
    try:
        with open(_flood_parent_procs_path(), "w", encoding="utf-8") as parent_file:
            parent_file.write(f"{pid}\n")
        eprint(f"[flood] Released PID {pid} from {FLOOD_CGROUP_PATH}")
    except OSError as exc:
        eprint(f"Failed to release pid {pid} from flood cgroup: {exc}")


def _active_aggregate_quota():
    """Return the strictest active aggregate quota, or None if no aggregate throttle."""
    if not _aggregate_root_quota:
        return None
    return min(_aggregate_root_quota.values())


def _quota_from_observed_rate(current_quota, observed_rate, theta=None):
    """Apply alpha * theta / observed_rate as a monotone quota decrease."""
    current_quota = max(0, int(current_quota))
    observed_rate = int(observed_rate)
    if theta is None:
        theta = FLOOD_THETA
    if observed_rate <= 0:
        scale = 1.0
    else:
        scale = min(1.0, (FLOOD_ALPHA * theta) / observed_rate)

    raw_q = int(current_quota * scale)
    new_q = raw_q
    if new_q > cgroup_q_max:
        new_q = cgroup_q_max
    if new_q < CGROUP_QUOTA_WRITE_MIN:
        new_q = CGROUP_QUOTA_WRITE_MIN
    return new_q, raw_q, scale


def _flood_cpu_util(cpu_ns, wall_ns):
    if wall_ns <= 0:
        return 0.0
    return cpu_ns / wall_ns


def _alert_is_direct_flood(alert_count, alert_cpu_ns, alert_rho, alert_wall_ns,
                           alert_sentinel_count=0):
    """Userspace sanity check before any cgroup move from a kernel alert.

    Two independent paths can qualify an alert:
    1. Total density: rho > FLOOD_AGG_MIN_RHO with cpu_util > threshold (existing).
    2. Sentinel density: sentinel_rho > FLOOD_AGG_MIN_SENTINEL_RHO with cpu_util >
       threshold.  This catches moderate-rate floods using attack-typical syscalls
       (kill, mprotect, clone, execve, etc.) that stay below the total-density gate.
    """
    cpu_util = _flood_cpu_util(alert_cpu_ns, alert_wall_ns)
    if (alert_count >= FLOOD_MIN_COUNT and
            alert_cpu_ns >= FLOOD_MIN_CPU_NS and
            alert_rho >= FLOOD_AGG_MIN_RHO and
            cpu_util >= FLOOD_AGG_MIN_CPU_UTIL):
        return True
    if alert_cpu_ns > 0 and alert_sentinel_count >= FLOOD_MIN_SENTINEL_COUNT:
        sentinel_rho = (alert_sentinel_count * 1_000_000_000) // alert_cpu_ns
        if (sentinel_rho >= FLOOD_AGG_MIN_SENTINEL_RHO and
                cpu_util >= FLOOD_AGG_MIN_CPU_UTIL):
            return True
    return False


def _cleanup_fast_root_alerts(current_ts_ns):
    """Keep only alert entries inside the last kernel 100ms interval."""
    cutoff_ns = current_ts_ns - FLOOD_W_NS
    for key, bucket in list(_fast_root_alerts.items()):
        children = bucket.get("children", {})
        for child_pid, child in list(children.items()):
            if child.get("ts_ns", 0) < cutoff_ns:
                children.pop(child_pid, None)
        if not children:
            _fast_root_alerts.pop(key, None)


def _clear_fast_root_alerts(root_pid):
    """Drop fast-path alert buckets for a root that was released or vanished."""
    for key in list(_fast_root_alerts):
        if key[0] == root_pid:
            _fast_root_alerts.pop(key, None)


def _maybe_fast_root_throttle(pid, root_pid, root_name, name,
                              alert_count, alert_cpu_ns, alert_rho,
                              alert_wall_ns, ts_ns, alert_sentinel_count=0):
    """Throttle a root immediately when enough children alert within 100ms.

    This runs in the 1ms alert-drain loop.  It deliberately uses only O(1)
    bucket updates per alert: the expensive full proc_state scan remains in the
    aggregate poller as a fallback.  To avoid benign fanout, fast root throttling
    requires distinct children from the same UID inside the last kernel 100ms.

    Root throttling is gated on sentinel syscall activity only.  A benign process
    that individually spikes above FLOOD_THETA on read/write calls may get its own
    cgroup quota adjusted, but its parent tree is never pulled in — only attack-
    typical syscalls (kill, mprotect, chmod, etc.) qualify a child for root
    escalation.
    """
    if root_pid is None or root_pid == pid or root_pid in _parent_throttled:
        return False
    if not root_name or root_name in _PROTECTED_PARENTS:
        return False
    if ts_ns <= 0:
        return False
    # Sentinel gate: the child must have triggered via sentinel syscalls, not just
    # via total density on benign read/write calls.
    if alert_cpu_ns <= 0 or alert_sentinel_count < FLOOD_MIN_SENTINEL_COUNT:
        return False
    sentinel_rho = (alert_sentinel_count * 1_000_000_000) // alert_cpu_ns
    if sentinel_rho < FLOOD_AGG_MIN_SENTINEL_RHO:
        return False
    if _flood_cpu_util(alert_cpu_ns, alert_wall_ns) < FLOOD_AGG_MIN_CPU_UTIL:
        return False

    pid_uid = _get_process_uid(pid)
    root_uid = _get_process_uid(root_pid)
    if pid_uid is None or root_uid is None or pid_uid != root_uid:
        return False

    window_id = ts_ns // FLOOD_W_NS
    _cleanup_fast_root_alerts(ts_ns)

    bucket_key = (root_pid, pid_uid)
    bucket = _fast_root_alerts.setdefault(bucket_key, {
        "root_name": root_name,
        "children": {},
    })
    bucket["children"][pid] = {
        "name": name,
        "rho": alert_rho,
        "count": alert_count,
        "cpu_ns": alert_cpu_ns,
        "wall_ns": alert_wall_ns,
        "sentinel_count": alert_sentinel_count,
        "sentinel_wall_rate": ((alert_sentinel_count * 1_000_000_000) // alert_wall_ns
                               if alert_wall_ns > 0 else 0),
        "ts_ns": ts_ns,
    }

    children = bucket["children"]
    if len(children) < FLOOD_AGG_MIN_CHILDREN:
        return False

    sum_count = sum(child["count"] for child in children.values())
    sum_cpu_ns = sum(child["cpu_ns"] for child in children.values())
    sum_sentinel_count = sum(child.get("sentinel_count", 0) for child in children.values())
    control_rho = ((sum_count * 1_000_000_000) // sum_cpu_ns
                   if sum_cpu_ns > 0 else max(alert_rho, 1))
    sentinel_control_rho = ((sum_sentinel_count * 1_000_000_000) // sum_cpu_ns
                            if sum_cpu_ns > 0 else 0)
    initial_control_rho = max(sentinel_control_rho, 1)
    initial_q, raw_q, scale = _quota_from_observed_rate(
        cgroup_q_max,
        initial_control_rho,
        FLOOD_THETA_SENTINEL,
    )

    if not _ensure_flood_cgroup():
        return False

    _parent_throttled.add(root_pid)
    _parent_flood_counts[root_pid] = len(children)
    _aggregate_root_quota[root_pid] = initial_q
    _aggregate_release_streak[root_pid] = 0
    _aggregate_root_mode[root_pid] = "sentinel"
    _aggregate_trigger_streak.pop(root_pid, None)

    _apply_dynamic_quota(initial_q, force=True, reason="fast_root_alert")
    _cgroup_write_queue.put(root_pid)

    child_preview_rows = sorted(
        children.items(),
        key=lambda item: item[1]["rho"],
        reverse=True,
    )
    child_preview = ", ".join(
        f"{child_pid}:{child['name']}:rho={child['rho']}:count={child['count']}:"
        f"cpu_ns={child['cpu_ns']}:sentinel_count={child.get('sentinel_count', 0)}:"
        f"sentinel_wall={child.get('sentinel_wall_rate', 0)}:"
        f"cpu_util={_flood_cpu_util(child['cpu_ns'], child['wall_ns']):.3f}"
        for child_pid, child in child_preview_rows[:8]
    )
    eprint(
        f"[flood] root_throttle root_pid={root_pid} root_name={root_name} "
        f"children={len(children)} contributors={len(children)} "
        f"count={sum_count} cpu_ns={sum_cpu_ns} "
        f"rho={control_rho}>child_rho_threshold={FLOOD_AGG_MIN_RHO} "
        f"sentinel_rho={sentinel_control_rho}>sentinel_threshold={FLOOD_AGG_MIN_SENTINEL_RHO} "
        f"cpu_util_threshold={FLOOD_AGG_MIN_CPU_UTIL} "
        f"min_count={FLOOD_MIN_COUNT} min_cpu_ns={FLOOD_MIN_CPU_NS} "
        f"min_children={FLOOD_AGG_MIN_CHILDREN} window_id={window_id} "
        f"same_uid={pid_uid} initial_quota={initial_q} raw_q={raw_q} "
        f"quota_theta={FLOOD_THETA_SENTINEL} quota_rate={initial_control_rho} "
        f"scale={scale:.6f} contributors_detail=[{child_preview}] "
        f"reason=fast_alert_same_window"
    )

    for child_pid, child in children.items():
        already_tracked = child_pid in _parent_active_children[root_pid]
        if not already_tracked:
            _parent_active_children[root_pid].add(child_pid)
            _pid_root_parent[child_pid] = root_pid
        child_info = _throttled_procs.setdefault(child_pid, {
            "current_quota": cgroup_q_max,
            "last_rho": child["rho"],
        })
        child_info["aggregate_root"] = root_pid
        child_info["last_rho"] = child["rho"]
        child_info["mode"] = "sentinel"
        if not already_tracked:
            _cgroup_write_queue.put(child_pid)

    descendants_queued = _queue_root_descendants(root_pid, "sentinel")
    eprint(
        f"[flood] root_throttle_descendants root_pid={root_pid} "
        f"root_name={root_name} queued={descendants_queued} "
        f"tracked_children={len(_parent_active_children[root_pid])} "
        f"queue_size={_cgroup_write_queue.qsize()}"
    )

    _fast_root_alerts.pop(bucket_key, None)
    return True


def _drain_flood_alerts():
    """Drain flood alerts reported via the BPF map and throttle offending pids."""
    global _flood_alerts_map

    if _flood_alerts_map is None:
        return

    key_type = getattr(_flood_alerts_map, "Key", None)
    try:
        alerts = list(_flood_alerts_map.items())
    except Exception as exc:
        eprint(f"Failed to read flood alerts: {exc}")
        return

    if alerts:
        eprint(f"[flood] drain alerts count={len(alerts)}")

    # Pass 1: collect new flooding pids before doing expensive parent-tree walks.
    new_pids = []
    for key, alert in alerts:
        pid = getattr(key, "value", None)
        if pid is None:
            continue
        if not os.path.exists(f"/proc/{pid}"):
            try:
                if key_type is not None:
                    del _flood_alerts_map[key_type(pid)]
                else:
                    del _flood_alerts_map[ctypes.c_uint(pid)]
            except Exception:
                pass
            if pid in _throttled_procs:
                del _throttled_procs[pid]
            _untrack_child_from_parent(pid)
            if pid in _parent_throttled:
                _parent_throttled.discard(pid)
                _parent_flood_counts.pop(pid, None)
                _clear_fast_root_alerts(pid)
            continue

        action_val = int(getattr(alert, "action", 0))
        if action_val != 1:
            continue

        if pid not in _throttled_procs:
            new_pids.append((pid, alert))
        else:
            # Already throttled; clear the duplicate alert.
            try:
                if key_type is not None:
                    del _flood_alerts_map[key_type(pid)]
                else:
                    del _flood_alerts_map[ctypes.c_uint(pid)]
            except Exception:
                pass

    # Pass 2: do the expensive work (parent-tree walk, cgroup enqueue).
    global _total_throttled_procs
    for pid, alert in new_pids:
        alert_rho = 0
        alert_count = 0
        alert_cpu_ns = 0
        alert_wall_ns = 0
        alert_sentinel_count = 0
        alert_sentinel_rho = 0
        ts_ns = 0
        name = None
        try:
            ts_ns = int(getattr(alert, "ts_ns"))
            alert_count = int(getattr(alert, "count", 0))
            alert_cpu_ns = int(getattr(alert, "cpu_ns", 0))
            alert_wall_ns = int(getattr(alert, "wall_ns", 0))
            alert_sentinel_count = int(getattr(alert, "sentinel_count", 0))
            alert_rho = ((alert_count * 1_000_000_000) // alert_cpu_ns
                         if alert_cpu_ns > 0 else 0)
            alert_sentinel_rho = ((alert_sentinel_count * 1_000_000_000) // alert_cpu_ns
                                  if alert_cpu_ns > 0 else 0)
            alert_cpu_util = _flood_cpu_util(alert_cpu_ns, alert_wall_ns)
            eprint(
                f"[flood] alert sample_ns={ts_ns} pid={pid} count={alert_count} cpu_ns={alert_cpu_ns} "
                f"wall_ns={alert_wall_ns} cpu_util={alert_cpu_util:.3f} "
                f"rho={alert_rho} sentinel_count={alert_sentinel_count} sentinel_rho={alert_sentinel_rho} "
                f"theta={FLOOD_THETA} theta_sentinel={FLOOD_THETA_SENTINEL} min_count={FLOOD_MIN_COUNT} "
                f"min_cpu_ns={FLOOD_MIN_CPU_NS}"
            )
        except Exception as e:
            eprint(f"[flood] Error calculating delay: {e}")

        root_pid, root_name, _tgid, _ppid, name = _find_root_coordinator(pid)
        sentinel_candidate = (
            alert_sentinel_count >= FLOOD_MIN_SENTINEL_COUNT and
            alert_sentinel_rho >= FLOOD_AGG_MIN_SENTINEL_RHO
        )
        fast_rooted = False
        if sentinel_candidate:
            # For sentinel fanout, aggregate root detection is allowed before the
            # individual cpu_util sanity gate. This catches 192/384-way attacks
            # where each child gets a tiny CPU slice but the root is already
            # flooding the audit pipeline.
            fast_rooted = _maybe_fast_root_throttle(
                pid, root_pid, root_name, name,
                alert_count, alert_cpu_ns, alert_rho, alert_wall_ns, ts_ns,
                alert_sentinel_count,
            )
            if fast_rooted:
                try:
                    if key_type is not None:
                        del _flood_alerts_map[key_type(pid)]
                    else:
                        del _flood_alerts_map[ctypes.c_uint(pid)]
                except Exception:
                    pass
                continue

        if not _alert_is_direct_flood(alert_count, alert_cpu_ns, alert_rho, alert_wall_ns,
                                      alert_sentinel_count):
            eprint(
                f"[flood] alert ignored pid={pid} count={alert_count} cpu_ns={alert_cpu_ns} "
                f"wall_ns={alert_wall_ns} cpu_util={_flood_cpu_util(alert_cpu_ns, alert_wall_ns):.3f} "
                f"rho={alert_rho} min_rho={FLOOD_AGG_MIN_RHO} "
                f"sentinel_count={alert_sentinel_count} min_sentinel_rho={FLOOD_AGG_MIN_SENTINEL_RHO} "
                f"cpu_util_threshold={FLOOD_AGG_MIN_CPU_UTIL}"
            )
            try:
                if key_type is not None:
                    del _flood_alerts_map[key_type(pid)]
                else:
                    del _flood_alerts_map[ctypes.c_uint(pid)]
            except Exception:
                pass
            continue

        sentinel_alert = (
            alert_sentinel_count >= FLOOD_MIN_SENTINEL_COUNT and
            alert_sentinel_rho >= FLOOD_AGG_MIN_SENTINEL_RHO and
            _flood_cpu_util(alert_cpu_ns, alert_wall_ns) >= FLOOD_AGG_MIN_CPU_UTIL
        )
        quota_rate = alert_sentinel_rho if sentinel_alert else alert_rho
        quota_theta = FLOOD_THETA_SENTINEL if sentinel_alert else FLOOD_THETA

        _total_throttled_procs += 1
        initial_q, raw_q, scale = _quota_from_observed_rate(
            cgroup_q_max,
            quota_rate,
            quota_theta,
        )
        _throttled_procs[pid] = {
            "current_quota": initial_q,
            "last_rho": alert_rho,
            "mode": "sentinel" if sentinel_alert else "density",
        }
        eprint(
            f"[flood] new throttled pid={pid} initial_quota={initial_q} "
            f"raw_q={raw_q} scale={scale:.6f} quota_theta={quota_theta} "
            f"quota_rate={quota_rate} mode={'sentinel' if sentinel_alert else 'density'} "
            f"theta_rel={FLOOD_THETA_SENTINEL_REL if sentinel_alert else FLOOD_THETA_REL}"
        )

        # Snap the global quota down for this newly throttled process.
        new_q = initial_q
        aggregate_q = _active_aggregate_quota()
        if aggregate_q is not None:
            new_q = min(new_q, aggregate_q)
        _apply_dynamic_quota(new_q, force=(aggregate_q is not None), reason="new_pid")

        # Walk the parent tree once.  If multiple children under the same root
        # alert in the same kernel 100ms window, throttle the root immediately;
        # otherwise throttle only the alerted child.  No SIGSTOP is needed.
        if not fast_rooted:
            fast_rooted = _maybe_fast_root_throttle(
                pid, root_pid, root_name, name,
                alert_count, alert_cpu_ns, alert_rho, alert_wall_ns, ts_ns,
                alert_sentinel_count,
            )
        if not fast_rooted:
            _cgroup_write_queue.put(pid)
            eprint(
                f"[flood] queued pid={pid} for cgroup migration "
                f"queue_size={_cgroup_write_queue.qsize()}"
            )
        try:
            if key_type is not None:
                del _flood_alerts_map[key_type(pid)]
            else:
                del _flood_alerts_map[ctypes.c_uint(pid)]
        except Exception:
            pass

def _poll_throttled_procs(proc_state_map):
    """Update per-throttled-unit cgroup quota; release units that recovered."""
    if proc_state_map is None or not _throttled_procs:
        return

    theta = FLOOD_THETA
    theta_rel = FLOOD_THETA_REL

    for pid, info in list(_throttled_procs.items()):
        if not os.path.exists(f"/proc/{pid}"):
            _throttled_procs.pop(pid, None)
            _throttle_kernel_window_seen.pop(pid, None)
            _untrack_child_from_parent(pid)
            if pid in _parent_throttled:
                _parent_throttled.discard(pid)
                _parent_flood_counts.pop(pid, None)
                _clear_fast_root_alerts(pid)
            try:
                if _flood_alerts_map is not None:
                    key_type = getattr(_flood_alerts_map, "Key", ctypes.c_uint)
                    del _flood_alerts_map[key_type(pid)]
            except Exception:
                pass
            continue

        if info.get("aggregate_root") is not None:
            continue

        try:
            key_type = getattr(proc_state_map, "Key", ctypes.c_uint)
            w = proc_state_map[key_type(pid)]
            win_end = int(getattr(w, "last_win_end", 0))
            if win_end <= 0 or _throttle_kernel_window_seen.get(pid) == win_end:
                continue
            _throttle_kernel_window_seen[pid] = win_end

            count = int(getattr(w, "last_count", 0))
            cpu_ns = int(getattr(w, "last_cpu_ns", 0))
            sentinel_count = int(getattr(w, "last_sentinel_count", 0))
            win_start = int(getattr(w, "last_win_start", 0))
            wall_ns = win_end - win_start
        except KeyError:
            # Process evicted from LRU — treat as recovered.
            _release_pid_cgroup(pid)
            _throttled_procs.pop(pid, None)
            _untrack_child_from_parent(pid)
            _throttle_kernel_window_seen.pop(pid, None)
            continue
        except Exception as e:
            eprint(f"[flood] Error reading proc_state for {pid}: {e}")
            continue

        if count <= 0 or cpu_ns <= 0 or wall_ns <= 0:
            continue

        rho = (count * 1_000_000_000) // cpu_ns
        if rho <= 0:
            rho = 1
        sentinel_rho = ((sentinel_count * 1_000_000_000) // cpu_ns
                        if cpu_ns > 0 else 0)

        current_q = info.get("current_quota", cgroup_q_max)
        mode = info.get("mode", "density")
        if mode == "sentinel":
            quota_rate = max(sentinel_rho, 1)
            quota_theta = FLOOD_THETA_SENTINEL
            release_signal = sentinel_rho
            release_threshold = FLOOD_THETA_SENTINEL_REL
        else:
            quota_rate = rho
            quota_theta = FLOOD_THETA
            release_signal = rho
            release_threshold = theta_rel
        new_q, raw_q, scale = _quota_from_observed_rate(current_q, quota_rate, quota_theta)

        info["current_quota"] = new_q
        info["last_rho"] = rho
        eprint(
            f"[flood] poll sample_ns={win_end} pid={pid} count={count} "
            f"cpu_ns={cpu_ns} wall_ns={wall_ns} rho={rho} "
            f"sentinel_count={sentinel_count} sentinel_rho={sentinel_rho} "
            f"mode={mode} quota_theta={quota_theta} quota_rate={quota_rate} "
            f"theta={theta} alpha={FLOOD_ALPHA} quota={current_q}->{new_q} "
            f"raw_q={raw_q} scale={scale:.6f}"
        )

        if release_signal <= release_threshold:
            eprint(
                f"[flood] release pid={pid}: release_signal={release_signal} "
                f"<= release_threshold={release_threshold} mode={mode}"
            )
            _release_pid_cgroup(pid)
            _throttled_procs.pop(pid, None)
            _throttle_kernel_window_seen.pop(pid, None)
            _untrack_child_from_parent(pid)
            try:
                if _flood_alerts_map is not None:
                    key_type = getattr(_flood_alerts_map, "Key", ctypes.c_uint)
                    del _flood_alerts_map[key_type(pid)]
            except Exception:
                pass
            continue

    individual_infos = [
        info for info in _throttled_procs.values()
        if info.get("aggregate_root") is None
    ]
    if individual_infos:
        target_q = max(info.get("current_quota", cgroup_q_max)
                       for info in individual_infos)
        aggregate_q = _active_aggregate_quota()
        if aggregate_q is not None:
            target_q = min(target_q, aggregate_q)
        _apply_dynamic_quota(target_q, force=(aggregate_q is not None), reason="individual_poll")

def _proc_window_value(val, field, default):
    """Read newer BPF fields while remaining compatible during reloads."""
    return int(getattr(val, field, getattr(val, default)))

def _poll_aggregate_proc_density(proc_state_map):
    """Throttle parent-tree groups whose combined child density exceeds theta."""
    global _aggregate_debug_last_ns

    if proc_state_map is None:
        return

    groups = {}
    key_type = getattr(proc_state_map, "Key", ctypes.c_uint)
    try:
        items = list(proc_state_map.items())
    except Exception as exc:
        eprint(f"[flood] aggregate scan failed: {exc}")
        return

    live_pids = set()

    for key, val in items:
        pid = int(getattr(key, "value", key))
        if pid <= 0 or pid == os.getpid() or not os.path.exists(f"/proc/{pid}"):
            _proc_kernel_window_seen.pop(pid, None)
            continue
        live_pids.add(pid)

        win_end = int(getattr(val, "last_win_end", 0))
        if win_end <= 0 or _proc_kernel_window_seen.get(pid) == win_end:
            continue
        _proc_kernel_window_seen[pid] = win_end

        count = int(getattr(val, "last_count", 0))
        cpu_ns = int(getattr(val, "last_cpu_ns", 0))
        win_start = int(getattr(val, "last_win_start", 0))
        sentinel_count = int(getattr(val, "last_sentinel_count", 0))
        wall_ns = win_end - win_start
        if count <= 0 or cpu_ns <= 0 or wall_ns <= 0:
            continue

        rho = (count * 1_000_000_000) // cpu_ns
        sentinel_rho = (sentinel_count * 1_000_000_000) // cpu_ns if cpu_ns > 0 else 0
        sentinel_wall_rate = (sentinel_count * 1_000_000_000) // wall_ns if wall_ns > 0 else 0
        root_pid, root_name, _tgid, _ppid, name = _find_root_coordinator(pid)
        if root_pid is None or root_pid == pid:
            continue

        group = groups.setdefault(root_pid, {
            "name": root_name,
            "sum_child_rho_debug": 0,
            "sum_count": 0,
            "sum_cpu_ns": 0,
            "sum_sentinel_count": 0,
            "wall_ns": 0,
            "children": [],
        })
        group["sum_child_rho_debug"] += rho
        group["sum_count"] += count
        group["sum_cpu_ns"] += cpu_ns
        group["sum_sentinel_count"] += sentinel_count
        if wall_ns > group["wall_ns"]:
            group["wall_ns"] = wall_ns
        wall_rate = (count * 1_000_000_000) // wall_ns
        # child tuple indices:
        #  0=pid 1=name 2=rho 3=count 4=cpu_ns 5=wall_ns 6=wall_rate
        #  7=sentinel_count 8=sentinel_rho 9=sentinel_wall_rate
        group["children"].append(
            (pid, name, rho, count, cpu_ns, wall_ns, wall_rate,
             sentinel_count, sentinel_rho, sentinel_wall_rate)
        )

    for pid in list(_proc_kernel_window_seen):
        if pid not in live_pids:
            _proc_kernel_window_seen.pop(pid, None)

    for info in groups.values():
        # Direct contributors: children individually suspicious on sentinel syscalls.
        # Use sentinel_rho (not total rho) so that benign workers doing heavy
        # read/write never qualify — a process must be calling attack-typical
        # syscalls (kill, mprotect, chmod, clone, execve, etc.) at high density.
        direct_contributors = [
            child for child in info["children"]
            if (child[8] >= FLOOD_AGG_MIN_SENTINEL_RHO and
                child[5] > 0 and child[4] / child[5] >= FLOOD_AGG_MIN_CPU_UTIL)
        ]
        # Distributed contributors: children with enough sentinel calls per window.
        # Using sentinel_count (not total count) means benign I/O children are
        # excluded from distributed-fanout detection entirely.
        distributed_contributors = [
            child for child in info["children"]
            if child[7] >= FLOOD_MIN_SENTINEL_COUNT
        ]
        # Group-level sentinel rate: sum of sentinel_wall_rates across all children.
        group_sentinel_wall_rate = (
            (info["sum_sentinel_count"] * 1_000_000_000) // info["wall_ns"]
            if info["wall_ns"] > 0 else 0
        )
        # Keep total wall_rate for reporting only (not for throttle decisions).
        group_wall_rate = (
            (info["sum_count"] * 1_000_000_000) // info["wall_ns"]
            if info["wall_ns"] > 0 else 0
        )
        # Standard distributed path: N children each above the sentinel count floor
        # AND the group's combined sentinel rate is over the capacity threshold.
        group_overloaded = (
            group_sentinel_wall_rate >= FLOOD_AGG_MIN_GROUP_SENTINEL_WALL_RATE and
            len(distributed_contributors) >= FLOOD_AGG_MIN_CHILDREN
        )
        # High-fanout path: many children each making too few sentinel calls to
        # individually cross FLOOD_MIN_SENTINEL_COUNT, but the collective sentinel
        # rate still overwhelms the threshold.
        high_fanout_overloaded = (
            not group_overloaded and
            group_sentinel_wall_rate >= FLOOD_AGG_MIN_GROUP_SENTINEL_WALL_RATE and
            len(info["children"]) >= FLOOD_AGG_HIGH_FANOUT_CHILDREN
        )
        # Long-lived fanout path: attack that deliberately keeps per-child sentinel
        # rate so low that group_sentinel_wall_rate stays below the threshold, but
        # spawns many persistent child processes that each use sentinel syscalls.
        # Only processes with a completed kernel window appear in info["children"]
        # (alive > FLOOD_W_NS = 100ms), so short-lived benign workers (e.g. gcc
        # invocations that each finish in <100ms) are naturally absent.
        # Sentinel guard: count only children with sentinel_count > 0.  A make -j50
        # build has 50 compiler workers alive > 100ms but their sentinel_count ≈ 0
        # (they call read/write/mmap for code loading, not kill/mprotect repeatedly).
        long_lived_sentinel_children = [c for c in info["children"] if c[7] > 0]
        long_lived_fanout = (
            not group_overloaded and
            not high_fanout_overloaded and
            len(long_lived_sentinel_children) >= FLOOD_AGG_LONG_LIVED_FANOUT_CHILDREN
        )
        # Resolve contributors and trigger label for whichever path fired.
        if group_overloaded:
            contributors = distributed_contributors if distributed_contributors else info["children"]
            trigger_path = "group_wall_rate_over_capacity"
        elif high_fanout_overloaded:
            contributors = info["children"]
            trigger_path = "high_fanout_distributed"
        elif long_lived_fanout:
            contributors = long_lived_sentinel_children
            trigger_path = "long_lived_high_fanout"
        else:
            contributors = direct_contributors
            trigger_path = "more_than_2_misbehaving_children"
        group_overloaded = group_overloaded or high_fanout_overloaded or long_lived_fanout
        info["trigger_path"] = trigger_path
        info["contributors"] = contributors
        info["direct_contributors"] = direct_contributors
        info["distributed_contributors"] = distributed_contributors
        info["group_overloaded"] = group_overloaded
        info["contrib_sum_count"] = sum(child[3] for child in contributors)
        info["contrib_sum_cpu_ns"] = sum(child[4] for child in contributors)
        info["contrib_sum_sentinel_count"] = sum(child[7] for child in contributors)
        info["contrib_wall_ns"] = max((child[5] for child in contributors), default=0)
        info["contrib_rho"] = (
            (info["contrib_sum_count"] * 1_000_000_000) // info["contrib_sum_cpu_ns"]
            if info["contrib_sum_cpu_ns"] > 0 else 0
        )
        info["contrib_sentinel_rho"] = (
            (info["contrib_sum_sentinel_count"] * 1_000_000_000) // info["contrib_sum_cpu_ns"]
            if info["contrib_sum_cpu_ns"] > 0 else 0
        )
        info["contrib_wall_rate"] = (
            (info["contrib_sum_count"] * 1_000_000_000) // info["contrib_wall_ns"]
            if info["contrib_wall_ns"] > 0 else 0
        )
        info["contrib_sentinel_wall_rate"] = (
            (info["contrib_sum_sentinel_count"] * 1_000_000_000) // info["contrib_wall_ns"]
            if info["contrib_wall_ns"] > 0 else 0
        )
        info["max_child_sentinel_rho"] = max((child[8] for child in contributors), default=0)
        info["group_rho"] = (
            (info["sum_count"] * 1_000_000_000) // info["sum_cpu_ns"]
            if info["sum_cpu_ns"] > 0 else 0
        )
        info["group_wall_rate"] = group_wall_rate
        info["group_sentinel_wall_rate"] = group_sentinel_wall_rate
        info["sentinel_control_rho"] = max(
            info["group_sentinel_wall_rate"],
            info["contrib_sentinel_rho"],
            info["contrib_sentinel_wall_rate"],
            info["max_child_sentinel_rho"],
        )
        info["broad_overload"] = (
            group_overloaded or len(info["contributors"]) >= FLOOD_AGG_MIN_CHILDREN
        )
        info["control_rho"] = max(info["contrib_rho"], info["contrib_wall_rate"])

    now = time.monotonic_ns()
    if verbosity >= 2 and now - _aggregate_debug_last_ns >= 1_000_000_000:
        _aggregate_debug_last_ns = now
        if groups:
            top = sorted(groups.items(), key=lambda item: item[1]["group_rho"], reverse=True)[:3]
            summary = ", ".join(
                f"root={root} name={info['name']} children={len(info['children'])} "
                f"contributors={len(info['contributors'])} group_rho={info['group_rho']} "
                f"sum_count={info['sum_count']} sum_cpu_ns={info['sum_cpu_ns']} "
                f"sum_sentinel={info['sum_sentinel_count']} "
                f"wall_rate={info['group_wall_rate']} "
                f"sentinel_wall_rate={info['group_sentinel_wall_rate']} "
                f"wall_ns={info['wall_ns']} "
                f"contrib_rho={info['contrib_rho']} contrib_count={info['contrib_sum_count']} "
                f"contrib_cpu_ns={info['contrib_sum_cpu_ns']} "
                f"contrib_wall_rate={info['contrib_wall_rate']} "
                f"group_overloaded={info['group_overloaded']}"
                for root, info in top
            )
            eprint(
                f"[flood] aggregate top: {summary}; theta={FLOOD_THETA} "
                f"theta_sentinel={FLOOD_THETA_SENTINEL} "
                f"min_children={FLOOD_AGG_MIN_CHILDREN} "
                f"min_child_sentinel_rho={FLOOD_AGG_MIN_SENTINEL_RHO} "
                f"min_group_sentinel_wall_rate={FLOOD_AGG_MIN_GROUP_SENTINEL_WALL_RATE} "
                f"parent_throttled={list(_parent_throttled)}"
            )
        else:
            eprint(
                f"[flood] aggregate top: no non-protected child groups; theta={FLOOD_THETA} "
                f"theta_sentinel={FLOOD_THETA_SENTINEL} "
                f"min_children={FLOOD_AGG_MIN_CHILDREN} "
                f"min_child_sentinel_rho={FLOOD_AGG_MIN_SENTINEL_RHO} "
                f"min_group_sentinel_wall_rate={FLOOD_AGG_MIN_GROUP_SENTINEL_WALL_RATE}"
            )

    for root_pid in list(_aggregate_root_quota):
        if root_pid in groups:
            continue
        active_children = set(_parent_active_children.get(root_pid, set()))
        live_children = {
            child_pid for child_pid in active_children
            if _process_is_active(child_pid)
        }
        if live_children:
            _parent_active_children[root_pid] = live_children
            _parent_flood_counts[root_pid] = len(live_children)
            continue

        eprint(f"[flood] aggregate release root={root_pid}: no live throttled children")
        _parent_throttled.discard(root_pid)
        _parent_flood_counts.pop(root_pid, None)
        _aggregate_root_quota.pop(root_pid, None)
        _aggregate_release_streak.pop(root_pid, None)
        _aggregate_trigger_streak.pop(root_pid, None)
        _aggregate_root_mode.pop(root_pid, None)
        _clear_fast_root_alerts(root_pid)
        try:
            _release_pid_cgroup(root_pid)
        except Exception:
            pass
        for child_pid in list(_parent_active_children.get(root_pid, set())):
            _release_pid_cgroup(child_pid)
            _throttled_procs.pop(child_pid, None)
            _pid_root_parent.pop(child_pid, None)
        _parent_active_children.pop(root_pid, None)

    for root_pid, info in groups.items():
        if root_pid in _parent_throttled:
            root_mode = _aggregate_root_mode.get(root_pid, "density")
            newly_queued = 0
            for child in info["children"]:
                child_pid = child[0]
                rho = child[2]
                if child_pid not in _parent_active_children[root_pid]:
                    _parent_active_children[root_pid].add(child_pid)
                    _pid_root_parent[child_pid] = root_pid
                    child_info = _throttled_procs.setdefault(child_pid, {
                        "current_quota": cgroup_q_max,
                        "last_rho": rho,
                        "aggregate_root": root_pid,
                    })
                    child_info["aggregate_root"] = root_pid
                    child_info["last_rho"] = rho
                    child_info["mode"] = root_mode
                    _cgroup_write_queue.put(child_pid)
                    newly_queued += 1
            _parent_flood_counts[root_pid] = len(_parent_active_children[root_pid])

            current_q = _aggregate_root_quota.get(root_pid, cgroup_q_max)
            active_control_rho = max(info["control_rho"], info["group_wall_rate"])
            if root_mode == "sentinel":
                quota_rate = max(info["sentinel_control_rho"], 1)
                quota_theta = FLOOD_THETA_SENTINEL
                release_signal = info["sentinel_control_rho"]
                release_threshold = FLOOD_THETA_SENTINEL_REL
            else:
                quota_rate = active_control_rho
                quota_theta = FLOOD_THETA
                release_signal = active_control_rho
                release_threshold = FLOOD_THETA_REL
            new_q, raw_q, scale = _quota_from_observed_rate(current_q, quota_rate, quota_theta)
            _aggregate_root_quota[root_pid] = new_q
            eprint(
                f"[flood] aggregate poll root={root_pid} children={len(info['children'])} "
                f"contributors={len(info['contributors'])} contrib_rho={info['contrib_rho']} "
                f"contrib_count={info['contrib_sum_count']} contrib_cpu_ns={info['contrib_sum_cpu_ns']} "
                f"tracked_children={len(_parent_active_children[root_pid])} newly_queued={newly_queued} "
                f"wall_rate={info['group_wall_rate']} contrib_wall_rate={info['contrib_wall_rate']} "
                f"sentinel_control_rho={info['sentinel_control_rho']} root_mode={root_mode} "
                f"control_rho={info['control_rho']} active_control_rho={active_control_rho} "
                f"quota_theta={quota_theta} quota_rate={quota_rate} "
                f"theta={FLOOD_THETA} alpha={FLOOD_ALPHA} quota={current_q}->{new_q} "
                f"raw_q={raw_q} scale={scale:.6f}"
            )
            _apply_dynamic_quota(new_q, force=True, reason="aggregate_poll")

            if release_signal <= release_threshold:
                _aggregate_release_streak[root_pid] = _aggregate_release_streak.get(root_pid, 0) + 1
                eprint(
                    f"[flood] aggregate release-check root={root_pid}: "
                    f"release_signal={release_signal} <= release_threshold={release_threshold} "
                    f"root_mode={root_mode} "
                    f"streak={_aggregate_release_streak[root_pid]}/{FLOOD_AGG_RELEASE_WINDOWS}"
                )
            else:
                _aggregate_release_streak[root_pid] = 0

            if _aggregate_release_streak.get(root_pid, 0) >= FLOOD_AGG_RELEASE_WINDOWS:
                eprint(f"[flood] aggregate release root={root_pid}: recovered for {FLOOD_AGG_RELEASE_WINDOWS} windows")
                _parent_throttled.discard(root_pid)
                _parent_flood_counts.pop(root_pid, None)
                _aggregate_root_quota.pop(root_pid, None)
                _aggregate_release_streak.pop(root_pid, None)
                _aggregate_trigger_streak.pop(root_pid, None)
                _aggregate_root_mode.pop(root_pid, None)
                _clear_fast_root_alerts(root_pid)
                try:
                    _release_pid_cgroup(root_pid)
                except Exception:
                    pass
                for child_pid in list(_parent_active_children.get(root_pid, set())):
                    _release_pid_cgroup(child_pid)
                    _throttled_procs.pop(child_pid, None)
                    _pid_root_parent.pop(child_pid, None)
                _parent_active_children.pop(root_pid, None)
            continue

        if not info["broad_overload"]:
            # Group has calmed down: reset any pre-trigger strike count so a
            # subsequent burst must again accumulate FLOOD_AGG_TRIGGER_WINDOWS
            # consecutive overloaded windows before throttling kicks in.
            _aggregate_trigger_streak.pop(root_pid, None)
            if (info["group_rho"] > FLOOD_THETA or
                  info["sum_child_rho_debug"] > FLOOD_THETA or
                  info["group_wall_rate"] > FLOOD_C) and verbosity >= 2:
                eprint(
                    f"[flood] aggregate suppress root={root_pid} name={info['name']} "
                    f"children={len(info['children'])} contributors={len(info['contributors'])} "
                    f"group_rho={info['group_rho']} sum_count={info['sum_count']} "
                    f"sum_cpu_ns={info['sum_cpu_ns']} wall_rate={info['group_wall_rate']} "
                    f"wall_ns={info['wall_ns']} contrib_rho={info['contrib_rho']} "
                    f"contrib_count={info['contrib_sum_count']} contrib_cpu_ns={info['contrib_sum_cpu_ns']} "
                    f"contrib_wall_rate={info['contrib_wall_rate']} "
                    f"group_overloaded={info['group_overloaded']} "
                    f"reason=need_at_least_3_misbehaving_children"
                )
            continue

        # Group is overloaded.  Require FLOOD_AGG_TRIGGER_WINDOWS consecutive
        # overloaded kernel windows before throttling to absorb benign bursts.
        # Each kernel window is FLOOD_W_NS (100 ms), so the default of 3 windows
        # means a group must sustain the overload signal for ~300 ms.  Attackers
        # that run continuously accumulate this in a handful of windows; a benign
        # tar or database flush typically recovers within 1-2 windows.
        required_streak = (
            FLOOD_AGG_SENTINEL_TRIGGER_WINDOWS
            if info["trigger_path"] in {
                "group_wall_rate_over_capacity",
                "high_fanout_distributed",
                "more_than_2_misbehaving_children",
            }
            else FLOOD_AGG_TRIGGER_WINDOWS
        )
        streak = _aggregate_trigger_streak.get(root_pid, 0) + 1
        _aggregate_trigger_streak[root_pid] = streak
        if streak < required_streak:
            eprint(
                f"[flood] aggregate pre-trigger root={root_pid} name={info['name']} "
                f"streak={streak}/{required_streak} "
                f"children={len(info['children'])} contributors={len(info['contributors'])} "
                f"group_wall_rate={info['group_wall_rate']} contrib_rho={info['contrib_rho']} "
                f"group_overloaded={info['group_overloaded']}"
            )
            continue
        # Strike threshold reached: commit to throttle and clear the counter.
        _aggregate_trigger_streak.pop(root_pid, None)

        children = sorted(info["contributors"], key=lambda row: row[2], reverse=True)
        child_preview = ", ".join(
            f"{child[0]}:{child[1]}:rho={child[2]}:wall={child[6]}:"
            f"sentinel_count={child[7]}:sentinel_rho={child[8]}:"
            f"sentinel_wall={child[9]}"
            for child in children[:8]
        )
        _reason = info["trigger_path"]
        eprint(
            f"[flood] root_throttle root_pid={root_pid} root_name={info['name']} "
            f"children={len(info['children'])} contributors={len(children)} "
            f"count={info['contrib_sum_count']} cpu_ns={info['contrib_sum_cpu_ns']} "
            f"rho={info['contrib_rho']}>child_rho_threshold={FLOOD_AGG_MIN_RHO} "
            f"cpu_util_threshold={FLOOD_AGG_MIN_CPU_UTIL} "
            f"wall_rate={info['group_wall_rate']}>group_wall_threshold={FLOOD_AGG_MIN_GROUP_WALL_RATE} "
            f"child_wall_threshold={FLOOD_AGG_MIN_CHILD_WALL_RATE} "
            f"min_count={FLOOD_MIN_COUNT} min_children={FLOOD_AGG_MIN_CHILDREN} "
            f"high_fanout_min={FLOOD_AGG_HIGH_FANOUT_CHILDREN} "
            f"contributors_detail=[{child_preview}] reason={_reason}"
        )
        eprint(
            f"[flood] aggregate trigger root={root_pid} name={info['name']} "
            f"children={len(info['children'])} contributors={len(children)} "
            f"contrib_rho={info['contrib_rho']} contrib_count={info['contrib_sum_count']} "
            f"contrib_cpu_ns={info['contrib_sum_cpu_ns']} wall_rate={info['group_wall_rate']} "
            f"contrib_wall_rate={info['contrib_wall_rate']} "
            f"group_overloaded={info['group_overloaded']} "
            f"reason={_reason} "
            f"theta={FLOOD_THETA} "
            f"sample=[{child_preview}]"
        )

        if not _ensure_flood_cgroup():
            eprint(f"[flood] aggregate trigger root={root_pid} could not ensure cgroup")
            continue

        root_mode = "sentinel"
        initial_control_rho = max(info["sentinel_control_rho"], 1)
        quota_theta = FLOOD_THETA_SENTINEL
        # For long-lived fanout the attacker deliberately keeps per-child rates
        # low. Use a sentinel-specific floor so the first quota is still visible.
        if (_reason == "long_lived_high_fanout" and
                initial_control_rho < FLOOD_THETA_SENTINEL * 10):
            initial_control_rho = FLOOD_THETA_SENTINEL * 10
        initial_q, raw_q, scale = _quota_from_observed_rate(
            cgroup_q_max,
            initial_control_rho,
            quota_theta,
        )

        _parent_throttled.add(root_pid)
        _parent_flood_counts[root_pid] = len(children)
        _aggregate_root_quota[root_pid] = initial_q
        _aggregate_release_streak[root_pid] = 0
        _aggregate_root_mode[root_pid] = root_mode
        _apply_dynamic_quota(initial_q, force=True, reason="aggregate_trigger")
        _cgroup_write_queue.put(root_pid)
        eprint(
            f"[flood] aggregate queued root pid={root_pid} initial_quota={initial_q} "
            f"initial_control_rho={initial_control_rho} quota_theta={quota_theta} raw_q={raw_q} "
            f"scale={scale:.6f} queue_size={_cgroup_write_queue.qsize()}"
        )

        for child in children:
            pid = child[0]
            rho = child[2]
            already_tracked = pid in _parent_active_children[root_pid]
            if not already_tracked:
                _parent_active_children[root_pid].add(pid)
                _pid_root_parent[pid] = root_pid
            if pid not in _throttled_procs:
                _throttled_procs[pid] = {
                    "current_quota": cgroup_q_max,
                    "last_rho": rho,
                    "aggregate_root": root_pid,
                }
            _throttled_procs[pid]["aggregate_root"] = root_pid
            _throttled_procs[pid]["last_rho"] = rho
            _throttled_procs[pid]["mode"] = root_mode
            if not already_tracked:
                _cgroup_write_queue.put(pid)
        descendants_queued = _queue_root_descendants(root_pid, root_mode)
        eprint(
            f"[flood] aggregate queued {len(children)} contributors for root={root_pid} "
            f"descendants_queued={descendants_queued} "
            f"tracked_children={len(_parent_active_children[root_pid])} "
            f"queue_size={_cgroup_write_queue.qsize()}"
        )

def _emit_flood_density_samples(proc_state_map, now):
    """Emit generic 100ms density samples for optional process-name filters."""
    global _flood_sample_last_ns

    if not FLOOD_SAMPLE_NAMES and not FLOOD_WINDOW_DEBUG:
        return
    if now - _flood_sample_last_ns < 100_000_000:
        return
    _flood_sample_last_ns = now

    try:
        if FLOOD_WINDOW_DEBUG:
            rows = []
            live_pids = set()
            for key, val in proc_state_map.items():
                pid = int(getattr(key, "value", key))
                _tgid, ppid, name = _get_process_info(pid)
                if not name:
                    continue
                if FLOOD_SAMPLE_NAMES and name not in FLOOD_SAMPLE_NAMES:
                    continue
                live_pids.add(pid)

                win_end = int(getattr(val, "last_win_end", 0))
                if win_end <= 0 or _flood_sample_kernel_window_seen.get(pid) == win_end:
                    continue
                _flood_sample_kernel_window_seen[pid] = win_end

                count = int(getattr(val, "last_count", 0))
                cpu_ns = int(getattr(val, "last_cpu_ns", 0))
                if count <= 0 and cpu_ns <= 0:
                    continue
                if count < 0:
                    count = 0
                if cpu_ns < 0:
                    cpu_ns = 0
                rho = (count * 1_000_000_000) // cpu_ns if cpu_ns > 0 else 0

                root_pid, root_name, tgid, _parent_pid, _proc_name = _find_root_coordinator(pid)
                if root_pid is None:
                    root_pid = ppid or tgid or pid
                    root_name = name
                throttled = int(pid in _throttled_procs or root_pid in _parent_throttled)
                rows.append((root_pid, root_name, pid, name, count, cpu_ns, rho, throttled, win_end))

            for pid in list(_flood_sample_kernel_window_seen):
                if pid not in live_pids:
                    _flood_sample_kernel_window_seen.pop(pid, None)

            if FLOOD_TOTAL_SAMPLE_ONLY:
                total_count = sum(row[4] for row in rows)
                total_cpu_ns = sum(row[5] for row in rows)
                throttled_pids = sum(1 for row in rows if row[7])
                sample_ns = max((row[8] for row in rows), default=now)
                if total_count > 0 or total_cpu_ns > 0:
                    eprint(
                        f"[flood] total_sample sample_ns={sample_ns} "
                        f"total_count={total_count} total_cpu_ns={total_cpu_ns} "
                        f"pids={len(rows)} "
                        f"throttled_pids={throttled_pids}"
                    )
                return

            for root_pid, root_name, pid, name, count, cpu_ns, rho, throttled, win_end in sorted(rows):
                if throttled or rho > FLOOD_THETA or not globals().get("FLOOD_COMPACT_DEBUG", True):
                    eprint(
                        f"[flood] window sample_ns={win_end} root_pid={root_pid} "
                        f"root_name={root_name} pid={pid} name={name} "
                        f"count={count} cpu_ns={cpu_ns} rho={rho} throttled={throttled}"
                    )
            return

        for key, val in proc_state_map.items():
            pid = int(getattr(key, "value", key))
            _tgid, _ppid, name = _get_process_info(pid)
            if not name or name not in FLOOD_SAMPLE_NAMES:
                continue
            win_end = int(getattr(val, "last_win_end", 0))
            if win_end <= 0:
                continue
            count = int(getattr(val, "last_count", 0))
            cpu_ns = int(getattr(val, "last_cpu_ns", 0))
            total_count = _proc_window_value(val, "total_count", "count")
            total_cpu_ns = _proc_window_value(val, "total_cpu_ns", "cpu_ns")
            alerted = int(val.alerted)
            win_start = int(getattr(val, "last_win_start", 0))
            wall_ns = win_end - win_start
            rho = (count * 1_000_000_000) // cpu_ns if cpu_ns > 0 else 0
            wall_rate = (count * 1_000_000_000) // wall_ns if wall_ns > 0 else 0
            if alerted or rho > FLOOD_THETA or not globals().get("FLOOD_COMPACT_DEBUG", True):
                eprint(
                    f"[flood] window sample_ns={win_end} name={name} pid={pid} rho={rho} "
                    f"wall_rate={wall_rate} count={count} cpu_ns={cpu_ns} "
                    f"total_count={total_count} total_cpu_ns={total_cpu_ns} "
                    f"wall_ns={wall_ns} alerted={alerted}"
                )
    except Exception as exc:
        eprint(f"[flood] sample snapshot failed: {exc}")


def _debug_proc_density_snapshot(proc_state_map):
    """Print a compact once-per-second view of current kernel density state."""
    global _flood_debug_last_ns

    if verbosity < 2 or proc_state_map is None:
        return

    now = time.monotonic_ns()
    _emit_flood_density_samples(proc_state_map, now)
    if now - _flood_debug_last_ns < 1_000_000_000:
        return
    _flood_debug_last_ns = now

    dbg = ""
    if _flood_dbg_map is not None:
        names = [
            "root_bypass",
            "proc_init",
            "oc_missing",
            "zero_cpu_win",
            "window_roll",
            "alert_emit",
            "syscall_seen",
            "switch_cpu_add",
            "min_guard_skip",
        ]
        vals = []
        key_type = getattr(_flood_dbg_map, "Key", ctypes.c_int)
        try:
            for idx, name in enumerate(names):
                val = _flood_dbg_map[key_type(idx)]
                vals.append(f"{name}={int(getattr(val, 'value', val))}")
            dbg = " dbg{" + " ".join(vals) + "}"
        except Exception as exc:
            dbg = f" dbg_error={exc}"

    rows = []
    try:
        for key, val in proc_state_map.items():
            pid = int(getattr(key, "value", key))
            count = int(val.count)
            cpu_ns = int(val.cpu_ns)
            alerted = int(val.alerted)
            rho = (count * 1_000_000_000) // cpu_ns if cpu_ns > 0 else 0
            rows.append((rho, pid, count, cpu_ns, alerted))
    except Exception as exc:
        eprint(f"[flood] proc_state snapshot failed: {exc}")
        return

    rows.sort(reverse=True)
    if not rows:
        eprint(f"[flood] proc_state empty; no non-root syscall-density samples yet. theta={FLOOD_THETA} theta_rel={FLOOD_THETA_REL}{dbg}")
        return

    top = rows[:5]
    summary = ", ".join(
        f"pid={pid} rho={rho} count={count} cpu_ns={cpu_ns} alerted={alerted}"
        for rho, pid, count, cpu_ns, alerted in top
    )
    eprint(f"[flood] proc_state top {len(top)}/{len(rows)}: {summary}; throttled={list(_throttled_procs.keys())}{dbg}")

def _flood_alert_loop():
    """Fast 1ms loop: drain BPF flood alerts and place offenders into cgroup."""
    interval = 0.001
    if not _ensure_flood_cgroup(): return

    eprint(f"[flood] alert loop started interval_ms={interval * 1000:.3f}")

    while not _flood_stop.is_set():
        _drain_flood_alerts()
        time.sleep(interval)

def _adaptive_poll_loop():
    """Control loop: adapt cpu.max based on per-pid syscall density."""
    interval = 0.0050
    eprint(f"[flood] density poll loop started interval_ms={interval * 1000:.1f} proc_state_map={_proc_state_map is not None} adaptive_disabled={disable_adaptive_cgroup}")

    while not _flood_stop.is_set():
        if _proc_state_map is not None and filter_sc_flood:
            _debug_proc_density_snapshot(_proc_state_map)

        if _proc_state_map is not None and filter_sc_flood and not disable_adaptive_cgroup:
            _poll_aggregate_proc_density(_proc_state_map)

        if _proc_state_map is not None and filter_sc_flood and not disable_adaptive_cgroup:
            _poll_throttled_procs(_proc_state_map)

        time.sleep(interval)

_adaptive_poller = None

def _start_flood_poller():
    global _flood_poller
    global _adaptive_poller

    if _flood_poller is not None:
        return

    eprint(
        f"[flood] starting pollers theta={FLOOD_THETA} theta_rel={FLOOD_THETA_REL} "
        f"theta_sentinel={FLOOD_THETA_SENTINEL} min_sentinel_count={FLOOD_MIN_SENTINEL_COUNT} "
        f"min_sentinel_rho={FLOOD_AGG_MIN_SENTINEL_RHO} "
        f"min_sentinel_cpu_ns={FLOOD_MIN_SENTINEL_CPU_NS} "
        f"sentinel_fast_min_ns={FLOOD_SENTINEL_FAST_MIN_NS} "
        f"window_ns={FLOOD_W_NS} min_count={FLOOD_MIN_COUNT} "
        f"min_cpu_ns={FLOOD_MIN_CPU_NS} alpha={FLOOD_ALPHA} q_max={cgroup_q_max} "
        f"throttling_disabled={disable_adaptive_cgroup}"
    )

    if not disable_adaptive_cgroup:
        threading.Thread(target=_cgroup_writer_worker, daemon=True).start()

        _flood_poller = threading.Thread(target=_flood_alert_loop, daemon=True)
        _flood_poller.start()

    _adaptive_poller = threading.Thread(target=_adaptive_poll_loop, daemon=True)
    _adaptive_poller.start()

###############################################################################
# Set up all the parameters used by the ebpf probe. Some of them could be set
# at runtime, but for now, it seems good enough to set them up at load time.
###############################################################################
# First, key performance params. Small => low latency, less chance for attacks
# to wipe events before they reach the log file. Large => better performance.
###############################################################################
src = """
#define  TX_THRESH %d
#define  TX_WT_THRESH %d
#define RINGBUF_PAGES %d
#define RINGBUF_PUSH_INTERVAL %d // Fraction of ringbuf outputs that wakeup
#define MAX_TASKS %d
#define MAX_OBJS %d
#define MAX_FDS %d
#define TEMP_CACHE_SZ %d
#define FDI_REUSE_SZ %d
""" % (perf_fac*1024, WT_THRESH, ringbuf_size*256, push_interval, 
       max_tasks, max_objs, max_fds, temp_cache_sz, fdi_reuse_sz);

src += """
#define WT_THRESH      %d
#define WT_CRITICAL    %d
#define WT_IMPORTANT   %d
#define WT_ENDPOINT    %d
#define WT_DGRAM       %d
#define WT_FDTRACK     %d
#define WT_RDWR        %d
#define WT_UNIMPORTANT %d
#define WT_REDUNDANT   %d
#define RSEED          %dul
""" % (WT_THRESH, WT_CRITICAL, WT_IMPORTANT,
       WT_ENDPOINT, WT_DGRAM, WT_FDTRACK, WT_RDWR,
       WT_UNIMPORTANT, WT_REDUNDANT, random.randrange(1<<63))

src += """
#define MAXCACHETIME             %dul
#define TOO_LONG_TIME            %dul
#define TOO_SMALL_RDWR_BYTES     %dul
#define MED_RDWR_RATIO           %d
#define TOO_LARGE_RDWR_BYTES     %dul
#define VER_DIFF_THRESH_FAC      %d
#define TOO_LARGE_VER_DIFF       %d
#define VER_THR_SHIFT            %d
#define PRINTK_LOG_LEVEL         %d
""" % (max_cache_time, TOO_LONG_TIME, TOO_SMALL_RDWR_BYTES, MED_RDWR_RATIO,
       TOO_LARGE_RDWR_BYTES, ver_diff_thresh_fac, too_large_ver_diff, 
       ver_thr_shift, verbosity)

src += """
#define EAUDIT_PID               %d
#define NETMASK1                 %x
#define NETMASK2                 %x
#define NETMASK3                 %x
#define NETADDR1                 %x
#define NETADDR2                 %x
#define NETADDR3                 %x
#define NS_TO_LOCAL_EP_EPOCH     %d
#define NS_TO_FOREIGN_EP_EPOCH   %d
""" % (os.getpid(), 
       IP4NETMASK1, IP4NETMASK2, IP4NETMASK3, 
       IP4NETADDR1, IP4NETADDR2, IP4NETADDR3,
       NS_TO_LOCAL_EP_EPOCH, NS_TO_FOREIGN_EP_EPOCH)

src += """
#define FLOOD_THETA          %dULL
#define FLOOD_THETA_REL      %dULL
#define FLOOD_THETA_SENTINEL %dULL
#define FLOOD_MIN_SENTINEL_COUNT %dULL
#define FLOOD_MIN_SENTINEL_CPU_NS %dULL
#define FLOOD_SENTINEL_FAST_MIN_NS %dULL
#define FLOOD_W_NS           %dULL
#define FLOOD_MIN_CPU_NS     %dULL
#define FLOOD_MIN_COUNT      %dULL
""" % (FLOOD_THETA, FLOOD_THETA_REL, FLOOD_THETA_SENTINEL,
       FLOOD_MIN_SENTINEL_COUNT, FLOOD_MIN_SENTINEL_CPU_NS,
       FLOOD_SENTINEL_FAST_MIN_NS,
       FLOOD_W_NS, FLOOD_MIN_CPU_NS, FLOOD_MIN_COUNT)

if ID_NOT_FD:
    src += "#define ID_NOT_FD\n" 

if filter_rw:
    src += "#define FILTER_REP_RDWR\n"
    if filter_dep:
        src += "#define FILTER_DEP\n"
    if filter_open:
        src += "#define FILTER_REP_OPEN\n" 
    if filter_instrument:
        src += "#define INSTRUMENT_CACHED_FDINFO\n" 
    if filter_size:
        src += "#define FILTER_SIZE\n" 
    if filter_diffpropagation:
        src += "#define FILTER_DIFF\n"
    if filter_lastpath:
        src += "#define FILTER_LASTPATH\n"
    if filter_sc_flood:
        src += "#define FILTER_SC_FLOOD\n"

# if filter_sc_flood:
#     src += "#define FILTER_SC_FLOOD\n"

if disable_lastwriter:
    src += "#define DISABLE_LASTWRITER\n"

if not update_remote_versions:
    src += "#define NO_REMOTE_VER\n"

src += "#define NUMCPU " + str(os.cpu_count()) + "\n";
if percpu_cache:
    src += "#define  PERCPU_CACHE\n"
else:
    if (flush_algo == 3):
        src += "#define FLUSH_CACHE_1\n"
        src += "#define FLUSH_CACHE_2\n"
    else:
        src += "#define FLUSH_CACHE_" + str(flush_algo) + "\n"

if tamper_detect:
    long_seqnum = True 
    src += "#define TAMPER_DETECT\n"
    if hash_algo == "UMAC3":
        src += "#define UMAC3\n"

if not long_seqnum:
    src += "#define  SHORT_SEQNUM\n"
if incl_procid:
    src += "#define  INCL_PROCID\n"

if REPORT_MMAP_ERRS:
    src += "#define  REPORT_MMAP_ERRS\n"
if REPORT_RDWR_ERRS:
    src += "#define  REPORT_RDWR_ERRS\n"
if REPORT_OPEN_ERRS:
    src += "#define  REPORT_OPEN_ERRS\n"

if debug_dep:
    src += "#define  FILTER_REASON\n"

src += open(ebpf_prog, "r").read();



b = BPF(text=src);
#b = BPF(text=src, debug=0x1);

try:
    _proc_state_map = b["proc_state"]
except KeyError:
    _proc_state_map = None
    if filter_sc_flood:
        eprint("[flood] proc_state map missing; density polling disabled")
else:
    if filter_sc_flood:
        eprint("[flood] proc_state map attached")

try:
    _flood_dbg_map = b["flood_dbg"]
except KeyError:
    _flood_dbg_map = None
    if filter_sc_flood:
        eprint("[flood] flood_dbg map missing")
else:
    if filter_sc_flood:
        eprint("[flood] flood_dbg map attached")

try:
   _flood_alerts_map = b["sc_flood_alerts"]
except KeyError:
    _flood_alerts_map = None
    if filter_sc_flood:
        eprint("[flood] sc_flood_alerts map missing; throttling alerts disabled")
else:
    if filter_sc_flood:
        eprint("[flood] sc_flood_alerts map attached")
        _start_flood_poller()


# Set up tail calls file descriptors for logging all argv and envp of execve.
#-------------------------------------------------------------------------------
fd_add_argv_1 = b.load_func("add_string_tail_argv", BPF.TRACEPOINT)
fd_add_envp_2 = b.load_func("add_string_tail_envp", BPF.TRACEPOINT)
prog_array = b.get_table("tailcall")
prog_array[ctypes.c_int(0)] = ctypes.c_int(fd_add_argv_1.fd)
prog_array[ctypes.c_int(1)] = ctypes.c_int(fd_add_envp_2.fd)

if tamper_detect:
    # Shared libraty for key generation
    #-----------------------------------------------------------------------
    keygen_lib = ctypes.CDLL("./libkeygen.so")

    # Define function signature for generating keys
    keygen_lib.generate_keys_and_load.argtypes = [ctypes.c_char_p, ctypes.c_int]
    keygen_lib.generate_keys_and_load.restype = ctypes.c_int
    keygen_lib.load_sync_key.argtypes = [ctypes.c_char_p, ctypes.c_int]
    keygen_lib.load_sync_key.restype = ctypes.c_int
    # Defining tailcall for tamper detection computation.
    #-------------------------------------------------------------------------#
    fd_add_umac3 = b.load_func("tailcall_umac3", BPF.TRACEPOINT)
    prog_array[ctypes.c_int(4)] = ctypes.c_int(fd_add_umac3.fd)

    # Loading maps for inserting computed keys.
    #-------------------------------------------------------------------------#
    key_set1 = b["keyset0"]
    map_fd1 = key_set1.get_fd()
    key_set2 = b["keyset1"]
    map_fd2 = key_set2.get_fd()
    sync_key = b["basekey"]
    map_fd0 = sync_key.get_fd()
    init_key = b["initkey"]
    map_fd3 = init_key.get_fd()

# First, stop logging.
log_level = b["log_level"];
log_level[ctypes.c_int(0)] = (ctypes.c_int*1) (1000);

if tamper_detect:
    initial_key = os.urandom(KEY_SIZE)
    # Load first initial key immediately
    key_buf = ctypes.create_string_buffer(initial_key)
    ret = keygen_lib.load_sync_key(key_buf, map_fd3)
    
    key_batch_set1 = (ctypes.c_ubyte * (TOTAL_KEYS * KEY_SIZE))()
    key_batch_set2 = (ctypes.c_ubyte * (TOTAL_KEYS * KEY_SIZE))()
    ret = keygen_lib.generate_keys_and_load(initial_key, map_fd1)
    if ret != 0:
        raise RuntimeError("Map update failed via kernel batch syscall")

time.sleep(2)

user_args.insert(0, clib)
init_args = [x.encode('utf-8') for x in user_args];
nargs = len(init_args)
init_args_c = (ctypes.c_char_p * nargs)(*init_args)
init_logger(ctypes.c_int(nargs), init_args_c)

#################################################################
# Load the ebpf program and listen to events
#################################################################
b["events"].open_ring_buffer(logprinter);

# Allow time for any events that were logged before the stop operation above.
# Complain if any bytes have been lost by now.
#
b.ring_buffer_consume()
time.sleep(0.1)
b.ring_buffer_consume()
stats = [v.value for (i, v) in b["mystat"].items()]
bytes_sent = stats[1]
if bytes_sent != nread() and verbosity >= 2:
    eprint("At start: bytes sent=%d differs from received=%d" % 
          (bytes_sent, nread()));

# Turn logging back on, proceed to normal operation
#
ierrcount = b["errcount"].values()
log_level[ctypes.c_int(0)] = (ctypes.c_int*1) (0);

stats = [v.value for (i, v) in b["mystat"].items()]
unexp_lkp_fail = stats[50]

# Can there be performance problems due to BCC's reliance on python? Unlikely
# since the main loop below has just one nontrivial operation, ring_buffer_poll,
# which is a function in __init__.py in bcc's python source code. That function
# is just a couple of lines, and makes a call to libbcc's C-code that defines
# ring_buffer_poll. The callback from that function is a C-function, so no
# Python overhead in the event handler either.

# The following thresholds are guesses. We should find the right values through
# extensive experimentation.

wakes_rcvd=0
bmsgs_rcvd = b["msgs_rcvd"]
try:
    while not killer.kill_now:
        # _drain_flood_alerts()
        # _release_flooded_pids()
        b.ring_buffer_poll()

        msgs_rcvd = do_write()
        bmsgs_rcvd[ctypes.c_int(0)] = (ctypes.c_long*1) (int(msgs_rcvd))
        if tamper_detect:
            key_index = int(b["seqn"].values()[0].value)
            key_index = key_index & 0xFFFF #sn & 0xFFFF   
            current_bank = int(b["bank_state"][ctypes.c_int(0)].current_bank)
            next_bank = int(b["bank_state"][ctypes.c_int(0)].next_bank)
            keygen_signal = (b["keygen_signal"][ctypes.c_int(0)].value)

            if (key_index > (30/100 * TOTAL_KEYS) and keygen_signal in [1, 2]):
                synckey = os.urandom(KEY_SIZE)
                key_buf = ctypes.create_string_buffer(synckey)
                ret = keygen_lib.load_sync_key(key_buf, map_fd0)
                if keygen_signal == 2:
                    ret = keygen_lib.generate_keys_and_load(key_buf, map_fd2)
                    b["keygen_signal"][ctypes.c_int(0)] = ctypes.c_int(0)
                else:
                    ret = keygen_lib.generate_keys_and_load(key_buf, map_fd1)
                    b["keygen_signal"][ctypes.c_int(0)] = ctypes.c_int(0)

        wakes_rcvd += 1

except KeyboardInterrupt:
    pass

finally:
    if _flood_poller is not None:
        _flood_stop.set()
        _flood_poller.join(timeout=1.0)
    if _adaptive_poller is not None:
        _adaptive_poller.join(timeout=1.0)

#################################################################
# Done: print stats/summary and exit
#################################################################

# In order to cleany empty out and stop logging, we should not produce any
# more log entries. So, we set the log level back to a very high value.

log_level[ctypes.c_int(0)] = (ctypes.c_int*1) (1000);

if (verbosity >= 3):
    eprint("Received interrupt, emptying ring buffer");

while True:
    prev_rcvd = nread();
    do_write();
    b.ring_buffer_consume()
    if (prev_rcvd == nread()):
        break;

time.sleep(0.1)

while True:
    prev_rcvd = nread();
    do_write();
    b.ring_buffer_consume()
    if (prev_rcvd == nread()):
        break;

do_write();
end_op()
time.sleep(0.01)

eprint('======================== Summary from logger =========================')

nzcounts = [(i.value, v.value) for (i, v) in b["count"].items() if v.value != 0];
stats = [v.value for (i, v) in b["mystat"].items()]
nsubj = stats[34]

if prt_summary:
    eprint("\nSystem call counts (%d new processes)"
           % nsubj);
    eprint("=======================================");
totsc=0;
for k, v in sorted(nzcounts, key=lambda itm: itm[1]):
    totsc += v;
    if (prt_summary):
        eprint("%3d: %6d" % (k, v));
if (prt_summary):
    eprint("-------------------");

rb_drops = stats[0];
if (rb_drops > 0) and (verbosity > 0):
    eprint("*** Dropped data *** Ring buffer output failed %d times" % rb_drops)

bytes_sent = stats[1]
bytes_got = nread();
msgs_sent = stats[2] and stats[2] or stats[2]+1;
if msgs_sent == 0:
    msgs_sent = 0.01
if totsc == 0:
    totsc = 0.01
wakes_sent = stats[3] and stats[3] or stats[3]+1;
nflushes = stats[51];
nflushchecks = stats[52];
if (verbosity > 0):
#  if prt_summary:
    eprint("%s Calls, %siB (%s lost), Size: call=%d record=%d\n" % \
      (pp(totsc), pp(bytes_got), pp(bytes_sent-bytes_got), \
       bytes_sent/totsc, bytes_sent/msgs_sent));

if verbosity >= 2:
  eprint("%d ringbuf calls with wakeup flag, %d without, %d actual wakes" % 
       (wakes_sent, msgs_sent-wakes_sent, wakes_rcvd));
  if nflushes > 0:
      eprint("%d flushes of an idle core's cache (%0.3f%% of syscalls)" \
             % (nflushes, nflushes*100.0/totsc))

fn_errs = stats[4];
if (fn_errs > 0) and (verbosity > 2):
    eprint("*** %d file names could not be retrieved ***" % fn_errs)

data_errs = stats[5];
if (data_errs > 0) and (verbosity > 2):
    eprint("*** %d data fields could not be retrieved ***" % data_errs)

argv_errs = stats[6];
if (argv_errs > 0) and (verbosity > 2):
    eprint("*** %d errors while reading argv or envp arrays ***" % argv_errs)

fcntl_errs = stats[7];
if (fcntl_errs > 0) and (verbosity > 0):
    eprint("*** %d errors in matching fcntl calls ***" % fcntl_errs)

saddr_errs = stats[8];
if (saddr_errs > 0) and (verbosity > 0):
    eprint("*** %d errors in matching receive socket addr calls ***" % saddr_errs)

pipe_errs = stats[9];
if (pipe_errs > 0) and (verbosity > 0):
    eprint("*** %d errors in matching pipe calls and returns ***" % pipe_errs)

mmap_errs = stats[10] and (verbosity > 0);
if (mmap_errs > 1):
    eprint("*** %d errors in matching mmap calls and returns ***" % mmap_errs)

rdwr_rec = stats[11];
rdwr_supp = stats[12];
if (rdwr_rec + rdwr_supp > 0) and (verbosity >= 2):
    eprint("*** %d read/writes, %d recorded ***" % (rdwr_rec+rdwr_supp, rdwr_rec))

str_trunc_err = stats[13];
if (str_trunc_err > 0) and (verbosity >= 2):
    eprint("*** %d strings were too long and were truncated ***" % (str_trunc_err))

data_trunc_err = stats[14];
data_ops = 0;
for i in range(14, 23):
    data_ops += stats[i]
if (data_trunc_err > 0) and (verbosity >= 2):
    if verbosity > 2 or data_trunc_err * 100 > data_ops:
        eprint("*** %d of %d data operations were too long and were truncated ***" 
               % (data_trunc_err, data_ops))

for i in range(16, 23):
    ct = stats[i]
    if (verbosity > 2 and ct > 0  or verbosity == 2 and ct*1000 > data_ops):
        eprint("*** %d data read errors of kind %d ***" % (ct, i))

idgen = stats[29];
idgenerrs = stats[28];
if (idgen > 0) and (verbosity >= 2):
    if (verbosity > 2 and idgenerrs > 0) or idgenerrs*300 > idgen:
        eprint("*** %d fdtoid calls, %d errors ***" % (idgen, idgenerrs))

for i in range(23, 28):
    ct = stats[i]
    if (verbosity > 2 and ct > 0)  or (verbosity == 2 and ct*1000000 > idgen):
        eprint("*** %0.3f%% id gen errors of kind %d ***" % (ct*100.0/idgen, i))

ct = stats[30]
if ct > 0:
    eprint("****** %d subjid hard failures ******" % (ct))

ct = stats[31]
if verbosity > 2 or (verbosity==2 and (ct > 100 and ct*1000 > nsubj)):
    eprint("*** Too many (%d) unknown or deleted subjects: ***" % (ct))
    eprint("*** Too many (%d) unknown or deleted subjects at rdwr: ***" % (stats[57]))

ct = stats[32]
if (verbosity > 2 and ct > 0) or (verbosity==2 and ct*10000 > nsubj):
    eprint("*** Too many (%d) instances of unfreed subjinfo: ***" % (ct))

ct = stats[33]
if (verbosity > 2 and ct > 0) or (verbosity==2 and ct*10000 > nsubj):
    eprint("*** Too many (%d) subjects with too many threads: ***" % (ct))

ct = stats[35]
if ct > 0:
    eprint("****** %d objid hard failures ******" % (ct))

ct = stats[36]
if (verbosity > 2 and ct > 0) or (verbosity==2 and (ct > 100 and ct*1000 > idgen)):
    eprint("*** Too many (%d) unknown or deleted objects: ***" % (ct))

ct = stats[37]
if (verbosity > 2 and ct > 0) or (verbosity==2 and (ct > 20 and ct*5000 > idgen)):
    eprint("*** Too many objects (%d) used by too many subjects: ***" % (ct))

ct = stats[48]
if (verbosity >= 2 and ct > 0):
    eprint("*** %d syscalls lost due to lock contention: ***" % (ct))

ct = stats[58]
if (verbosity >= 2 and ct > 0):
    eprint("*** %d syscalls MAC generation failure: ***" % (ct))

ct = stats[49]
if (verbosity >= 2 and ct > 0):
    eprint("*** %d unexpected map lookup failures: ***" % (ct))

arg_lookup_fail = stats[50] - unexp_lkp_fail
if (verbosity > 0 and arg_lookup_fail*500 > totsc): 
    eprint("*** %0.2f%% unexpected argument lookup failures: ***" % 
           (arg_lookup_fail*100.0/totsc));
    if arg_lookup_fail*200 > totsc: 
        eprint("\tSysCall #errors")
        errcount = b["errcount"].values()
        for i in range(0, len(ierrcount)):
            e = errcount[i].value - ierrcount[i].value
            if e > 0:
                eprint("\t%d\t%d" % (i, e))

reuse_opens = stats[38];
new_opens = stats[39];
missed_reuse = stats[40];
deleted_fi = stats[41];
deleted_fdi = stats[42];
if (reuse_opens > 0) and (verbosity >= 2):
  if missed_reuse > 0:
    eprint("*** %d opens, %d recorded, %d reuse opportunities missed ***" % 
           (reuse_opens+new_opens, new_opens, missed_reuse))
  else:
    eprint("*** %d opens, %d recorded ***" % (reuse_opens+new_opens, new_opens))

ct = deleted_fdi;
if (verbosity > 2 and ct > 0) or (verbosity==2 and 
                                  (ct > 500 and ct*100 > (rdwr_supp+rdwr_rec))):
    eprint("*** Too many fds (%d) uninitialized: ***" % (ct));

if (deleted_fi > 0 and verbosity > 0):
    eprint("*** Too many fileinfo (%d) unfound: ***" % (deleted_fi));

for i in range(43, 48):
    ct = stats[i];
    if (ct > 0 and verbosity > 0):
        eprint("*** %d data errors of kind %d ***" % (ct, i))

if machine_friendly:
    eprint("%ssyscalls %d" % (machine_friendly, totsc))
    eprint("%ssent %d" % (machine_friendly, bytes_sent))
    eprint("%slost %d" % (machine_friendly, bytes_sent-bytes_got))
    eprint("%savgcallsize %d" % (machine_friendly, bytes_sent/totsc))
    eprint("%savgcachesize %d" % (machine_friendly, bytes_sent/msgs_sent))
    eprint("%savgp %d" % (machine_friendly, (totsc+msgs_sent-1)/msgs_sent))
    eprint("%savgw %d" % (machine_friendly, (msgs_sent+wakes_rcvd-1)/wakes_rcvd))
    # if filter_sc_flood:
    #     throttle_status = "throttled" if (_total_throttled_procs > 0 or len(_parent_throttled) > 0) else "not_throttled"
    #     eprint("%sthrottling_status %s" % (machine_friendly, throttle_status))
    #     eprint("%sthrottled_procs %d" % (machine_friendly, _total_throttled_procs))
    #     eprint("%sthrottled_parents %d" % (machine_friendly, len(_parent_throttled)))

    if filter_rw:
        eprint("%stot_rdwr %d" % (machine_friendly, rdwr_rec+rdwr_supp))
        eprint("%srec_rdwr %d" % (machine_friendly, rdwr_rec))
        eprint("%stot_open %d" % (machine_friendly, reuse_opens+new_opens))
        eprint("%srec_open %d" % (machine_friendly, new_opens))
        eprint("%sfi_fail %0.2f%%" % (machine_friendly, (deleted_fi*100)/(rdwr_rec+rdwr_supp)))
    if ID_NOT_FD:
        eprint("%sid_fail %0.2f%%" % (machine_friendly, (idgenerrs*100)/idgen))
    eprint("%sarg_fail %0.2f%%" % (machine_friendly, (arg_lookup_fail*100)/totsc))

# @@@@ Remove these later
eprint("MED_RDWR_LOGGED %d" % (stats[53]))
eprint("TOO_LARGE_LOGGED %d" % (stats[54]))
eprint("TOO_SMALL_SKIPPED %d" % (stats[55]))
eprint("ZERO_RDWR_SKIPPED %d" % (stats[56]))

if verbosity > 2:
    #b["fduse"].print_log2_hist("fd#")
    #print(" ")
    b["msg_delivery_lag"].print_log2_hist("queued messages (#)")
    b["cache_flush_lag"].print_log2_hist("cache_flush_lag (us)")

eprint('====================== END Summary from logger ======================')
time.sleep(0.01)


# Performance effects of some of the less performance-sensitive options:
# On LG17, kernel 6.2.0-26, fbm2 4 16
# Base: 6.2/26s
# ./ecapd -v0 -C -l -S: Agent: 0.7 Benchmark: 7.9/32.3
# ./ecapd -v0 -C -l   : Agent: 0.6 Benchmark: 8.1/33.5
# ./ecapd -v0 -C      : Agent: 0.7 Benchmark: 8.1/33.5
# ./ecapd -v0         : Agent: 0.8 Benchmark: 8.2/34
# Summary: -l flag has negligible effect.
#          -S is potentially the most overhead-inducing but too important.
#          -C has minimal impact as well. 
# Conclusion: Eliminate -l and -S, continue current default for -C.
