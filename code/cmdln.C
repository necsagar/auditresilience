#include "cmdln.h"

void prtUsage(int argc, const char* argv[], const char *msg="") {
 if (msg && *msg)
    fprintf(stderr, "Error: %s.\n", msg);
 fprintf(stderr, "Usage: %s ", argv[0]);
 fprintf(stderr, 
  " [-#] [-f flushInterval] [-l logLevel] [-L] [-u] [-v] [-w width]\n"
  "[-[I|C] <auditFile>] [-P <printFile>]\n"
  "  -#: indicates that processor core #s are included in capture file\n"
  "  -C <file>: store captured records to the specified file.\n"
  "     <file> can be of the form [<protocol>:[//<host]/]]<filename> where:\n"
  "       -- <protocol> is one of ssh, gzip, gzipfast, ssh+gzip, ssh+gzipfast,\n"
  "          gzip+ssh, or gzipfast+ssh.\n"
  "       -- <host> is of the form [user@]remhost, and\n"
  "       -- <filename> is a simple file name.\n"
  "  -f <num>: flush idle caches every <num> seconds, e.g., 0.001.\n"
  "  -I: specify the input capture file.\n"
  "  -l logLevel: specify logging level, defaults to %d.\n", ERRLEVEL);
 fprintf(stderr,
  "  -L: input contains 32-bit sequence numbers instead of the default 16-bit.\n"
  "  -P: print syscalls in readable format immediately on parsing.\n"
  "  -t <n>: Set a tamper window n times the flush interval.\n"
  "  -u: use microsecond granularity timestamp when printing.\n"
  "  -v: specify the hashing algorithm (siphash | umac1 | umac3)\n"
  "  -w width: format output for display with width columns.\n"
  "This program can operate online or offline. In online mode, captured syscall\n"
  "records are processed by this program and saved to a capture file. In offline\n"
  "mode, an input capture file is read and printed. Not all options are\n"
  "meaningful in both modes."
  "\nFile names can be specified as \"-\" to denote stdin/stdout. If -I option\n"
  "is missing in offline mode, records are read from stdin.\n");
  exit(1);
}

bool online_mode=false;
bool use_procid = false;
const char* capturefn=nullptr, *prtpfn=nullptr;
float flushInterval;
int logLevel=ERRLEVEL; // WARNLEVEL, ERRLEVEL, etc. Zero means don't complain
bool long_seqnum=false;
bool prtInParser=false, prt_musec_ts=false;
bool verifyLog=false;
long tamperWindow;
int width=80;
int hash_algo = 3;            //using UMAC3 as default algorithm 

void
parseCmdLine(int argc, const char* argv[]) {
   for (int i=1; i < argc; i++) {
      if (argv[i][0] == '-') {
         switch (argv[i][1]) {
         case '#':
            use_procid = !use_procid;
            break;

         case 'C':
         case 'I':
            if (++i >= argc)
               prtUsage(argc, argv, "-I and -C options require a filename");
            capturefn = argv[i];
            break;

         case 'f':
            if (++i >= argc)
               prtUsage(argc, argv, "-f option require a numeric argument");
            sscanf(argv[i], "%g", &flushInterval);
            break;

         case 'h':
            prtUsage(argc, argv);
            break;

         case 'l':
            if (++i >= argc ||
                (sscanf(argv[i], "%d", &logLevel) < 1))
               prtUsage(argc, argv, "-l option requires a loglevel argument");
            break;

         case 'L':
            long_seqnum = true;
            break;

         case 'P':
            prtInParser = true;
            if (++i >= argc || !*(argv[i]))
               prtUsage(argc, argv, "-P option requires a filename");
            prtpfn = argv[i];
            break;

         case 't':
            if (++i >= argc ||
                (sscanf(argv[i], "%ld", &tamperWindow) < 1))
               prtUsage(argc, argv, "-t option requires an integer argument");
            if (10 > tamperWindow || tamperWindow > 1000)
               prtUsage(argc, argv, "-t: valid argument range is 10 to 1000");
            break;

         case 'u':
            prt_musec_ts = true;
            break;

         case 'v':
            verifyLog = true;
            hash_algo = 3;
            break;
            

         case 'w':
            if (++i >= argc ||
                (sscanf(argv[i], "%d", &width) < 1)) {
               i--;
               width = 132;
            }
            break;

         default: prtUsage(argc, argv, "Unrecognized option"); break;
         }
      }
   }
}
