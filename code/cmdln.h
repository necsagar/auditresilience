#ifndef CMDLN_H
#define CMDLN_H
#include "Base.h"

extern bool online_mode, use_procid;
extern const char* capturefn;
extern const char *prtpfn;
extern float flushInterval;
extern int logLevel;
extern bool long_seqnum;
extern bool prtInParser, prt_musec_ts;
extern long tamperWindow;
extern int width;

void parseCmdLine(int argc, const char* argv[]);
#endif
