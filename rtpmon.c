#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
#include <errno.h>
#include <rtpmon.h>

void rtpmon_init(void) {
    rtpmon.active        = 0;
    rtpmon.qpath         = RTPMON_DEFAULT_QPATH;
    rtpmon.qlen          = RTPMON_DEFAULT_QLEN;
    rtpmon.dump_interval = RTPMON_DEFAULT_DUMP_INTERVAL;
    rtpmon.error         = NULL;
    rtpmon.sampleno      = 0;
}

/* sets rtpmon.error in case of troubles */
void
rtpmon_parse_options(char *argument) {
    char *tok,*kv,*k,*v,*tokpos;
    char error[256];
    for (tok = strtok_r(argument, ",",&tokpos); tok && !rtpmon.error; tok = strtok_r(NULL, ",",&tokpos)) {
        if (tok) {
            kv = strdup(tok);
            k = strtok(kv,"=");
            v = strtok(NULL,"=");
            if (strcmp(k,"qpath") == 0) {
                if (v && strlen(v)) {
                    /* no checks made here, let fwrite fail later on */
                    rtpmon.qpath = strdup(v);
                    while (rtpmon.qpath[strlen(rtpmon.qpath)-1] == '/') { //TODO: assumes we're on Unix
                        rtpmon.qpath[strlen(rtpmon.qpath)-1] = 0;
                    }
                } else {
                    rtpmon.error = "Empty value for \"qpath\"";
                }
            } else if (strcmp(k,"qlen") == 0) {
                if (v && strlen(v)) {
                    rtpmon.qlen = strtol(v,NULL,10);
                    if (rtpmon.qlen < 1 || rtpmon.qlen > 10000) {
                        rtpmon.error = "\"qlen\" is either invalid or outside of the [1,10000] range";
                    }
                } else {
                    rtpmon.error = "Empty value for \"qlen\"";
                }
            } else if (strcmp(k,"dump-interval") == 0) {
                if (v && strlen(v)) {
                    rtpmon.dump_interval = strtol(v,NULL,10);
                    if (rtpmon.dump_interval < 500 || rtpmon.dump_interval > (1000*60*60*24)) {
                        rtpmon.error = "\"dump-interval\" is either invalid or outside of the [500,(1000*60*60*24)] range";
                    }
                } else {
                    rtpmon.error = "Empty value for \"dump-interval\"";
                }
            } else {
                snprintf(error,sizeof(error),"Unknown option: %s",k);
                rtpmon.error = strdup(error);
            }
        }
    }
}
