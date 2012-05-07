/* rtpmon.h
 */

#ifndef RTPMON_H_INCLUDED
#define RTPMON_H_INCLUDED

#include <glib.h>
#include "ui/gtk/rtp_stream.h"

#define RTPMON_DEFAULT_QPATH         "/tmp"
#define RTPMON_DEFAULT_QLEN          1800
#define RTPMON_DEFAULT_DUMP_INTERVAL 1000

/*
 * TODO
 * - Errors might get printed at dump-interval rate. Fix this.
 */

struct {
    int     active;
    char*   qpath;
    int     qlen;
    int     dump_interval;
    char*   error;
    int     sampleno;  /* Sample number (counter). Wraps around at qlen. */
    guint32 last_dump; /* When (in msecs since the beginning of the capture), the last sample has been dumped */
} rtpmon;

void rtpmon_init(void);
void rtpmon_parse_options(char *argument);
int  rtpmon_dump_sample(rtpstream_tapinfo_t *tapinfo);
void rtpmon_describe_rtp_stream_info(void);

#endif /*RTPMON_H_INCLUDED*/
