/* rtpmon.h
 */

#ifndef RTPMON_H_INCLUDED
#define RTPMON_H_INCLUDED

#define RTPMON_DEFAULT_QPATH         "/tmp"
#define RTPMON_DEFAULT_QLEN          1800
#define RTPMON_DEFAULT_DUMP_INTERVAL 1000

struct {
    int   active;
    char* qpath;
    int   qlen;
    int   dump_interval;
    char* error;
    int   sampleno;  /* Sample number (counter). Wraps around at qlen. */
} rtpmon;

void rtpmon_init(void);
void rtpmon_parse_options(char *argument);

#endif /*RTPMON_H_INCLUDED*/
