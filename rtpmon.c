#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
#include <errno.h>
#include "rtpmon.h"

void rtpmon_init(void) {
    rtpmon.active        = 0;
    rtpmon.qpath         = RTPMON_DEFAULT_QPATH;
    rtpmon.qlen          = RTPMON_DEFAULT_QLEN;
    rtpmon.dump_interval = RTPMON_DEFAULT_DUMP_INTERVAL;
    rtpmon.error         = NULL;
    rtpmon.sampleno      = 0;
    rtpmon.last_dump     = 0;
}

/* in case of troubles, sets rtpmon.error to a non empty value */
void
rtpmon_parse_options(char *argument) {
    char *tok,*kv,*k,*v,*tokpos;
    char error[256];
    if (argument && argument[0] == '-') {
        rtpmon.error = "-M requires an argument (i.e.: -M on)";
        return;
    }
    for (tok = strtok_r(argument, ",",&tokpos); tok && !rtpmon.error; tok = strtok_r(NULL, ",",&tokpos)) {
        if (tok) {
            kv = strdup(tok);
            k = strtok(kv,"=");
            v = strtok(NULL,"=");
            if (strcmp(k,"on") == 0) {
            } else if (strcmp(k,"qpath") == 0) {
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
            } else if (strcmp(k,"describe-output") == 0) {
                rtpmon_describe_rtp_stream_info();
                rtpmon.error = "";
            } else {
                snprintf(error,sizeof(error),"Unknown option: %s",k);
                rtpmon.error = strdup(error);
            }
        }
    }
}

/* returns 0 upon failure */
/* TODO: upon failure, should we abort the whole capture? */
int
rtpmon_dump_sample(rtpstream_tapinfo_t *tapinfo) {
    FILE *fp;
    char filename[256];
    char sampleno_string[16];
    size_t rc;
    size_t written;
    GList *list;
    rtp_stream_info_t* strinfo;
    if (rtpmon.sampleno >= rtpmon.qlen) rtpmon.sampleno = 0;
    rc = snprintf(filename,sizeof(filename),"%s/rtpmon%05d.bin",rtpmon.qpath,rtpmon.sampleno); //TODO: assumes we're on Unix
    if (rc >= sizeof(filename)) {
        fprintf(stderr,"Maximum filename length exceeded (%d/%d)\n",(int)rc,(int)sizeof(filename));
        return 0;
    }
    fp = fopen(filename,"w+");
    if (fp == NULL) {
        perror("Error opening file");
        return 0;
    }
    list = tapinfo->strinfo_list;
    list = g_list_first(list);
    while (list) {
        strinfo = (rtp_stream_info_t*)(list->data);
        //printf("pt: %d\n", ((char*)(strinfo))[offsetof(rtp_stream_info_t,pt)]);
        written = fwrite(strinfo,sizeof(rtp_stream_info_t),1,fp);
        if (written != 1) {
            perror("Error writing to file");
            return 0;
        }
        written = fwrite(strinfo->src_addr.data,1,strinfo->src_addr.len,fp);
        if (written != (unsigned)strinfo->src_addr.len) {
            perror("Error writing to file");
            return 0;
        }
        written = fwrite(strinfo->dest_addr.data,1,strinfo->dest_addr.len,fp);
        if (written != (unsigned)strinfo->dest_addr.len) {
            perror("Error writing to file");
            return 0;
        }
        list = g_list_next(list);
    }
    rc = fclose(fp);
    if (rc != 0) {
        perror("Error closing file");
    }
    /* writes the "end pointer" */
    rc = snprintf(filename,sizeof(filename),"%s/rtpmonlast.txt",rtpmon.qpath); //TODO: assumes we're on Unix
    if (rc >= sizeof(filename)) {
        fprintf(stderr,"Maximum filename length exceeded (%d/%d)\n",(int)rc,(int)sizeof(filename));
        return 0;
    }
    fp = fopen(filename,"w+");
    if (fp == NULL) {
        perror("Error opening file");
        return 0;
    }
    snprintf(sampleno_string,sizeof(sampleno_string),"%d\n",rtpmon.sampleno);
    written = fwrite(sampleno_string,strlen(sampleno_string),1,fp);
    if (written != 1) {
        perror("Error writing to file");
        return 0;
    }
    rc = fclose(fp);
    if (rc != 0) {
        perror("Error closing file");
    }
    rtpmon.sampleno++;
    return 1;
}

void
rtpmon_describe_rtp_stream_info(void) {
    printf("rtp_stream_info_t            (size,ofs)(%4d,----):\n",(int)sizeof(rtp_stream_info_t));
    printf("address         src_addr               (%4d,%4d)\n", (int)sizeof(address)         , (int)offsetof(rtp_stream_info_t,src_addr));
    printf("guint16         src_port               (%4d,%4d)\n", (int)sizeof(guint16)         , (int)offsetof(rtp_stream_info_t,src_port));
    printf("address         dest_addr              (%4d,%4d)\n", (int)sizeof(address)         , (int)offsetof(rtp_stream_info_t,dest_addr));
    printf("guint16         dest_port              (%4d,%4d)\n", (int)sizeof(guint16)         , (int)offsetof(rtp_stream_info_t,dest_port));
    printf("guint32         ssrc                   (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(rtp_stream_info_t,ssrc));
    printf("guint8          pt                     (%4d,%4d)\n", (int)sizeof(guint8)          , (int)offsetof(rtp_stream_info_t,pt));
    printf("gchar           *info_payload_type_str (%4d,%4d)\n", (int)sizeof(gchar*)          , (int)offsetof(rtp_stream_info_t,info_payload_type_str));
    printf("guint32         npackets               (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(rtp_stream_info_t,npackets));
    printf("guint32         first_frame_num        (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(rtp_stream_info_t,first_frame_num));
    printf("guint32         setup_frame_number     (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(rtp_stream_info_t,setup_frame_number));
    printf("guint32         start_sec              (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(rtp_stream_info_t,start_sec));
    printf("guint32         start_usec             (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(rtp_stream_info_t,start_usec));
    printf("gboolean        tag_vlan_error         (%4d,%4d)\n", (int)sizeof(gboolean)        , (int)offsetof(rtp_stream_info_t,tag_vlan_error));
    printf("guint32         start_rel_sec          (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(rtp_stream_info_t,start_rel_sec));
    printf("guint32         start_rel_usec         (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(rtp_stream_info_t,start_rel_usec));
    printf("guint32         stop_rel_sec           (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(rtp_stream_info_t,stop_rel_sec));
    printf("guint32         stop_rel_usec          (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(rtp_stream_info_t,stop_rel_usec));
    printf("gboolean        tag_diffserv_error     (%4d,%4d)\n", (int)sizeof(gboolean)        , (int)offsetof(rtp_stream_info_t,tag_diffserv_error));
    printf("guint16         vlan_id                (%4d,%4d)\n", (int)sizeof(guint16)         , (int)offsetof(rtp_stream_info_t,vlan_id));
    printf("tap_rtp_stat_t  rtp_stats              (%4d,%4d)\n", (int)sizeof(tap_rtp_stat_t)  , (int)offsetof(rtp_stream_info_t,rtp_stats));
    printf("gboolean        problem                (%4d,%4d)\n", (int)sizeof(gboolean)        , (int)offsetof(rtp_stream_info_t,problem));
    printf("\n");
    printf("tap_rtp_stat_t               (size,ofs)(%4d,----):\n",(int)sizeof(tap_rtp_stat_t));
    printf("gboolean        first_packet           (%4d,%4d)\n", (int)sizeof(gboolean)        , (int)offsetof(tap_rtp_stat_t,first_packet));
    printf("guint32         flags                  (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(tap_rtp_stat_t,flags));
    printf("guint16         seq_num                (%4d,%4d)\n", (int)sizeof(guint16)         , (int)offsetof(tap_rtp_stat_t,seq_num));
    printf("guint32         timestamp              (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(tap_rtp_stat_t,timestamp));
    printf("guint32         first_timestamp        (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(tap_rtp_stat_t,first_timestamp));
    printf("guint32         delta_timestamp        (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(tap_rtp_stat_t,delta_timestamp));
    printf("double          bandwidth              (%4d,%4d)\n", (int)sizeof(double)          , (int)offsetof(tap_rtp_stat_t,bandwidth));
    printf("bw_history_item bw_history[BUFF_BW]    (%4d,%4d)\n", (int)sizeof(bw_history_item)*BUFF_BW , (int)offsetof(tap_rtp_stat_t,bw_history));
    printf("                           BUFF_BW = %d\n", BUFF_BW);
    printf("guint16         bw_start_index         (%4d,%4d)\n", (int)sizeof(guint16)         , (int)offsetof(tap_rtp_stat_t,bw_start_index));
    printf("guint16         bw_index               (%4d,%4d)\n", (int)sizeof(guint16)         , (int)offsetof(tap_rtp_stat_t,bw_index));
    printf("guint32         total_bytes            (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(tap_rtp_stat_t,total_bytes));
    printf("guint32         clock_rate             (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(tap_rtp_stat_t,clock_rate));
    printf("double          delta                  (%4d,%4d)\n", (int)sizeof(double)          , (int)offsetof(tap_rtp_stat_t,delta));
    printf("double          jitter                 (%4d,%4d)\n", (int)sizeof(double)          , (int)offsetof(tap_rtp_stat_t,jitter));
    printf("double          diff                   (%4d,%4d)\n", (int)sizeof(double)          , (int)offsetof(tap_rtp_stat_t,diff));
    printf("double          skew                   (%4d,%4d)\n", (int)sizeof(double)          , (int)offsetof(tap_rtp_stat_t,skew));
    printf("double          sumt                   (%4d,%4d)\n", (int)sizeof(double)          , (int)offsetof(tap_rtp_stat_t,sumt));
    printf("double          sumTS                  (%4d,%4d)\n", (int)sizeof(double)          , (int)offsetof(tap_rtp_stat_t,sumTS));
    printf("double          sumt2                  (%4d,%4d)\n", (int)sizeof(double)          , (int)offsetof(tap_rtp_stat_t,sumt2));
    printf("double          sumtTS                 (%4d,%4d)\n", (int)sizeof(double)          , (int)offsetof(tap_rtp_stat_t,sumtTS));
    printf("double          time                   (%4d,%4d)\n", (int)sizeof(double)          , (int)offsetof(tap_rtp_stat_t,time));
    printf("double          start_time             (%4d,%4d)\n", (int)sizeof(double)          , (int)offsetof(tap_rtp_stat_t,start_time));
    printf("double          lastnominaltime        (%4d,%4d)\n", (int)sizeof(double)          , (int)offsetof(tap_rtp_stat_t,lastnominaltime));
    printf("double          max_delta              (%4d,%4d)\n", (int)sizeof(double)          , (int)offsetof(tap_rtp_stat_t,max_delta));
    printf("double          max_jitter             (%4d,%4d)\n", (int)sizeof(double)          , (int)offsetof(tap_rtp_stat_t,max_jitter));
    printf("double          max_skew               (%4d,%4d)\n", (int)sizeof(double)          , (int)offsetof(tap_rtp_stat_t,max_skew));
    printf("double          mean_jitter            (%4d,%4d)\n", (int)sizeof(double)          , (int)offsetof(tap_rtp_stat_t,mean_jitter));
    printf("guint32         max_nr                 (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(tap_rtp_stat_t,max_nr));
    printf("guint16         start_seq_nr           (%4d,%4d)\n", (int)sizeof(guint16)         , (int)offsetof(tap_rtp_stat_t,start_seq_nr));
    printf("guint16         stop_seq_nr            (%4d,%4d)\n", (int)sizeof(guint16)         , (int)offsetof(tap_rtp_stat_t,stop_seq_nr));
    printf("guint32         total_nr               (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(tap_rtp_stat_t,total_nr));
    printf("guint32         sequence               (%4d,%4d)\n", (int)sizeof(guint32)         , (int)offsetof(tap_rtp_stat_t,sequence));
    printf("gboolean        under                  (%4d,%4d)\n", (int)sizeof(gboolean)        , (int)offsetof(tap_rtp_stat_t,under));
    printf("gint            cycles                 (%4d,%4d)\n", (int)sizeof(gint)            , (int)offsetof(tap_rtp_stat_t,cycles));
    printf("guint16         pt                     (%4d,%4d)\n", (int)sizeof(guint16)         , (int)offsetof(tap_rtp_stat_t,pt));
    printf("int             reg_pt                 (%4d,%4d)\n", (int)sizeof(int)             , (int)offsetof(tap_rtp_stat_t,reg_pt));
    printf("\n");
    printf("bw_history_item              (size,ofs)(%4d,----):\n",(int)sizeof(bw_history_item));
    printf("double          time                   (%4d,%4d)\n", (int)sizeof(double)         , (int)offsetof(bw_history_item,time));
    printf("guint32         bytes                  (%4d,%4d)\n", (int)sizeof(guint32)        , (int)offsetof(bw_history_item,bytes));
    printf("\n");
    printf("address                      (size,ofs)(%4d,----):\n",(int)sizeof(address));
    printf("address_type    type                   (%4d,%4d)\n", (int)sizeof(address_type)    , (int)offsetof(address,type));
    printf("int             len                    (%4d,%4d)\n", (int)sizeof(int)             , (int)offsetof(address,len));
    printf("void            *data                  (%4d,%4d)\n", (int)sizeof(const void*)     , (int)offsetof(address,data));
}
