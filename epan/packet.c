/* packet.c
 * Routines for packet disassembly
 *
 * $Id: packet.c,v 1.29 2001/04/01 05:48:15 hagbard Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif

#include <glib.h>

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#include <string.h>
#include <ctype.h>
#include <time.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef NEED_INET_V6DEFS_H
# include "inet_v6defs.h"
#endif

#include "packet.h"
#include "timestamp.h"

#include "atalk-utils.h"
#include "packet-frame.h"
#include "packet-ipv6.h"
#include "sna-utils.h"
#include "packet-vines.h"
#include "osi-utils.h"
#include "to_str.h"

#include "resolv.h"
#include "tvbuff.h"
#include "plugins.h"

void
packet_init(void)
{
  /* nothing */
}

void
packet_cleanup(void)
{
	/* nothing */
}

/* Allocate all the data structures for constructing column data, given
   the number of columns. */
void
col_init(column_info *col_info, gint num_cols)
{
  col_info->num_cols	= num_cols;
  col_info->col_fmt	= (gint *) g_malloc(sizeof(gint) * num_cols);
  col_info->fmt_matx	= (gboolean **) g_malloc(sizeof(gboolean *) * num_cols);
  col_info->col_width	= (gint *) g_malloc(sizeof(gint) * num_cols);
  col_info->col_title	= (gchar **) g_malloc(sizeof(gchar *) * num_cols);
  col_info->col_data	= (gchar **) g_malloc(sizeof(gchar *) * num_cols);
  col_info->col_buf	= (gchar **) g_malloc(sizeof(gchar *) * num_cols);
}

gboolean
col_get_writable(frame_data *fd)
{
  if (fd) {

    return (fd->cinfo ? fd->cinfo->writable : FALSE);

  }

  return FALSE;

}

void
col_set_writable(frame_data *fd, gboolean writable)
{
	if (fd->cinfo) {
		fd->cinfo->writable = writable;
	}
}

/* Checks to see if a particular packet information element is needed for
   the packet list */
gint
check_col(frame_data *fd, gint el) {
  int i;

  if (fd->cinfo && fd->cinfo->writable) {
    for (i = 0; i < fd->cinfo->num_cols; i++) {
      if (fd->cinfo->fmt_matx[i][el])
        return TRUE;
    }
  }
  return FALSE;
}

/* Use this to clear out a column, especially if you're going to be
   appending to it later; at least on some platforms, it's more
   efficient than using "col_add_str()" with a null string, and
   more efficient than "col_set_str()" with a null string if you
   later append to it, as the later append will cause a string
   copy to be done. */
void
col_clear(frame_data *fd, gint el) {
  int    i;

  for (i = 0; i < fd->cinfo->num_cols; i++) {
    if (fd->cinfo->fmt_matx[i][el]) {
      fd->cinfo->col_buf[i][0] = 0;
      fd->cinfo->col_data[i] = fd->cinfo->col_buf[i];
    }
  }
}

/* Use this if "str" points to something that will stay around (and thus
   needn't be copied). */
void
col_set_str(frame_data *fd, gint el, gchar* str) {
  int i;
  
  for (i = 0; i < fd->cinfo->num_cols; i++) {
    if (fd->cinfo->fmt_matx[i][el])
      fd->cinfo->col_data[i] = str;
  }
}

/* Adds a vararg list to a packet info string. */
void
col_add_fstr(frame_data *fd, gint el, gchar *format, ...) {
  va_list ap;
  int     i;
  size_t  max_len;

  if (el == COL_INFO)
	max_len = COL_MAX_INFO_LEN;
  else
	max_len = COL_MAX_LEN;
  
  va_start(ap, format);
  for (i = 0; i < fd->cinfo->num_cols; i++) {
    if (fd->cinfo->fmt_matx[i][el]) {
      vsnprintf(fd->cinfo->col_buf[i], max_len, format, ap);
      fd->cinfo->col_data[i] = fd->cinfo->col_buf[i];
    }
  }
}

/* Use this if "str" points to something that won't stay around (and
   must thus be copied). */
void
col_add_str(frame_data *fd, gint el, const gchar* str) {
  int    i;
  size_t max_len;

  if (el == COL_INFO)
	max_len = COL_MAX_INFO_LEN;
  else
	max_len = COL_MAX_LEN;
  
  for (i = 0; i < fd->cinfo->num_cols; i++) {
    if (fd->cinfo->fmt_matx[i][el]) {
      strncpy(fd->cinfo->col_buf[i], str, max_len);
      fd->cinfo->col_buf[i][max_len - 1] = 0;
      fd->cinfo->col_data[i] = fd->cinfo->col_buf[i];
    }
  }
}

/* Appends a vararg list to a packet info string. */
void
col_append_fstr(frame_data *fd, gint el, gchar *format, ...) {
  va_list ap;
  int     i;
  size_t  len, max_len;
  
  if (el == COL_INFO)
	max_len = COL_MAX_INFO_LEN;
  else
	max_len = COL_MAX_LEN;
  
  va_start(ap, format);
  for (i = 0; i < fd->cinfo->num_cols; i++) {
    if (fd->cinfo->fmt_matx[i][el]) {
      if (fd->cinfo->col_data[i] != fd->cinfo->col_buf[i]) {
      	/* This was set with "col_set_str()"; copy the string they
	   set it to into the buffer, so we can append to it. */
	strncpy(fd->cinfo->col_buf[i], fd->cinfo->col_data[i], max_len);
	fd->cinfo->col_buf[i][max_len - 1] = '\0';
      }
      len = strlen(fd->cinfo->col_buf[i]);
      vsnprintf(&fd->cinfo->col_buf[i][len], max_len - len, format, ap);
      fd->cinfo->col_data[i] = fd->cinfo->col_buf[i];
    }
  }
}

void
col_append_str(frame_data *fd, gint el, gchar* str) {
  int    i;
  size_t len, max_len;

  if (el == COL_INFO)
	max_len = COL_MAX_INFO_LEN;
  else
	max_len = COL_MAX_LEN;
  
  for (i = 0; i < fd->cinfo->num_cols; i++) {
    if (fd->cinfo->fmt_matx[i][el]) {
      if (fd->cinfo->col_data[i] != fd->cinfo->col_buf[i]) {
      	/* This was set with "col_set_str()"; copy the string they
	   set it to into the buffer, so we can append to it. */
	strncpy(fd->cinfo->col_buf[i], fd->cinfo->col_data[i], max_len);
	fd->cinfo->col_buf[i][max_len - 1] = '\0';
      }
      len = strlen(fd->cinfo->col_buf[i]);
      strncat(fd->cinfo->col_buf[i], str, max_len - len);
      fd->cinfo->col_buf[i][max_len - 1] = 0;
      fd->cinfo->col_data[i] = fd->cinfo->col_buf[i];
    }
  }
}

/* To do: Add check_col checks to the col_add* routines */

static void
col_set_abs_time(frame_data *fd, int col)
{
  struct tm *tmp;
  time_t then;

  then = fd->abs_secs;
  tmp = localtime(&then);
  snprintf(fd->cinfo->col_buf[col], COL_MAX_LEN, "%02d:%02d:%02d.%04ld",
    tmp->tm_hour,
    tmp->tm_min,
    tmp->tm_sec,
    (long)fd->abs_usecs/100);
  fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
}

static void
col_set_abs_date_time(frame_data *fd, int col)
{
  struct tm *tmp;
  time_t then;

  then = fd->abs_secs;
  tmp = localtime(&then);
  snprintf(fd->cinfo->col_buf[col], COL_MAX_LEN,
    "%04d-%02d-%02d %02d:%02d:%02d.%04ld",
    tmp->tm_year + 1900,
    tmp->tm_mon + 1,
    tmp->tm_mday,
    tmp->tm_hour,
    tmp->tm_min,
    tmp->tm_sec,
    (long)fd->abs_usecs/100);
  fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
}

static void
col_set_rel_time(frame_data *fd, int col)
{
  display_signed_time(fd->cinfo->col_buf[col], COL_MAX_LEN,
	fd->rel_secs, fd->rel_usecs);
  fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
}

static void
col_set_delta_time(frame_data *fd, int col)
{
  display_signed_time(fd->cinfo->col_buf[col], COL_MAX_LEN,
	fd->del_secs, fd->del_usecs);
  fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
}

/* Add "command-line-specified" time.
   XXX - this is called from "file.c" when the user changes the time
   format they want for "command-line-specified" time; it's a bit ugly
   that we have to export it, but if we go to a CList-like widget that
   invokes callbacks to get the text for the columns rather than
   requiring us to stuff the text into the widget from outside, we
   might be able to clean this up. */
void
col_set_cls_time(frame_data *fd, int col)
{
  switch (timestamp_type) {
    case ABSOLUTE:
      col_set_abs_time(fd, col);
      break;

    case ABSOLUTE_WITH_DATE:
      col_set_abs_date_time(fd, col);
      break;

    case RELATIVE:
      col_set_rel_time(fd, col);
      break;

    case DELTA:
      col_set_delta_time(fd, col);
      break;
  }
}

static void
col_set_addr(frame_data *fd, int col, address *addr, gboolean is_res)
{
  u_int ipv4_addr;
  struct e_in6_addr ipv6_addr;
  struct atalk_ddp_addr ddp_addr;
  struct sna_fid_type_4_addr sna_fid_type_4_addr;

  switch (addr->type) {

  case AT_ETHER:
    if (is_res)
      strncpy(fd->cinfo->col_buf[col], get_ether_name(addr->data), COL_MAX_LEN);
    else
      strncpy(fd->cinfo->col_buf[col], ether_to_str(addr->data), COL_MAX_LEN);
    fd->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
    break;

  case AT_IPv4:
    memcpy(&ipv4_addr, addr->data, sizeof ipv4_addr);
    if (is_res)
      strncpy(fd->cinfo->col_buf[col], get_hostname(ipv4_addr), COL_MAX_LEN);
    else
      strncpy(fd->cinfo->col_buf[col], ip_to_str(addr->data), COL_MAX_LEN);
    fd->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
    break;

  case AT_IPv6:
    memcpy(&ipv6_addr.s6_addr, addr->data, sizeof ipv6_addr.s6_addr);
    if (is_res)
      strncpy(fd->cinfo->col_buf[col], get_hostname6(&ipv6_addr), COL_MAX_LEN);
    else
      strncpy(fd->cinfo->col_buf[col], ip6_to_str(&ipv6_addr), COL_MAX_LEN);
    fd->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
    break;

  case AT_IPX:
    strncpy(fd->cinfo->col_buf[col],
      ipx_addr_to_str(pntohl(&addr->data[0]), &addr->data[4]), COL_MAX_LEN);
    fd->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
    break;

  case AT_SNA:
    switch (addr->len) {

    case 1:
      snprintf(fd->cinfo->col_buf[col], COL_MAX_LEN, "%04X", addr->data[0]);
      break;

    case 2:
      snprintf(fd->cinfo->col_buf[col], COL_MAX_LEN, "%04X",
        pntohs(&addr->data[0]));
      break;

    case SNA_FID_TYPE_4_ADDR_LEN:
      memcpy(&sna_fid_type_4_addr, addr->data, SNA_FID_TYPE_4_ADDR_LEN);
      strncpy(fd->cinfo->col_buf[col],
        sna_fid_type_4_addr_to_str(&sna_fid_type_4_addr), COL_MAX_LEN);
      break;
    }
    fd->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
    break;

  case AT_ATALK:
    memcpy(&ddp_addr, addr->data, sizeof ddp_addr);
    strncpy(fd->cinfo->col_buf[col], atalk_addr_to_str(&ddp_addr),
      COL_MAX_LEN);
    fd->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
    break;

  case AT_VINES:
    strncpy(fd->cinfo->col_buf[col], vines_addr_to_str(&addr->data[0]),
      COL_MAX_LEN);
    fd->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
    break;

  case AT_OSI:
    strncpy(fd->cinfo->col_buf[col], print_nsap_net(addr->data, addr->len),
      COL_MAX_LEN);
    fd->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
    fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
    break;

  default:
    break;
  }
}

static void
col_set_port(frame_data *fd, int col, port_type ptype, guint32 port,
		gboolean is_res)
{
  switch (ptype) {

  case PT_SCTP:
    if (is_res)
      strncpy(fd->cinfo->col_buf[col], get_sctp_port(port), COL_MAX_LEN);
    else
      snprintf(fd->cinfo->col_buf[col], COL_MAX_LEN, "%u", port);
    break;
    
  case PT_TCP:
    if (is_res)
      strncpy(fd->cinfo->col_buf[col], get_tcp_port(port), COL_MAX_LEN);
    else
      snprintf(fd->cinfo->col_buf[col], COL_MAX_LEN, "%u", port);
    break;

  case PT_UDP:
    if (is_res)
      strncpy(fd->cinfo->col_buf[col], get_udp_port(port), COL_MAX_LEN);
    else
      snprintf(fd->cinfo->col_buf[col], COL_MAX_LEN, "%u", port);
    break;

  default:
    break;
  }
  fd->cinfo->col_buf[col][COL_MAX_LEN - 1] = '\0';
  fd->cinfo->col_data[col] = fd->cinfo->col_buf[col];
}

void
fill_in_columns(frame_data *fd)
{
  int i;

  for (i = 0; i < fd->cinfo->num_cols; i++) {
    switch (fd->cinfo->col_fmt[i]) {

    case COL_NUMBER:
      snprintf(fd->cinfo->col_buf[i], COL_MAX_LEN, "%u", fd->num);
      fd->cinfo->col_data[i] = fd->cinfo->col_buf[i];
      break;

    case COL_CLS_TIME:
      col_set_cls_time(fd, i);
      break;

    case COL_ABS_TIME:
      col_set_abs_time(fd, i);
      break;

    case COL_ABS_DATE_TIME:
      col_set_abs_date_time(fd, i);
      break;

    case COL_REL_TIME:
      col_set_rel_time(fd, i);
      break;

    case COL_DELTA_TIME:
      col_set_delta_time(fd, i);
      break;

    case COL_DEF_SRC:
    case COL_RES_SRC:	/* COL_DEF_SRC is currently just like COL_RES_SRC */
      col_set_addr(fd, i, &pi.src, TRUE);
      break;

    case COL_UNRES_SRC:
      col_set_addr(fd, i, &pi.src, FALSE);
      break;

    case COL_DEF_DL_SRC:
    case COL_RES_DL_SRC:
      col_set_addr(fd, i, &pi.dl_src, TRUE);
      break;

    case COL_UNRES_DL_SRC:
      col_set_addr(fd, i, &pi.dl_src, FALSE);
      break;

    case COL_DEF_NET_SRC:
    case COL_RES_NET_SRC:
      col_set_addr(fd, i, &pi.net_src, TRUE);
      break;

    case COL_UNRES_NET_SRC:
      col_set_addr(fd, i, &pi.net_src, FALSE);
      break;

    case COL_DEF_DST:
    case COL_RES_DST:	/* COL_DEF_DST is currently just like COL_RES_DST */
      col_set_addr(fd, i, &pi.dst, TRUE);
      break;

    case COL_UNRES_DST:
      col_set_addr(fd, i, &pi.dst, FALSE);
      break;

    case COL_DEF_DL_DST:
    case COL_RES_DL_DST:
      col_set_addr(fd, i, &pi.dl_dst, TRUE);
      break;

    case COL_UNRES_DL_DST:
      col_set_addr(fd, i, &pi.dl_dst, FALSE);
      break;

    case COL_DEF_NET_DST:
    case COL_RES_NET_DST:
      col_set_addr(fd, i, &pi.net_dst, TRUE);
      break;

    case COL_UNRES_NET_DST:
      col_set_addr(fd, i, &pi.net_dst, FALSE);
      break;

    case COL_DEF_SRC_PORT:
    case COL_RES_SRC_PORT:	/* COL_DEF_SRC_PORT is currently just like COL_RES_SRC_PORT */
      col_set_port(fd, i, pi.ptype, pi.srcport, TRUE);
      break;

    case COL_UNRES_SRC_PORT:
      col_set_port(fd, i, pi.ptype, pi.srcport, FALSE);
      break;

    case COL_DEF_DST_PORT:
    case COL_RES_DST_PORT:	/* COL_DEF_DST_PORT is currently just like COL_RES_DST_PORT */
      col_set_port(fd, i, pi.ptype, pi.destport, TRUE);
      break;

    case COL_UNRES_DST_PORT:
      col_set_port(fd, i, pi.ptype, pi.destport, FALSE);
      break;

    case COL_PROTOCOL:	/* currently done by dissectors */
    case COL_INFO:	/* currently done by dissectors */
      break;

    case COL_PACKET_LENGTH:
      snprintf(fd->cinfo->col_buf[i], COL_MAX_LEN, "%d", fd->pkt_len);
      fd->cinfo->col_data[i] = fd->cinfo->col_buf[i];
      break;

    case NUM_COL_FMTS:	/* keep compiler happy - shouldn't get here */
      break;
    }
  }
}
	
/* Allow protocols to register "init" routines, which are called before
   we make a pass through a capture file and dissect all its packets
   (e.g., when we read in a new capture file, or run a "filter packets"
   or "colorize packets" pass over the current capture file). */
static GSList *init_routines;

void
register_init_routine(void (*func)(void))
{
	init_routines = g_slist_append(init_routines, func);
}

/* Call all the registered "init" routines. */
static void
call_init_routine(gpointer routine, gpointer dummy)
{
	void (*func)(void) = routine;

	(*func)();
}

void
init_all_protocols(void)
{
	g_slist_foreach(init_routines, &call_init_routine, NULL);
}

/* Creates the top-most tvbuff and calls dissect_frame() */
void
dissect_packet(tvbuff_t **p_tvb, union wtap_pseudo_header *pseudo_header,
		const u_char *pd, frame_data *fd, proto_tree *tree)
{
	blank_packetinfo();

	/* Set the initial payload to the packet length, and the initial
	   captured payload to the capture length (other protocols may
	   reduce them if their headers say they're less). */
	pi.len = fd->pkt_len;
	pi.captured_len = fd->cap_len;

	pi.fd = fd;
	pi.pseudo_header = pseudo_header;

	col_set_writable(fd, TRUE);

	TRY {
		*p_tvb = tvb_new_real_data(pd, fd->cap_len, fd->pkt_len, "Frame");
	/* Add this tvbuffer into the data_src list */
                fd->data_src = g_slist_append( fd->data_src, *p_tvb);

		pi.compat_top_tvb = *p_tvb;
	}
	CATCH(BoundsError) {
		g_assert_not_reached();
	}
	CATCH(ReportedBoundsError) {
		proto_tree_add_protocol_format(tree, proto_malformed, *p_tvb, 0, 0,
				"[Malformed Frame: Packet Length]" );
	}
	ENDTRY;

	dissect_frame(*p_tvb, &pi, tree);

	fd->flags.visited = 1;
}

/*********************** code added for sub-dissector lookup *********************/

static GHashTable *dissector_tables = NULL;

/*
 * XXX - for now, we support having both "old" dissectors, with packet
 * data pointer, packet offset, frame_data pointer, and protocol tree
 * pointer arguments, and "new" dissectors, with tvbuff pointer,
 * packet_info pointer, and protocol tree pointer arguments.
 *
 * Nuke this and go back to storing a pointer to the dissector when
 * the last old-style dissector is gone.
 */
typedef struct {
	gboolean is_old_dissector;
	union {
		old_dissector_t	old;
		dissector_t	new;
	} dissector;
	int	proto_index;
} dissector_entry_t;

struct dtbl_entry {
	dissector_entry_t initial;
	dissector_entry_t current;
};

static void
dissect_null(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
}

/* Finds a dissector table by field name. */
static dissector_table_t
find_dissector_table(const char *name)
{
	g_assert(dissector_tables);
	return g_hash_table_lookup( dissector_tables, name );
}

/* add an entry, lookup the dissector table for the specified field name,  */
/* if a valid table found, add the subdissector */
void
old_dissector_add(const char *name, guint32 pattern, old_dissector_t dissector,
    int proto)
{
	dissector_table_t sub_dissectors = find_dissector_table( name);
	dtbl_entry_t *dtbl_entry;

/* sanity check */
	g_assert( sub_dissectors);

	dtbl_entry = g_malloc(sizeof (dtbl_entry_t));
	dtbl_entry->current.is_old_dissector = TRUE;
	dtbl_entry->current.dissector.old = dissector;
	dtbl_entry->current.proto_index = proto;
	dtbl_entry->initial = dtbl_entry->current;
	proto_set_protocol_dissector(proto, dissector);

/* do the table insertion */
    	g_hash_table_insert( sub_dissectors, GUINT_TO_POINTER( pattern),
    	 (gpointer)dtbl_entry);
}

void
dissector_add(const char *name, guint32 pattern, dissector_t dissector,
    int proto)
{
	dissector_table_t sub_dissectors = find_dissector_table( name);
	dtbl_entry_t *dtbl_entry;

/* sanity check */
	g_assert( sub_dissectors);

	dtbl_entry = g_malloc(sizeof (dtbl_entry_t));
	dtbl_entry->current.is_old_dissector = FALSE;
	dtbl_entry->current.dissector.new = dissector;
	dtbl_entry->current.proto_index = proto;
	dtbl_entry->initial = dtbl_entry->current;
	proto_set_protocol_dissector(proto, dissector);

/* do the table insertion */
    	g_hash_table_insert( sub_dissectors, GUINT_TO_POINTER( pattern),
    	 (gpointer)dtbl_entry);
}

/* delete the entry for this dissector at this pattern */

/* NOTE: this doesn't use the dissector call variable. It is included to */
/*	be consistant with the dissector_add and more importantly to be used */
/*	if the technique of adding a temporary dissector is implemented.  */
/*	If temporary dissectors are deleted, then the original dissector must */
/*	be available. */
void
old_dissector_delete(const char *name, guint32 pattern, old_dissector_t dissector)
{
	dissector_table_t sub_dissectors = find_dissector_table( name);
	dtbl_entry_t *dtbl_entry;

/* sanity check */
	g_assert( sub_dissectors);

	/*
	 * Find the entry.
	 */
	dtbl_entry = g_hash_table_lookup(sub_dissectors,
	    GUINT_TO_POINTER(pattern));

	if (dtbl_entry != NULL) {
		/*
		 * Found - remove it.
		 */
		g_hash_table_remove(sub_dissectors, GUINT_TO_POINTER(pattern));

		/*
		 * Now free up the entry.
		 */
		g_free(dtbl_entry);
	}
}

void
dissector_delete(const char *name, guint32 pattern, dissector_t dissector)
{
	dissector_table_t sub_dissectors = find_dissector_table( name);
	dtbl_entry_t *dtbl_entry;

/* sanity check */
	g_assert( sub_dissectors);

	/*
	 * Find the entry.
	 */
	dtbl_entry = g_hash_table_lookup(sub_dissectors,
	    GUINT_TO_POINTER(pattern));

	if (dtbl_entry != NULL) {
		/*
		 * Found - remove it.
		 */
		g_hash_table_remove(sub_dissectors, GUINT_TO_POINTER(pattern));

		/*
		 * Now free up the entry.
		 */
		g_free(dtbl_entry);
	}
}

void
dissector_change(const char *name, guint32 pattern, dissector_t dissector,
		 gboolean old, int proto)
{
	dissector_table_t sub_dissectors = find_dissector_table( name);
	dtbl_entry_t *dtbl_entry;

/* sanity check */
	g_assert( sub_dissectors);

	/*
	 * See if the entry already exists. If so, reuse it.
	 */
	dtbl_entry = g_hash_table_lookup(sub_dissectors,
	    GUINT_TO_POINTER(pattern));
	if (dtbl_entry != NULL) {
	  dtbl_entry->current.is_old_dissector = old;
	  dtbl_entry->current.dissector.new = dissector ? dissector : dissect_null;
	  dtbl_entry->current.proto_index = proto;
	  return;
	}

	/*
	 * Don't create an entry if there is no dissector - I.E. the
	 * user said not to decode something that wasn't being decoded
	 * in the first place.
	 */
	if (dissector == NULL)
	  return;

	dtbl_entry = g_malloc(sizeof (dtbl_entry_t));
	dtbl_entry->initial.is_old_dissector = FALSE;
	dtbl_entry->initial.dissector.old = NULL;
	dtbl_entry->initial.proto_index = -1;
	dtbl_entry->current.is_old_dissector = old;
	dtbl_entry->current.dissector.new = dissector;
	dtbl_entry->current.proto_index = proto;

/* do the table insertion */
    	g_hash_table_insert( sub_dissectors, GUINT_TO_POINTER( pattern),
    	 (gpointer)dtbl_entry);
}

void
dissector_reset(const char *name, guint32 pattern)
{
	dissector_table_t sub_dissectors = find_dissector_table( name);
	dtbl_entry_t *dtbl_entry;

/* sanity check */
	g_assert( sub_dissectors);

	/*
	 * Find the entry.
	 */
	dtbl_entry = g_hash_table_lookup(sub_dissectors,
	    GUINT_TO_POINTER(pattern));

	if (dtbl_entry == NULL)
		return;

	/*
	 * Found - is there an initial value?
	 */
	if (dtbl_entry->initial.dissector.new != NULL) {
		dtbl_entry->current = dtbl_entry->initial;
	} else {
		g_hash_table_remove(sub_dissectors, GUINT_TO_POINTER(pattern));
		g_free(dtbl_entry);
	}
}

/* Look for a given port in a given dissector table and, if found, call
   the dissector with the arguments supplied, and return TRUE, otherwise
   return FALSE.

   If the arguments supplied don't match the arguments to the dissector,
   do the appropriate translation. */
gboolean
old_dissector_try_port(dissector_table_t sub_dissectors, guint32 port,
    const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	dtbl_entry_t *dtbl_entry;
	tvbuff_t *tvb;
	const char *saved_proto;
	guint32 saved_match_port;

	dtbl_entry = g_hash_table_lookup(sub_dissectors,
	    GUINT_TO_POINTER(port));
	if (dtbl_entry != NULL) {
		/*
		 * Is this protocol enabled?
		 */
		if (dtbl_entry->current.proto_index != -1 &&
		    !proto_is_protocol_enabled(dtbl_entry->current.proto_index)) {
			/*
			 * No - pretend this dissector didn't exist,
			 * so that other dissectors might have a chance
			 * to dissect this packet.
			 */
			return FALSE;
		}
			
		/*
		 * Yes, it's enabled.
		 */
		saved_proto = pi.current_proto;
		saved_match_port = pi.match_port;
		pi.match_port = port;
		if (dtbl_entry->current.is_old_dissector)
			(*dtbl_entry->current.dissector.old)(pd, offset, fd, tree);
		else {
			/*
			 * Old dissector calling new dissector; use
			 * "tvb_create_from_top()" to remap.
			 *
			 * XXX - what about the "pd" argument?  Do
			 * any dissectors not just pass that along and
			 * let the "offset" argument handle stepping
			 * through the packet?
			 */
			if (dtbl_entry->current.proto_index != -1) {
				pi.current_proto =
				    proto_get_protocol_short_name(dtbl_entry->current.proto_index);
			}
			tvb = tvb_create_from_top(offset);
			(*dtbl_entry->current.dissector.new)(tvb, &pi, tree);
		}
		pi.current_proto = saved_proto;
		pi.match_port = saved_match_port;
		return TRUE;
	} else
		return FALSE;
}

gboolean
dissector_try_port(dissector_table_t sub_dissectors, guint32 port,
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dtbl_entry_t *dtbl_entry;
	const guint8 *pd;
	int offset;
	const char *saved_proto;
	guint32 saved_match_port;

	dtbl_entry = g_hash_table_lookup(sub_dissectors,
	    GUINT_TO_POINTER(port));
	if (dtbl_entry != NULL) {
		/*
		 * Is this protocol enabled?
		 */
		if (dtbl_entry->current.proto_index != -1 &&
		    !proto_is_protocol_enabled(dtbl_entry->current.proto_index)) {
			/*
			 * No - pretend this dissector didn't exist,
			 * so that other dissectors might have a chance
			 * to dissect this packet.
			 */
			return FALSE;
		}
			
		/*
		 * Yes, it's enabled.
		 */
		saved_proto = pinfo->current_proto;
		saved_match_port = pinfo->match_port;
		pinfo->match_port = port;
		if (dtbl_entry->current.is_old_dissector) {
			/*
			 * New dissector calling old dissector; use
			 * "tvb_compat()" to remap.
			 */
			tvb_compat(tvb, &pd, &offset);
			(*dtbl_entry->current.dissector.old)(pd, offset, pinfo->fd,
			    tree);
		} else {
			if (dtbl_entry->current.proto_index != -1) {
				pinfo->current_proto =
				    proto_get_protocol_short_name(dtbl_entry->current.proto_index);
			}
			(*dtbl_entry->current.dissector.new)(tvb, pinfo, tree);
		}
		pinfo->current_proto = saved_proto;
		pinfo->match_port = saved_match_port;
		return TRUE;
	} else
		return FALSE;
}

gboolean
dissector_get_old_flag (dtbl_entry_t *dtbl_entry)
{
	g_assert(dtbl_entry);
	return(dtbl_entry->current.is_old_dissector);
}

gint
dissector_get_proto (dtbl_entry_t *dtbl_entry)
{
	g_assert(dtbl_entry);
	return(dtbl_entry->current.proto_index);
}

gint
dissector_get_initial_proto (dtbl_entry_t *dtbl_entry)
{
	g_assert(dtbl_entry);
	return(dtbl_entry->initial.proto_index);
}

/**************************************************/
/*                                                */
/*       Routines to walk dissector tables        */
/*                                                */
/**************************************************/

typedef struct dissector_foreach_info {
  gpointer     caller_data;
  DATFunc      caller_func;
  GHFunc       next_func;
  gchar       *table_name;
} dissector_foreach_info_t;

/*
 * Walk all dissector tables calling a user supplied function on each
 * entry.  These three routines handle traversing the hash of hashes
 * that is the dissector tables.
 */
static void
dissector_all_tables_foreach_func2 (gpointer key, gpointer value, gpointer user_data)
{
	dissector_foreach_info_t *info;
	dtbl_entry_t *dtbl_entry;

	g_assert(value);
	g_assert(user_data);

	dtbl_entry = value;
	if (dtbl_entry->current.proto_index == -1) {
	  return;
	}

	info = user_data;
	info->caller_func(info->table_name, key, value, info->caller_data);
}

static void
dissector_all_tables_foreach_func1 (gpointer key, gpointer value, gpointer user_data)
{
	GHashTable   *hash_table;
	dissector_foreach_info_t *info;

	g_assert(value);
	g_assert(user_data);

	hash_table = value;
	info = user_data;
	info->table_name = (gchar*) key;
	g_hash_table_foreach(hash_table, info->next_func, info);
}

void
dissector_all_tables_foreach (DATFunc func,
			      gpointer user_data)
{
	dissector_foreach_info_t info;

	info.caller_data = user_data;
	info.caller_func = func;
	info.next_func = dissector_all_tables_foreach_func2;
	g_hash_table_foreach(dissector_tables, dissector_all_tables_foreach_func1, &info);
}

/*
 * Walk one dissector table calling a user supplied function on each
 * entry.
 */
void
dissector_table_foreach (char *name,
			 DATFunc func,
			 gpointer user_data)
{
	dissector_foreach_info_t info;
	GHashTable *hash_table;

	hash_table = find_dissector_table(name);
	g_assert(hash_table);

	info.table_name = name;
	info.caller_func = func;
	info.caller_data = user_data;
	g_hash_table_foreach(hash_table, dissector_all_tables_foreach_func2, &info);
}

/*
 * Walk all dissector tables calling a user supplied function only on
 * any entry that has been changed from its original state.  These two
 * routines (plus one above) handle traversing the hash of hashes that
 * is the dissector tables.
 */
static void
dissector_all_tables_foreach_changed_func2 (gpointer key, gpointer value, gpointer user_data)
{
	dtbl_entry_t *dtbl_entry;
	dissector_foreach_info_t *info;

	g_assert(value);
	g_assert(user_data);

	dtbl_entry = value;
	if (dtbl_entry->initial.proto_index == dtbl_entry->current.proto_index) {
	    return;
	}

	info = user_data;
	info->caller_func(info->table_name, key, value, info->caller_data);
}

void
dissector_all_tables_foreach_changed (DATFunc func,
				      gpointer user_data)
{
	dissector_foreach_info_t info;

	info.caller_data = user_data;
	info.caller_func = func;
	info.next_func = dissector_all_tables_foreach_changed_func2;
	g_hash_table_foreach(dissector_tables, dissector_all_tables_foreach_func1, &info);
}

/*
 * Walk one dissector table calling a user supplied function only on
 * any entry that has been changed from its original state.
 */
void
dissector_table_foreach_changed (char *name,
				 DATFunc func,
				 gpointer user_data)
{
	dissector_foreach_info_t info;
	GHashTable *hash_table;

	hash_table = find_dissector_table(name);
	g_assert(hash_table);

	info.table_name = name;
	info.caller_func = func;
	info.caller_data = user_data;
	g_hash_table_foreach(hash_table, dissector_all_tables_foreach_changed_func2, &info);
}

dissector_table_t
register_dissector_table(const char *name)
{
	dissector_table_t	sub_dissectors;

	/* Create our hash-of-hashes if it doesn't already exist */
	if (!dissector_tables) {
		dissector_tables = g_hash_table_new( g_str_hash, g_str_equal );
		g_assert(dissector_tables);
	}

	/* Make sure the registration is unique */
	g_assert(!g_hash_table_lookup( dissector_tables, name ));

	/* Create and register the dissector table for this name; returns */
	/* a pointer to the dissector table. */
	sub_dissectors = g_hash_table_new( g_direct_hash, g_direct_equal );
	g_hash_table_insert( dissector_tables, (gpointer)name, (gpointer) sub_dissectors );
	return sub_dissectors;
}

static GHashTable *heur_dissector_lists = NULL;

/*
 * XXX - for now, we support having both "old" dissectors, with packet
 * data pointer, packet offset, frame_data pointer, and protocol tree
 * pointer arguments, and "new" dissectors, with tvbuff pointer,
 * packet_info pointer, and protocol tree pointer arguments.
 *
 * Nuke this and go back to storing a pointer to the dissector when
 * the last old-style dissector is gone.
 */
typedef struct {
	gboolean is_old_dissector;
	union {
		old_heur_dissector_t	old;
		heur_dissector_t	new;
	} dissector;
	int	proto_index;
} heur_dtbl_entry_t;

/* Finds a heuristic dissector table by field name. */
static heur_dissector_list_t *
find_heur_dissector_list(const char *name)
{
	g_assert(heur_dissector_lists != NULL);
	return g_hash_table_lookup(heur_dissector_lists, name);
}

void
old_heur_dissector_add(const char *name, old_heur_dissector_t dissector,
    int proto)
{
	heur_dissector_list_t *sub_dissectors = find_heur_dissector_list(name);
	heur_dtbl_entry_t *dtbl_entry;

	/* sanity check */
	g_assert(sub_dissectors != NULL);

	dtbl_entry = g_malloc(sizeof (heur_dtbl_entry_t));
	dtbl_entry->is_old_dissector = TRUE;
	dtbl_entry->dissector.old = dissector;
	dtbl_entry->proto_index = proto;

	/* do the table insertion */
	*sub_dissectors = g_slist_append(*sub_dissectors, (gpointer)dtbl_entry);
}

void
heur_dissector_add(const char *name, heur_dissector_t dissector, int proto)
{
	heur_dissector_list_t *sub_dissectors = find_heur_dissector_list(name);
	heur_dtbl_entry_t *dtbl_entry;

	/* sanity check */
	g_assert(sub_dissectors != NULL);

	dtbl_entry = g_malloc(sizeof (heur_dtbl_entry_t));
	dtbl_entry->is_old_dissector = FALSE;
	dtbl_entry->dissector.new = dissector;
	dtbl_entry->proto_index = proto;

	/* do the table insertion */
	*sub_dissectors = g_slist_append(*sub_dissectors, (gpointer)dtbl_entry);
}

gboolean
dissector_try_heuristic(heur_dissector_list_t sub_dissectors,
    tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gboolean status;
	const char *saved_proto;
	GSList *entry;
	heur_dtbl_entry_t *dtbl_entry;
	const guint8 *pd = NULL;
	int offset;

	status = FALSE;
	saved_proto = pinfo->current_proto;
	for (entry = sub_dissectors; entry != NULL; entry = g_slist_next(entry)) {
		dtbl_entry = (heur_dtbl_entry_t *)entry->data;
		if (dtbl_entry->proto_index != -1 &&
		    !proto_is_protocol_enabled(dtbl_entry->proto_index)) {
			/*
			 * No - don't try this dissector.
			 */
			continue;
		}

		if (dtbl_entry->is_old_dissector) {
			/*
			 * New dissector calling old dissector; use
			 * "tvb_compat()" to remap.
			 */
			if (pd == NULL)
				tvb_compat(tvb, &pd, &offset);
			if ((*dtbl_entry->dissector.old)(pd, offset, pinfo->fd,
			    tree)) {
				status = TRUE;
				break;
			}
		} else {
			if (dtbl_entry->proto_index != -1) {
				pinfo->current_proto =
				    proto_get_protocol_short_name(dtbl_entry->proto_index);
			}
			if ((*dtbl_entry->dissector.new)(tvb, pinfo, tree)) {
				status = TRUE;
				break;
			}
		}
	}
	pinfo->current_proto = saved_proto;
	return status;
}

void
register_heur_dissector_list(const char *name, heur_dissector_list_t *sub_dissectors)
{
	/* Create our hash-of-lists if it doesn't already exist */
	if (heur_dissector_lists == NULL) {
		heur_dissector_lists = g_hash_table_new(g_str_hash, g_str_equal);
		g_assert(heur_dissector_lists != NULL);
	}

	/* Make sure the registration is unique */
	g_assert(g_hash_table_lookup(heur_dissector_lists, name) == NULL);

	*sub_dissectors = NULL;	/* initially empty */
	g_hash_table_insert(heur_dissector_lists, (gpointer)name,
	    (gpointer) sub_dissectors);
}

static GHashTable *conv_dissector_lists = NULL;

/*
 * XXX - for now, we support having both "old" dissectors, with packet
 * data pointer, packet offset, frame_data pointer, and protocol tree
 * pointer arguments, and "new" dissectors, with tvbuff pointer,
 * packet_info pointer, and protocol tree pointer arguments.
 *
 * Nuke this and go back to storing a pointer to the dissector when
 * the last old-style dissector is gone.
 */
struct conv_dtbl_entry {
	gboolean is_old_dissector;
	union {
		old_dissector_t	old;
		dissector_t	new;
	} dissector;
	int	proto_index;
};

/* Finds a conversation dissector table by table name. */
static conv_dissector_list_t *
find_conv_dissector_list(const char *name)
{
	g_assert(conv_dissector_lists != NULL);
	return g_hash_table_lookup(conv_dissector_lists, name);
}

void
old_conv_dissector_add(const char *name, old_dissector_t dissector,
    int proto)
{
	conv_dissector_list_t *sub_dissectors = find_conv_dissector_list(name);
	conv_dtbl_entry_t *dtbl_entry;

	/* sanity check */
	g_assert(sub_dissectors != NULL);

	dtbl_entry = g_malloc(sizeof (conv_dtbl_entry_t));
	dtbl_entry->is_old_dissector = TRUE;
	dtbl_entry->dissector.old = dissector;
	dtbl_entry->proto_index = proto;
	proto_set_protocol_dissector(proto, dissector);

	/* do the table insertion */
	*sub_dissectors = g_slist_append(*sub_dissectors, (gpointer)dtbl_entry);
}

void
conv_dissector_add(const char *name, dissector_t dissector, int proto)
{
	conv_dissector_list_t *sub_dissectors = find_conv_dissector_list(name);
	conv_dtbl_entry_t *dtbl_entry;

	/* sanity check */
	g_assert(sub_dissectors != NULL);

	dtbl_entry = g_malloc(sizeof (conv_dtbl_entry_t));
	dtbl_entry->is_old_dissector = FALSE;
	dtbl_entry->dissector.new = dissector;
	dtbl_entry->proto_index = proto;
	proto_set_protocol_dissector(proto, dissector);

	/* do the table insertion */
	*sub_dissectors = g_slist_append(*sub_dissectors, (gpointer)dtbl_entry);
}

void
register_conv_dissector_list(const char *name, conv_dissector_list_t *sub_dissectors)
{
	/* Create our hash-of-lists if it doesn't already exist */
	if (conv_dissector_lists == NULL) {
		conv_dissector_lists = g_hash_table_new(g_str_hash, g_str_equal);
		g_assert(conv_dissector_lists != NULL);
	}

	/* Make sure the registration is unique */
	g_assert(g_hash_table_lookup(conv_dissector_lists, name) == NULL);

	*sub_dissectors = NULL;	/* initially empty */
	g_hash_table_insert(conv_dissector_lists, (gpointer)name,
	    (gpointer) sub_dissectors);
}

gboolean
conv_dissector_get_old_flag (conv_dtbl_entry_t *dtbl_entry)
{
	g_assert(dtbl_entry);
	return(dtbl_entry->is_old_dissector);
}

gint
conv_dissector_get_proto (conv_dtbl_entry_t *dtbl_entry)
{
	g_assert(dtbl_entry);
	return(dtbl_entry->proto_index);
}

void
dissector_conv_foreach (char *name,
			DATFunc func,
			gpointer user_data)
{
	conv_dissector_list_t *sub_dissectors = find_conv_dissector_list(name);
	GSList *tmp;

	/* sanity check */
	g_assert(sub_dissectors != NULL);

	for (tmp = *sub_dissectors; tmp; tmp = g_slist_next(tmp)) {
		func(name, 0, tmp->data, user_data);
	}
}

static void
dissector_all_conv_foreach_func1 (gpointer key, gpointer value, gpointer user_data)
{
	conv_dissector_list_t *sub_dissectors;
	GSList *tmp;
	dissector_foreach_info_t *info;

	g_assert(value);
	g_assert(user_data);

	sub_dissectors = value;
	for (tmp = *sub_dissectors; tmp; tmp = g_slist_next(tmp)) {
	  info = user_data;
	  info->caller_func(key, 0, tmp->data, info->caller_data);
	}
}

void
dissector_all_conv_foreach (DATFunc func,
			    gpointer user_data)
{
	dissector_foreach_info_t info;

	info.caller_data = user_data;
	info.caller_func = func;
	g_hash_table_foreach(conv_dissector_lists, dissector_all_conv_foreach_func1, &info);
}

/*
 * Register dissectors by name; used if one dissector always calls a
 * particular dissector, or if it bases the decision of which dissector
 * to call on something other than a numerical value or on "try a bunch
 * of dissectors until one likes the packet".
 */

/*
 * List of registered dissectors.
 */
static GHashTable *registered_dissectors = NULL;

/*
 * An entry in the list of registered dissectors.
 */
struct dissector_handle {
	const char	*name;		/* dissector name */
	dissector_t	dissector;
	int		proto_index;
};

/* Find a registered dissector by name. */
dissector_handle_t
find_dissector(const char *name)
{
	g_assert(registered_dissectors != NULL);
	return g_hash_table_lookup(registered_dissectors, name);
}

/* Register a dissector by name. */
void
register_dissector(const char *name, dissector_t dissector, int proto)
{
	struct dissector_handle *handle;

	/* Create our hash table if it doesn't already exist */
	if (registered_dissectors == NULL) {
		registered_dissectors = g_hash_table_new(g_str_hash, g_str_equal);
		g_assert(registered_dissectors != NULL);
	}

	/* Make sure the registration is unique */
	g_assert(g_hash_table_lookup(registered_dissectors, name) == NULL);

	handle = g_malloc(sizeof (struct dissector_handle));
	handle->name = name;
	handle->dissector = dissector;
	handle->proto_index = proto;
	
	g_hash_table_insert(registered_dissectors, (gpointer)name,
	    (gpointer) handle);
}

/* Call a dissector through a handle. */
void
call_dissector(dissector_handle_t handle, tvbuff_t *tvb,
    packet_info *pinfo, proto_tree *tree)
{
	const char *saved_proto;

	if (handle->proto_index != -1 &&
	    !proto_is_protocol_enabled(handle->proto_index)) {
		/*
		 * No - just dissect this packet as data.
		 */
		dissect_data(tvb, 0, pinfo, tree);
		return;
	}

	saved_proto = pinfo->current_proto;
	if (handle->proto_index != -1) {
		pinfo->current_proto =
		    proto_get_protocol_short_name(handle->proto_index);
	}
	(*handle->dissector)(tvb, pinfo, tree);
	pinfo->current_proto = saved_proto;
}
