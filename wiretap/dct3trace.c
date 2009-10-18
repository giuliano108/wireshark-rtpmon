/* dct3trace.c
 * Routines for reading signalling traces generated by Gammu (www.gammu.org)
 * from Nokia DCT3 phones in Netmonitor mode.
 *
 * gammu --nokiadebug nhm5_587.txt v18-19
 *
 * Duncan Salerno <duncan.salerno@googlemail.com>
 *
 * $Id$
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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
#include "config.h"
#endif
#include "wtap-int.h"
#include "buffer.h"
#include "dct3trace.h"
#include "file_wrappers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


/*
   Example downlink data:

<?xml version="1.0"?>
<dump>
<l1 direction="down" logicalchannel="96" physicalchannel="19" sequence="268116" error="0" timeshift="2992" bsic="22" data="31063F100DD0297A53E1020103C802398E0B2B2B2B2B2B" >
<l2 data="063F100DD0297A53E1020103" rest="C802398E0B2B2B2B2B2B" >
</l2>
</l1>
</dump>

   Example uplink data (no raw L1):

<?xml version="1.0"?>
<dump>
<l1 direction="up" logicalchannel="112" >
<l2 type="U" subtype="Unknown" p="0" data="061500400000000000000000000000000000" >
</l2>
</l1>
</dump>

 */


/* Magic text to check */
static const char dct3trace_magic_line1[] = "<?xml version=\"1.0\"?>";
static const char dct3trace_magic_line2[] = "<dump>";
static const char dct3trace_magic_record_start[]  = "<l1 ";
static const char dct3trace_magic_record_end[]  = "</l1>";
static const char dct3trace_magic_l2_start[]  = "<l2 ";
static const char dct3trace_magic_l2_end[]  = "</l2>";
static const char dct3trace_magic_end[]  = "</dump>";

#define MAX_PACKET_LEN 23

static gboolean dct3trace_read(wtap *wth, int *err, gchar **err_info,
	gint64 *data_offset);
static gboolean dct3trace_seek_read(wtap *wth, gint64 seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int len,
	int *err, gchar **err_info);

/*
 * Following 3 functions taken from gsmdecode-0.7bis, with permission - http://wiki.thc.org/gsm
 */

static int
hc2b(unsigned char hex)
{
	hex = tolower(hex);
	if ((hex >= '0') && (hex <= '9'))
		return hex - '0';
	if ((hex >= 'a') && (hex <= 'f'))
		return hex - 'a' + 10;
	return -1;
}

static int
hex2bin(unsigned char *out, unsigned char *in)
{
	unsigned char *out_start = out;
	unsigned char *end = in + strlen((char *)in);
	int is_low = 0;
	int c;

	/* Clamp to maximum packet size */
	if (end - in > MAX_PACKET_LEN*2) /* As we're reading nibbles */
		end = in + MAX_PACKET_LEN*2;

	while (in < end)
	{
		c = hc2b(in[0]);
		if (c < 0)
		{
			in++;
			continue;
		}
		if (is_low == 0)
		{
			out[0] = c << 4;
			is_low = 1;
		} else {
			out[0] |= (c & 0x0f);
			is_low = 0;
			out++;
		}
		in++;
	}

	return (int)(out - out_start);
}

static int
xml_get_int(int *val, const unsigned char *str, const unsigned char *pattern)
{
	char *ptr;
	char *start, *end;
	char buf[32];

	ptr = strstr((char *)str, (char *)pattern);
	if (ptr == NULL)
		return -1;
	start = strchr(ptr, '"');
	if (start == NULL)
		return -2;
	start++;
	end = strchr(start, '"');
	if (end == NULL)
		return -3;
	if (end - start > 31)
		return -4;

	memcpy(buf, start, end - start);
	buf[end - start] = '\0';
	*val = atoi(buf);
	return 0;
}


/* Look through the first part of a file to see if this is
 * a DCT3 trace file.
 *
 * Returns TRUE if it is, FALSE if it isn't or if we get an I/O error;
 * if we get an I/O error, "*err" will be set to a non-zero value.
 */
static gboolean dct3trace_check_file_type(wtap *wth, int *err)
{
	char line1[64], line2[64];

	if (file_gets(line1, sizeof(line1), wth->fh) != NULL &&
		file_gets(line2, sizeof(line2), wth->fh) != NULL)
	{
		/* Don't compare line endings */
		if( strncmp(dct3trace_magic_line1, line1, strlen(dct3trace_magic_line1)) == 0 &&
			strncmp(dct3trace_magic_line2, line2, strlen(dct3trace_magic_line2)) == 0)
		{
			return TRUE;
		}
	}
	/* EOF or error. */
	else
	{
		if (file_eof(wth->fh))
			*err = 0;
		else
			*err = file_error(wth->fh);
	}

	return FALSE;
}


int dct3trace_open(wtap *wth, int *err, gchar **err_info _U_)
{
	/* Look for Gammu DCT3 trace header */
	if (!dct3trace_check_file_type(wth, err))
	{
		if (*err == 0)
			return 0;
		else
			return -1;
	}

	wth->data_offset = 0;
	wth->file_encap = WTAP_ENCAP_GSM_UM;
	wth->file_type = WTAP_FILE_DCT3TRACE;
	wth->snapshot_length = 0; /* not known */
	wth->subtype_read = dct3trace_read;
	wth->subtype_seek_read = dct3trace_seek_read;
	wth->tsprecision = WTAP_FILE_TSPREC_SEC;

	return 1;
}


static gboolean dct3trace_get_packet(FILE *fh, union wtap_pseudo_header *pseudo_header,
	unsigned char *buf, int *len, int *err, gchar **err_info)
{
	unsigned char line[1024];
	gboolean have_data = FALSE;

	while (file_gets(line, sizeof(line), fh) != NULL)
	{
		if( memcmp(dct3trace_magic_end, line, strlen(dct3trace_magic_end)) == 0 )
		{
			/* Return on end of file </dump> */
			*err = 0;
			return FALSE;
		}
		else if( memcmp(dct3trace_magic_record_end, line, strlen(dct3trace_magic_record_end)) == 0 )
		{
			/* Return on end of record </l1> */
			if( have_data )
			{
				*err = 0;
				return TRUE;
			}
			else
			{
				/* If not got any data return error */
				*err = WTAP_ERR_BAD_RECORD;
				*err_info = g_strdup_printf("dct3trace: record without data");
				return FALSE;
			}
		}
		else if( memcmp(dct3trace_magic_record_start, line, strlen(dct3trace_magic_record_start)) == 0 )
		{
			/* Parse L1 header <l1 ...>*/
			int channel, tmp, ret = 0;
			char *ptr;

			pseudo_header->gsm_um.uplink = !strstr(line, "direction=\"down\"");
			ret |= xml_get_int(&channel, line, "logicalchannel");

			/* Parse downlink only fields */
			if( !pseudo_header->gsm_um.uplink )
			{
				ret |= xml_get_int(&tmp, line, "physicalchannel");
				pseudo_header->gsm_um.arfcn = tmp;
				ret |= xml_get_int(&tmp, line, "sequence");
				pseudo_header->gsm_um.tdma_frame = tmp;
				ret |= xml_get_int(&tmp, line, "bsic");
				pseudo_header->gsm_um.bsic = tmp;
				ret |= xml_get_int(&tmp, line, "error");
				pseudo_header->gsm_um.error = tmp;
				ret |= xml_get_int(&tmp, line, "timeshift");
				pseudo_header->gsm_um.timeshift = tmp;
			}

			if( ret != 0 )
			{
				*err = WTAP_ERR_BAD_RECORD;
				*err_info = g_strdup_printf("dct3trace: record missing mandatory attributes");
				return FALSE;
			}

			switch( channel )
			{
				case 128: pseudo_header->gsm_um.channel = GSM_UM_CHANNEL_SDCCH; break;
				case 112: pseudo_header->gsm_um.channel = GSM_UM_CHANNEL_SACCH; break;
				case 176: pseudo_header->gsm_um.channel = GSM_UM_CHANNEL_FACCH; break;
				case 96: pseudo_header->gsm_um.channel = GSM_UM_CHANNEL_CCCH; break;
				case 80: pseudo_header->gsm_um.channel = GSM_UM_CHANNEL_BCCH; break;
				default: pseudo_header->gsm_um.channel = GSM_UM_CHANNEL_UNKNOWN; break;
			}

			/* Read data (if have it) into buf */
			ptr = strstr(line, "data=\"");
			if( ptr )
			{
				have_data = TRUE; /* If has data... */
				*len = hex2bin(buf, ptr+6);
			}
		}
		else if( !have_data && memcmp(dct3trace_magic_l2_start, line, strlen(dct3trace_magic_l2_start)) == 0 )
		{
			/* For uplink packets we might not get the raw L1, so have to recreate it from the L2 */
			/* Parse L2 header if didn't get data from L1 <l2 ...> */
			int data_len = 0;
			char *ptr = strstr(line, "data=\"");

			if( !ptr )
			{
				continue;
			}

			have_data = TRUE;

			if( pseudo_header->gsm_um.channel == GSM_UM_CHANNEL_SACCH || pseudo_header->gsm_um.channel == GSM_UM_CHANNEL_FACCH || pseudo_header->gsm_um.channel == GSM_UM_CHANNEL_SDCCH )
			{
				/* Add LAPDm B header */
				memset(buf, 0x1, 2);
				*len = 3;
			}
			else
			{
				/* Add LAPDm Bbis header */
				*len = 1;
			}
			buf += *len;

			data_len = hex2bin(buf, ptr+6);
			*len += data_len;

			/* Add LAPDm length byte */
			*(buf - 1) = data_len << 2 | 0x1;
		}
	}

	*err = file_error(fh);
	if (*err == 0)
	{
		*err = WTAP_ERR_SHORT_READ;
	}
	return FALSE;
}


/* Find the next packet and parse it; called from wtap_read(). */
static gboolean dct3trace_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
	guint64 offset = file_tell(wth->fh);
	int buf_len;
	unsigned char buf[MAX_PACKET_LEN];

	if( !dct3trace_get_packet(wth->fh, &wth->pseudo_header, buf, &buf_len, err, err_info) )
	{
		return FALSE;
	}

	/* We've got a full packet! */
	wth->phdr.ts.secs = 0;
	wth->phdr.ts.nsecs = 0;
	wth->phdr.caplen = buf_len;
	wth->phdr.len = buf_len;

	/* Make sure we have enough room for the packet */
	buffer_assure_space(wth->frame_buffer, buf_len);
	memcpy( buffer_start_ptr(wth->frame_buffer), buf, buf_len );

	wth->data_offset = *data_offset = offset;

	return TRUE;
}


/* Used to read packets in random-access fashion */
static gboolean dct3trace_seek_read (wtap *wth, gint64 seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int len,
	int *err, gchar **err_info)
{
	int buf_len;
	unsigned char buf[MAX_PACKET_LEN];

	if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
	{
		return FALSE;
	}

	if( !dct3trace_get_packet(wth->random_fh, pseudo_header, buf, &buf_len, err, err_info) )
	{
		return FALSE;
	}

	if( len != buf_len && len != -1 )
	{
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup_printf("dct3trace: requested length %d doesn't match record length %d",
		    len, buf_len);
		return FALSE;
	}

	memcpy( pd, buf, buf_len );
	return TRUE;
}
