/* packet-multipart.c
 * Routines for multipart media encapsulation dissection
 * Copyright 2004, Anders Broman.
 * Copyright 2004, Olivier Biot.
 *
 * $Id: packet-multipart.c,v 1.8 2004/03/08 22:03:59 obiot Exp $
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * References for "media-type multipart/mixed :
 * http://www.iana.org/assignments/media-types/index.html
 * http://www.rfc-editor.org/rfc/rfc2045.txt
 * http://www.rfc-editor.org/rfc/rfc2046.txt
 * http://www.rfc-editor.org/rfc/rfc2047.txt
 * http://www.rfc-editor.org/rfc/rfc2048.txt
 * http://www.rfc-editor.org/rfc/rfc2049.txt
 *
 * Part of the code is modeled from the SIP and HTTP dissectors
 *
 * General format of a MIME multipart document:
 *		[ preamble line-end ]
 *		dash-boundary transport-padding line-end
 *		body-part
 *		*encapsulation
 *		close-delimiter transport-padding
 *		[ line-end epilogue ]
 *
 * Where:
 *		dash-boundary     := "--" boundary
 *		encapsulation     := delimiter transport-padding line-end body-part
 *		delimiter         := line-end body-part
 *		close-delimiter   := delimiter "--"
 *		body-part         := MIME-part-headers [ line-end *OCTET ]
 *		transport-padding := *LWSP-char
 * 
 * Note that line-end is often a LF instead of a CRLF.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "prefs.h"
#include <glib.h>
#include <ctype.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>

/* Dissector table for media requiring special attention in multipart
 * encapsulation. */
static dissector_table_t multipart_media_subdissector_table;

/* Initialize the protocol and registered fields */
static int proto_multipart = -1;

/* Initialize the subtree pointers */
static gint ett_multipart = -1;
static gint ett_multipart_main = -1;
static gint ett_multipart_body = -1;

/* Not sure that compact_name exists for multipart, but choose to keep
 * the structure from SIP dissector, all the content- is also from SIP */


static const char *multipart_headers[] = {
	"Unknown-header",		/* Pad so that the real headers start at index 1 */
	"Content-Disposition",
	"Content-Encoding",
	"Content-Language",
	"Content-Length",
	"Content-Type",
};

#define POS_CONTENT_DISPOSITION		1
#define POS_CONTENT_ENCODING		2
#define POS_CONTENT_LANGUAGE		3
#define POS_CONTENT_LENGTH			4
#define POS_CONTENT_TYPE			5

/* Initialize the header fields */
static gint hf_multipart_type = -1;
static gint hf_header_array[] = {
	-1, /* "Unknown-header" - Pad so that the real headers start at index 1 */
	-1, /* "Content-Disposition" */
	-1, /* "Content-Encoding" */
	-1, /* "Content-Language" */
	-1, /* "Content-Length" */
	-1, /* "Content-Type" */
};

/* Define media_type/Content type table */
static dissector_table_t media_type_dissector_table;

/* Data dissector handle */
static dissector_handle_t data_handle;

/* Determins if	bodies with no media type dissector shoud be displayed
 * as raw text, may cause problems with images sound etc
 * TODO improve to check for different content types ?
 */
static gboolean display_unknown_body_as_text = FALSE;


typedef struct {
	const char *type; /* Type of multipart */
	char *boundary; /* Boundary string (enclosing quotes removed if any) */
	guint boundary_length; /* Length of the boundary string */
} multipart_info_t;



static gint
find_first_boundary(tvbuff_t *tvb, gint start, const guint8 *boundary,
		gint boundary_len, gint *boundary_line_len, gboolean *last_boundary);
static gint
find_next_boundary(tvbuff_t *tvb, gint start, const guint8 *boundary,
		gint boundary_len, gint *boundary_line_len, gboolean *last_boundary);
static gint
process_preamble(proto_tree *tree, tvbuff_t *tvb, const guint8 *boundary,
		gint boundary_len, gboolean *last_boundary);
static gint
process_body_part(proto_tree *tree, tvbuff_t *tvb, const guint8 *boundary,
		gint boundary_len, packet_info *pinfo, gint start,
		gboolean *last_boundary);
static gint
is_known_multipart_header(const char *header_str, guint len);
static gint
index_of_char(const char *str, const char c);
char *
unfold_and_compact_mime_header(const char *lines, gint *first_colon_offset);

/*
 * Unfold and clean up a MIME-like header, and process LWS as follows:
 *		o Preserves LWS in quoted text
 *		o Remove LWS before and after a separator
 *		o Remove trailing LWS
 *		o Replace other LWS with a single space
 * Set value to the start of the value 
 * Return the cleaned-up RFC2822 header (buffer must be freed).
 */
char *
unfold_and_compact_mime_header(const char *lines, gint *first_colon_offset)
{
	const char *p = lines;
	char c;
	char *ret, *q;
	char sep_seen = 0; /* Did we see a separator ":;," */
	char lws = FALSE; /* Did we see LWS (incl. folding) */
	gint colon = -1;

	if (! lines) return NULL;

	c = *p;
	ret = g_malloc(strlen(lines) + 1);
	q = ret;

	while (c) {
		if (c == ':') {
			lws = FALSE; /* Prevent leading LWS from showing up */
			if (colon == -1) {/* First colon */
				colon = q - ret;
			}
			*(q++) = sep_seen = c;
			p++;
		} else if (c == ';' || c == ',' || c == '=') {
			lws = FALSE; /* Prevent leading LWS from showing up */
			*(q++) = sep_seen = c;
			p++;
		} else if (c == ' ' || c == '\t') {
			lws = TRUE;
			p++;
		} else if (c == '\n') {
			lws = FALSE; /* Skip trailing LWS */
			if ((c = *(p+1))) {
				if (c == ' ' || c == '\t') { /* Header unfolding */
					lws = TRUE;
					p += 2;
				} else {
					*q = c = 0; /* Stop */
				}
			}
		} else if (c == '\r') {
			lws = FALSE;
			if ((c = *(p+1))) {
				if (c == '\n') {
					if ((c = *(p+2))) {
						if (c == ' ' || c == '\t') { /* Header unfolding */
							lws = TRUE;
							p += 3;
						} else {
							*q = c = 0; /* Stop */
						}
					}
				} else if (c == ' ' || c == '\t') { /* Header unfolding */
					lws = TRUE;
					p += 2;
				} else {
					*q = c = 0; /* Stop */
				}
			}
		} else if (c == '"') { /* Start of quoted-string */
			lws = FALSE;
			*(q++) = c;
			while (c) {
				c = *(q++) = *(++p);
				if (c == '"') {
					p++; /* Skip closing quote */
					break;
				}
			}
		} else { /* Regular character */
			if (sep_seen) {
				sep_seen = 0;
				lws = FALSE;
			} else {
				if (lws) {
					*(q++) = ' ';
					lws = FALSE;
				}
			}
			lws = FALSE;
			*(q++) = c;
			p++; /* OK */
		}

		if (c) {
			c = *p;
		}
	}
	*q = 0;

	*first_colon_offset = colon;
	return (ret);
}

/* Return the index of a given char in the given string,
 * or -1 if not found.
 */
static gint
index_of_char(const char *str, const char c)
{
	gint len = 0;
	const char *p = str;

	while (*p && *p != c) {
		p++;
		len++;
	}

	if (*p)
		return len;
	return -1;
}

/* Retrieve the media information from pinfo->private_data,
 * and compute the boundary string and its length.
 * Return a pointer to a filled-in multipart_info_t, or NULL on failure.
 * 
 * Boundary delimiters must not appear within the encapsulated material,
 * and must be no longer than 70 characters, not counting the two
 * leading hyphens. (quote from rfc2046)
 */
static multipart_info_t *
get_multipart_info(packet_info *pinfo)
{
	const char *start, *p;
	int len = 0;
	multipart_info_t *m_info = NULL;
	const char *type = pinfo->match_string;
	const char *parameters = pinfo->private_data;
	gint dummy;

	if ((type == NULL) || (parameters == NULL)) {
		/*
		 * We need both a content type AND parameters
		 * for multipart dissection.
		 */
		return NULL;
	}

	/* Clean up the parameters */
	parameters = unfold_and_compact_mime_header(parameters, &dummy);

	/*
	 * Process the private data
	 * The parameters must contain the boundary string
	 */
	p = parameters;
	while (*p) {
		if (strncasecmp(p, "boundary=", 9) == 0)
			break;
		/* Skip to next parameter */
		p = strchr(p, ';');
		if (p == NULL)
			return NULL;
		p++; /* Skip semicolon */
		while ((*p) && isspace((guchar)*p))
			p++; /* Skip white space */
	}
	start = p + 9;
	if (start[0] == 0) {
		return NULL;
	}

	/*
	 * Process the parameter value
	 */
	if (start[0] == '"') {
		/*
		 * Boundary string is a quoted-string
		 */
		start++; /* Skip the quote */
		len = index_of_char(start, '"');
		if (len < 0) {
			/*
			 * No closing quote
			 */
			return NULL;
		}
	} else {
		/*
		 * Look for end of boundary
		 */
		p = start;
		while (*p) {
			if (*p == ';' || isspace((guchar)*p))
				break;
			p++;
			len++;
		}
	}
	/*
	 * There is a value for the boundary string
	 */
	m_info = g_malloc(sizeof(multipart_info_t));
	m_info->type = type;
	m_info->boundary = g_strndup(start, len);
	m_info->boundary_length = len;

	return m_info;
}

static void
cleanup_multipart_info(void *data)
{
	multipart_info_t *m_info = data;
	if (m_info) {
		if (m_info->boundary)
			g_free(m_info->boundary);
		g_free(m_info);
	}
}

/*
 * The first boundary does not implicitly contain the leading
 * line-end sequence.
 *
 * Return the offset to the 1st byte of the boundary delimiter line.
 * Set boundary_line_len to the length of the entire boundary delimiter.
 * Set last_boundary to TRUE if we've seen the last-boundary delimiter.
 */
static gint
find_first_boundary(tvbuff_t *tvb, gint start, const guint8 *boundary,
		gint boundary_len, gint *boundary_line_len, gboolean *last_boundary)
{
	gint offset = start, next_offset, line_len, boundary_start;

	while (tvb_length_remaining(tvb, offset + 2 + boundary_len) > 0) {
		boundary_start = offset;
		if (((tvb_strneql(tvb, offset, (const guint8 *)"--", 2) == 0)
					&& (tvb_strneql(tvb, offset + 2, boundary,	boundary_len) == 0)))
		{
			/* Boundary string; now check if last */
			if ((tvb_length_remaining(tvb, offset + 2 + boundary_len + 2) >= 0)
					&& (tvb_strneql(tvb, offset + 2 + boundary_len,
							(const guint8 *)"--", 2) == 0)) {
				*last_boundary = TRUE;
			} else {
				*last_boundary = FALSE;
			}
			/* Look for line end of the boundary line */
			line_len =  tvb_find_line_end(tvb, offset, -1, &offset, FALSE);
			if (line_len == -1) {
				*boundary_line_len = -1;
			} else {
				*boundary_line_len = offset - boundary_start;
			}
			return boundary_start;
		}
		line_len =  tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
		if (line_len == -1) {
			return -1;
		}
		offset = next_offset;
	}

	return -1;
}

/*
 * Unless the first boundary, subsequent boundaries include a line-end sequence
 * before the dashed boundary string.
 *
 * Return the offset to the 1st byte of the boundary delimiter line.
 * Set boundary_line_len to the length of the entire boundary delimiter.
 * Set last_boundary to TRUE if we've seen the last-boundary delimiter.
 */
static gint
find_next_boundary(tvbuff_t *tvb, gint start, const guint8 *boundary,
		gint boundary_len, gint *boundary_line_len, gboolean *last_boundary)
{
	gint offset = start, next_offset, line_len, boundary_start;

	while (tvb_length_remaining(tvb, offset + 2 + boundary_len) > 0) {
		line_len =  tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
		if (line_len == -1) {
			return -1;
		}
		boundary_start = offset + line_len;
		if (((tvb_strneql(tvb, next_offset, (const guint8 *)"--", 2) == 0)
					&& (tvb_strneql(tvb, next_offset + 2, boundary,	boundary_len) == 0)))
		{
			/* Boundary string; now check if last */
			if ((tvb_length_remaining(tvb, next_offset + 2 + boundary_len + 2) >= 0)
					&& (tvb_strneql(tvb, next_offset + 2 + boundary_len,
							(const guint8 *)"--", 2) == 0)) {
				*last_boundary = TRUE;
			} else {
				*last_boundary = FALSE;
			}
			/* Look for line end of the boundary line */
			line_len =  tvb_find_line_end(tvb, next_offset, -1, &offset, FALSE);
			if (line_len == -1) {
				*boundary_line_len = -1;
			} else {
				*boundary_line_len = offset - boundary_start;
			}
			return boundary_start;
		}
		offset = next_offset;
	}

	return -1;
}

/*
 * Process the multipart preamble:
 *		[ preamble line-end ] dashed-boundary transport-padding line-end
 *
 * Return the offset to the start of the first body-part.
 */
static gint
process_preamble(proto_tree *tree, tvbuff_t *tvb, const guint8 *boundary,
		gint boundary_len, gboolean *last_boundary)
{
	gint boundary_start, boundary_line_len, body_part_start;

	body_part_start = 0;
	boundary_start = find_first_boundary(tvb, 0, boundary, boundary_len,
			&boundary_line_len, last_boundary);
	if (boundary_start == 0) {
		if (tree) {
			proto_tree_add_text(tree, tvb, boundary_start, boundary_line_len,
					"First boundary: %s",
					tvb_format_text(tvb, boundary_start, boundary_line_len));
		}
		return boundary_start + boundary_line_len;
	} else if (boundary_start > 0) {
		if (boundary_line_len > 0) {
			gint body_part_start = boundary_start + boundary_line_len;

			if (tree) {
				if (body_part_start > 0) {
					proto_tree_add_text(tree, tvb, 0, body_part_start,
							"Preamble");
				}
				proto_tree_add_text(tree, tvb, boundary_start,
						boundary_line_len, "First boundary: %s",
						tvb_format_text(tvb, boundary_start,
							boundary_line_len));
			}
			return body_part_start;
		}
	}
	return -1;
}

/*
 * Process a multipart body-part:
 *		MIME-part-headers [ line-end *OCTET ]
 *		line-end dashed-boundary transport-padding line-end
 *
 * If applicable, call a media subdissector.
 *
 * Return the offset to the start of the next body-part.
 */
static gint
process_body_part(proto_tree *tree, tvbuff_t *tvb, const guint8 *boundary,
		gint boundary_len, packet_info *pinfo, gint start,
		gboolean *last_boundary)
{
	proto_tree *subtree = NULL;
	proto_item *ti = NULL;
	gint offset = start, next_offset;
	gint line_len = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
	char *parameters = NULL;
	gint body_start, boundary_start, boundary_line_len;

	char *content_type_str = NULL;

	if (tree) {
		ti = proto_tree_add_text(tree, tvb, start, 0,
				"Encapsulated multipart part");
		subtree = proto_item_add_subtree(ti, ett_multipart_body);
	}
	/*
	 * Process the MIME-part-headers
	 */

	while (line_len > 0)
	{
		gint colon_offset;
		char *header_str = tvb_get_string(tvb, offset, next_offset - offset);

		header_str = unfold_and_compact_mime_header(header_str, &colon_offset);
		if (colon_offset <= 0) {
			if (tree) {
				proto_tree_add_text(subtree, tvb, offset, next_offset - offset,
						"%s",
						tvb_format_text(tvb, offset, next_offset - offset));
			}
		} else {
			gint hf_index;

			/* Split header name from header value */
			header_str[colon_offset] = '\0';
			hf_index = is_known_multipart_header(header_str, colon_offset);

			if (hf_index == -1) {
				if (tree) {
					proto_tree_add_text(subtree, tvb, offset,
							next_offset - offset,
							"%s",
							tvb_format_text(tvb, offset, next_offset - offset));
				}
			} else {
				char *value_str = header_str + colon_offset + 1;

				if (tree) {
					proto_tree_add_string_format(subtree,
							hf_header_array[hf_index], tvb,
							offset, next_offset - offset,
							(const char *)value_str, "%s",
							tvb_format_text(tvb, offset, next_offset - offset));
				}

				switch (hf_index) {
					case POS_CONTENT_TYPE:
						{
							/* The Content-Type starts at colon_offset + 1 */
							gint semicolon_offset = index_of_char(
									value_str, ';');

							if (semicolon_offset > 0) {
								value_str[semicolon_offset] = '\0';
								parameters = value_str + semicolon_offset + 1;
							} else {
								parameters = NULL;
							}
#if GLIB_MAJOR_VERSION < 2
							content_type_str = g_strdup(value_str);
							g_strdown(content_type_str);
#else
							content_type_str = g_ascii_strdown(value_str, -1);
#endif
						}
						break;

					default:
						break;
				}
			}
		}
		offset = next_offset;
		line_len = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
	}
	if (line_len < 0) {
		/* ERROR */
		return -1;
	}
	proto_tree_add_text(subtree, tvb, offset, next_offset - offset,
			"%s", tvb_format_text(tvb, offset, next_offset - offset));

	body_start = next_offset;

	/*
	 * Process the body
	 */

	boundary_start = find_next_boundary(tvb, body_start, boundary, boundary_len,
			&boundary_line_len, last_boundary);
	if (boundary_start > 0) {
		gint body_len = boundary_start - body_start;
		tvbuff_t *tmp_tvb = tvb_new_subset(tvb, body_start,
				body_len, body_len);

		if (content_type_str) {
			/*
			 * subdissection
			 */
			void *save_private_data = pinfo->private_data;
			gboolean dissected;

			pinfo->private_data = parameters;
			/*
			 * First try the dedicated multipart dissector table
			 */
			dissected = dissector_try_string(multipart_media_subdissector_table,
						content_type_str, tmp_tvb, pinfo, subtree);
			if (! dissected) {
				/*
				 * Fall back to the default media dissector table
				 */
				dissected = dissector_try_string(media_type_dissector_table,
						content_type_str, tmp_tvb, pinfo, subtree);
			}
			pinfo->private_data = save_private_data;
			g_free(content_type_str);
			content_type_str = NULL;
			parameters = NULL; /* Shares same memory as content_type_str */
			if (! dissected) {
				call_dissector(data_handle, tmp_tvb, pinfo, subtree);
			}
		} else {
			call_dissector(data_handle, tmp_tvb, pinfo, subtree);
		}
		if (tree) {
			if (*last_boundary == TRUE) {
				proto_tree_add_text(tree, tvb,
						boundary_start, boundary_line_len,
						"Last boundary: %s",
						tvb_format_text(tvb, boundary_start,
							boundary_line_len));
			} else {
				proto_tree_add_text(tree, tvb,
						boundary_start, boundary_line_len,
						"Boundary: %s",
						tvb_format_text(tvb, boundary_start,
							boundary_line_len));
			}
		}
		return boundary_start + boundary_line_len;
	}

	return -1;
}

/*
 * Call this method to actually dissect the multipart body.
 * NOTE - Only do so if a boundary string has been found!
 */
static void dissect_multipart(tvbuff_t *tvb, packet_info *pinfo,
		proto_tree *tree)
{
	proto_tree *subtree = NULL;
	proto_item *ti = NULL;
	multipart_info_t *m_info = get_multipart_info(pinfo);
	gint header_start = 0;
	guint8 *boundary;
	gint boundary_len;
	gint offset = 0;
	gboolean last_boundary = FALSE;

	if (m_info == NULL) {
		/*
		 * We can't get the required multipart information
		 */
		proto_tree_add_text(tree, tvb, 0, -1,
				"The multipart dissector could not find "
				"the required boundary parameter.");
		call_dissector(data_handle, tvb, pinfo, tree);
		return;
	}
	boundary = (guint8 *)m_info->boundary;
	boundary_len = m_info->boundary_length;
	/* Clean up the memory if an exception is thrown */
	/* CLEANUP_PUSH(cleanup_multipart_info, m_info); */

	/* Add stuff to the protocol tree */
	if (tree) {
		ti = proto_tree_add_item(tree, proto_multipart,
				tvb, 0, -1, FALSE);
		subtree = proto_item_add_subtree(ti, ett_multipart);
		proto_item_append_text(ti, ", Type: %s, Boundary: \"%s\"",
				m_info->type, m_info->boundary);
		proto_tree_add_string(subtree, hf_multipart_type,
				tvb, 0, 0, pinfo->match_string);
	}

	/*
	 * Make no entries in Protocol column and Info column on summary display,
	 * but stop sub-dissectors from clearing entered text in summary display.
	 */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_fence(pinfo->cinfo, COL_INFO);

	offset = 0;

	/*
	 * Process the multipart preamble
	 */
	header_start = process_preamble(subtree, tvb, boundary,
			boundary_len, &last_boundary);
	if (header_start == -1) {
		call_dissector(data_handle, tvb, pinfo, subtree);
		/* Clean up the dynamically allocated memory */
		cleanup_multipart_info(m_info);
		return;
	}
	/*
	 * Process the encapsulated bodies
	 */
	while (last_boundary == FALSE) {
		header_start = process_body_part(subtree, tvb, boundary, boundary_len,
				pinfo, header_start, &last_boundary);
		if (header_start == -1) {
			/* Clean up the dynamically allocated memory */
			cleanup_multipart_info(m_info);
			return;
		}
	}
	/*
	 * Process the multipart trailer
	 */
	if (tree) {
		if (tvb_length_remaining(tvb, header_start) > 0) {
			proto_tree_add_text(subtree, tvb, header_start, -1, "Trailer");
		}
	}
	/* Clean up the dynamically allocated memory */
	cleanup_multipart_info(m_info);
	return;
}

/* Returns index of method in multipart_headers */
static gint
is_known_multipart_header(const char *header_str, guint len)
{
	guint i;

	for (i = 1; i < array_length(multipart_headers); i++) {
		if (len == strlen(multipart_headers[i]) &&
			strncasecmp(header_str, multipart_headers[i], len) == 0) {
			return i;
		}
	}

	return -1;
}

/*
 * Register the protocol with Ethereal.
 *
 * This format is required because a script is used to build the C function
 * that calls all the protocol registration.
 */

void
proto_register_multipart(void)
{

/* Setup list of header fields  See Section 1.6.1 for details */
	static hf_register_info hf[] = {
		{ &hf_multipart_type,
			{	"Type",
				"mime_multipart.type",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"RFC 3261: MIME multipart encapsulation type", HFILL
			}
		},
		{ &hf_header_array[POS_CONTENT_DISPOSITION],
			{	"Content-Disposition",
				"mime_multipart.header.content-disposition",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"RFC 3261: Content-Disposition Header", HFILL
			}
		},
		{ &hf_header_array[POS_CONTENT_ENCODING],
			{	"Content-Encoding",
				"mime_multipart.header.content-encoding",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"RFC 3261: Content-Encoding Header", HFILL
			}
		},
		{ &hf_header_array[POS_CONTENT_LANGUAGE],
			{	"Content-Language",
				"mime_multipart.header.content-language",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"RFC 3261: Content-Language Header", HFILL
			}
		},
		{ &hf_header_array[POS_CONTENT_LENGTH],
			{	"Content-Length",
				"mime_multipart.header.content-length",
				FT_STRING, BASE_NONE, NULL, 0x0,
				"RFC 3261: Content-Length Header", HFILL
			}
		},
		{ &hf_header_array[POS_CONTENT_TYPE],
			{	"Content-Type",
				"mime_multipart.header.content-type",
				FT_STRING, BASE_NONE,NULL,0x0,
				"RFC 3261: Content-Type Header", HFILL
			}
		},
	};

	/*
	 * Preferences
	 */
	module_t *multipart_module;

	/*
	 * Setup protocol subtree array
	 */
	static gint *ett[] = {
		&ett_multipart,
		&ett_multipart_main,
		&ett_multipart_body,
	};

	/*
	 * Register the protocol name and description
	 */
	proto_multipart = proto_register_protocol(
			"MIME Multipart Media Encapsulation",
			"MIME multipart",
			"mime_multipart");

	/*
	 * Required function calls to register
	 * the header fields and subtrees used.
	 */
	proto_register_field_array(proto_multipart, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/*
	 * Get the content type and Internet media type table
	 */
	media_type_dissector_table = find_dissector_table("media_type");

	multipart_module = prefs_register_protocol(proto_multipart, NULL);

	prefs_register_bool_preference(multipart_module,
			"display_unknown_body_as_text",
			"Display bodies without media type as text",
			"Display multipart bodies with no media type dissector"
			" as raw text (may cause problems with binary data).",
			&display_unknown_body_as_text);

	/*
	 * Dissectors requiring different behavior in cases where the media
	 * is contained in a multipart entity should register their multipart
	 * dissector in the dissector table below, which is similar to the
	 * "media_type" dissector table defined in the HTTP dissector code.
	 */
	multipart_media_subdissector_table = register_dissector_table(
			"multipart_media_type",
			"Internet media type (for multipart processing)",
			FT_STRING, BASE_NONE);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_multipart(void)
{
	dissector_handle_t multipart_handle;

	/*
	 * When we cannot display the data, call the data dissector
	 */
	data_handle = find_dissector("data");

	/*
	 * Handle for multipart dissection
	 */
	multipart_handle = create_dissector_handle(
			dissect_multipart, proto_multipart);

	dissector_add_string("media_type",
			"multipart/mixed", multipart_handle);
	dissector_add_string("media_type",
			"multipart/related", multipart_handle);
	dissector_add_string("media_type",
			"multipart/alternative", multipart_handle);
	dissector_add_string("media_type",
			"multipart/form-data", multipart_handle);

}
