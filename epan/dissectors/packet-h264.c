/* packet-h264.c
 * Routines for H.264 dissection
 * Copyright 2007, Anders Broman <anders.broman[at]ericsson.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * References:
 * http://www.ietf.org/rfc/rfc3984.txt?number=3984
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/proto.h>

#include "prefs.h"


/* Initialize the protocol and registered fields */
static int proto_h264						= -1;
static int hf_h264_type						= -1;
static int hf_h264_nal_f_bit				= -1;
static int hf_h264_nal_nri					= -1;
static int hf_h264_profile					= -1;
static int hf_h264_profile_idc				= -1;
static int hf_h264_constraint_set0_flag		= -1;
static int hf_h264_constraint_set1_flag		= -1;
static int hf_h264_constraint_set2_flag		= -1;
static int hf_h264_constraint_set3_flag		= -1;
static int hf_h264_reserved_zero_4bits		= -1;
static int hf_h264_level_idc				= -1;
static int hf_h264_nal_unit					= -1;
static int hf_h264_forbidden_zero_bit		= -1;
static int hf_h264_nal_ref_idc				= -1;
static int hf_h264_nal_unit_type			= -1;

/* Initialize the subtree pointers */
static int ett_h264 = -1;
static int ett_h264_profile = -1;
static int ett_h264_nal = -1;
static int ett_h264_nal_unit = -1;

/* The dynamic payload type which will be dissected as H.264 */

static guint dynamic_payload_type = 0;
static guint temp_dynamic_payload_type = 0;

static const true_false_string h264_f_bit_vals = {
  "Bit errors or other syntax violations",
  "No bit errors or other syntax violations"
};


static const value_string h264_type_values[] = {
	{ 0,	"Undefined" }, 
	{ 1,	"NAL unit" },	/* Single NAL unit packet per H.264 */
	{ 2,	"NAL unit" },
	{ 3,	"NAL unit" },
	{ 4,	"NAL unit" },
	{ 5,	"NAL unit" },
	{ 6,	"NAL unit" },
	{ 7,	"NAL unit" },
	{ 8,	"NAL unit" },
	{ 9,	"NAL unit" },
	{ 10,	"NAL unit" },
	{ 11,	"NAL unit" },	
	{ 12,	"NAL unit" },
	{ 13,	"NAL unit" },
	{ 14,	"NAL unit" },
	{ 15,	"NAL unit" },
	{ 16,	"NAL unit" },
	{ 17,	"NAL unit" },
	{ 18,	"NAL unit" },
	{ 19,	"NAL unit" },
	{ 20,	"NAL unit" },
	{ 21,	"NAL unit" },	
	{ 22,	"NAL unit" },
	{ 23,	"NAL unit" },
	{ 24,	"STAP-A" },		/* Single-time aggregation packet */
	{ 25,	"STAP-B" },		/* Single-time aggregation packet */
	{ 26,	"MTAP16" },		/* Multi-time aggregation packet */
	{ 27,	"MTAP24" },		/* Multi-time aggregation packet */ 
	{ 28,	"FU-A" },		/* Fragmentation unit */
	{ 29,	"FU-B" },		/* Fragmentation unit */
	{ 30,	"undefined" }, 
	{ 31,	"undefined" }, 
	{ 0,	NULL }
};


static const value_string h264_profile_idc_values[] = {
	{ 66,	"Baseline profile" },
	{ 77,	"Main profile" },
	{ 88,	"Extended profile" },
	{ 100,	"High profile" },
	{ 110,	"High 10 profile" },
	{ 122,	"High 4:2:2 profile" },
	{ 144,	"High 4:4:4 profile" },
	{ 0,	NULL }
};

static const value_string h264_nal_unit_type_vals[] = {
	{ 0,	"Unspecified" },
	{ 1,	"Coded slice of a non-IDR picture" },
	{ 2,	"Coded slice data partition A" },
	{ 3,	"Coded slice data partition B" },
	{ 4,	"Coded slice data partition C" },
	{ 5,	"Coded slice of an IDR picture" },
	{ 6,	"Supplemental enhancement information (SEI)" },
	{ 7,	"Sequence parameter set" },
	{ 8,	"Picture parameter set" },
	{ 9,	"Access unit delimiter" },
	{ 10,	"End of sequence" },
	{ 11,	"End of stream" },
	{ 12,	"Filler data" },
	{ 13,	"Sequence parameter set extension" },
	{ 14,	"Reserved" },
	{ 15,	"Reserved" },
	{ 16,	"Reserved" },
	{ 17,	"Reserved" },
	{ 18,	"Reserved" },
	{ 19,	"Coded slice of an auxiliary coded picture without partitioning" },
	{ 20,	"Reserved" },
	{ 21,	"Reserved" },
	{ 22,	"Reserved" },
	{ 23,	"Reserved" },
	{ 24,	"Unspecified" },
	{ 25,	"Unspecified" },
	{ 26,	"Unspecified" },
	{ 27,	"Unspecified" },
	{ 28,	"Unspecified" },
	{ 29,	"Unspecified" },
	{ 30,	"Unspecified" },
	{ 31,	"Unspecified" },
	{ 0,	NULL }
};

/* Used To dissect SDP parameter (H.264)profile */
void
dissect_h264_profile(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *item;
	proto_tree *h264_profile_tree;
	gint	offset = 0;

	item = proto_tree_add_item(tree, hf_h264_profile, tvb, offset, -1, FALSE);
	h264_profile_tree = proto_item_add_subtree(item, ett_h264_profile);

	proto_tree_add_item(h264_profile_tree, hf_h264_profile_idc, tvb, offset, 1, FALSE);
	offset++;
	
	proto_tree_add_item(h264_profile_tree, hf_h264_constraint_set0_flag, tvb, offset, 1, FALSE);
	proto_tree_add_item(h264_profile_tree, hf_h264_constraint_set1_flag, tvb, offset, 1, FALSE);
	proto_tree_add_item(h264_profile_tree, hf_h264_constraint_set2_flag, tvb, offset, 1, FALSE);
	proto_tree_add_item(h264_profile_tree, hf_h264_constraint_set3_flag, tvb, offset, 1, FALSE);
	proto_tree_add_item(h264_profile_tree, hf_h264_reserved_zero_4bits, tvb, offset, 1, FALSE);
	offset++;

	/* A level to which the bitstream conforms shall be indicated by the syntax element level_idc as follows.
	 *	If level_idc is equal to 9, the indicated level is level 1b.
	 *	Otherwise (level_idc is not equal to 9), level_idc shall be set equal to a value of ten times the level number
	 *	specified in Table A-1.
	 */

	proto_tree_add_item(h264_profile_tree, hf_h264_level_idc, tvb, offset, 1, FALSE);

}


static void
dissect_h264_slice_layer_without_partitioning_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	proto_tree_add_text(tree, tvb, offset, -1, "Not decoded yet");

}

static void
dissect_h264_slice_data_partition_a_layer_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	proto_tree_add_text(tree, tvb, offset, -1, "Not decoded yet");

}

static void
dissect_h264_slice_data_partition_b_layer_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	proto_tree_add_text(tree, tvb, offset, -1, "Not decoded yet");

}

static void
dissect_h264_slice_data_partition_c_layer_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	proto_tree_add_text(tree, tvb, offset, -1, "Not decoded yet");

}


static void
dissect_h264_sei_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	proto_tree_add_text(tree, tvb, offset, -1, "Not decoded yet");

}

/* Ref 7.3.2.1 Sequence parameter set RBSP syntax */
static void
dissect_h264_seq_parameter_set_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	/* profile_idc 0 u(8) */
	proto_tree_add_item(tree, hf_h264_profile_idc, tvb, offset, 1, FALSE);
	offset++;
	/* constraint_set0_flag 0 u(1) */
	proto_tree_add_item(tree, hf_h264_constraint_set0_flag, tvb, offset, 1, FALSE);
	/* constraint_set1_flag 0 u(1) */
	proto_tree_add_item(tree, hf_h264_constraint_set1_flag, tvb, offset, 1, FALSE);
	/* constraint_set2_flag 0 u(1) */
	proto_tree_add_item(tree, hf_h264_constraint_set2_flag, tvb, offset, 1, FALSE);
	/* constraint_set3_flag 0 u(1) */
	proto_tree_add_item(tree, hf_h264_constraint_set3_flag, tvb, offset, 1, FALSE);
	/* reserved_zero_4bits  equal to 0  0 u(4)*/
	proto_tree_add_item(tree, hf_h264_reserved_zero_4bits, tvb, offset, 1, FALSE);
	offset++;
	/* level_idc 0 u(8) */
	proto_tree_add_item(tree, hf_h264_level_idc, tvb, offset, 1, FALSE);
	offset;
	/* seq_parameter_set_id 0 ue(v) 
	 * ue(v): unsigned integer Exp-Golomb-coded syntax element with the left bit first.
	 * The parsing process for this descriptor is specified in subclause 9.1.
	 */
	proto_tree_add_text(tree, tvb, offset, -1, "Not decoded yet");

	
	offset++;

}

static void
dissect_h264_pic_parameter_set_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	proto_tree_add_text(tree, tvb, offset, -1, "Not decoded yet");

}

static void
dissect_h264_access_unit_delimiter_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	proto_tree_add_text(tree, tvb, offset, -1, "Not decoded yet");

}

static void
dissect_h264_end_of_seq_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	proto_tree_add_text(tree, tvb, offset, -1, "Not decoded yet");

}

static void
dissect_h264_end_of_stream_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	proto_tree_add_text(tree, tvb, offset, -1, "Not decoded yet");

}

static void
dissect_h264_filler_data_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	proto_tree_add_text(tree, tvb, offset, -1, "Not decoded yet");

}

static void
dissect_h264_seq_parameter_set_extension_rbsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	proto_tree_add_text(tree, tvb, offset, -1, "Not decoded yet");

}


/* Dissect NAL unit as recived in sprop-parameter-sets of SDP */
void
dissect_h264_nal_unit(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *item;
	proto_tree *h264_nal_tree;
	gint	offset = 0;
	guint8 nal_unit_type;
	item = proto_tree_add_item(tree, hf_h264_nal_unit, tvb, offset, -1, FALSE);
	h264_nal_tree = proto_item_add_subtree(item, ett_h264_nal_unit);

	/* Ref: 7.3.1 NAL unit syntax */
	nal_unit_type = tvb_get_guint8(tvb,offset) & 0x1f;

	/* forbidden_zero_bit All f(1) */
	proto_tree_add_item(h264_nal_tree, hf_h264_forbidden_zero_bit, tvb, offset, 1, FALSE);
	/* nal_ref_idc All u(2) */
	proto_tree_add_item(h264_nal_tree, hf_h264_nal_ref_idc, tvb, offset, 1, FALSE);
	/* nal_unit_type All u(5) */
	proto_tree_add_item(h264_nal_tree, hf_h264_nal_unit_type, tvb, offset, 1, FALSE);
	offset++;

	switch(nal_unit_type){
	case 0: /* Unspecified */
		proto_tree_add_text(h264_nal_tree, tvb, offset, -1, "Unspecified NAL unit type");
		break;
	case 1:	/* Coded slice of a non-IDR picture */ 
		dissect_h264_slice_layer_without_partitioning_rbsp(tree, tvb, pinfo, offset);
		break;
	case 2:	/* Coded slice data partition A */
		dissect_h264_slice_data_partition_a_layer_rbsp(tree, tvb, pinfo, offset);
		break;
	case 3:	/* Coded slice data partition B */
		dissect_h264_slice_data_partition_b_layer_rbsp(tree, tvb, pinfo, offset);
		break;
	case 4:	/* Coded slice data partition C */
		dissect_h264_slice_data_partition_c_layer_rbsp(tree, tvb, pinfo, offset);
		break;
	case 5:	/* Coded slice of an IDR picture */
		dissect_h264_slice_layer_without_partitioning_rbsp(tree, tvb, pinfo, offset);
		break;
	case 6:	/* Supplemental enhancement information (SEI) */
		dissect_h264_sei_rbsp(tree, tvb, pinfo, offset);
		break;
	case 7:	/* Sequence parameter set*/
		dissect_h264_seq_parameter_set_rbsp(tree, tvb, pinfo, offset);
		break;
	case 8:	/* Picture parameter set */
		dissect_h264_pic_parameter_set_rbsp(tree, tvb, pinfo, offset);
		break;
	case 9:	/* Access unit delimiter */
		dissect_h264_access_unit_delimiter_rbsp(tree, tvb, pinfo, offset);
		break;
	case 10:	/* End of sequence */
		dissect_h264_end_of_seq_rbsp(tree, tvb, pinfo, offset);
		break;
	case 11:	/* End of stream */
		dissect_h264_end_of_stream_rbsp(tree, tvb, pinfo, offset);
		break;
	case 12:	/* Filler data */
		dissect_h264_filler_data_rbsp(tree, tvb, pinfo, offset);
		break;
	case 13:	/* Sequence parameter set extension */
		dissect_h264_seq_parameter_set_extension_rbsp(tree, tvb, pinfo, offset);
		break;
	case 14:	/* Reserved */
	case 15:	/* Reserved */
	case 16:	/* Reserved */
	case 17:	/* Reserved */
	case 18:	/* Reserved */
		proto_tree_add_text(h264_nal_tree, tvb, offset, -1, "Reserved NAL unit type");
		break;
	case 19:	/* Coded slice of an auxiliary coded picture without partitioning */
		dissect_h264_slice_layer_without_partitioning_rbsp(tree, tvb, pinfo, offset);
		break;
	default:
		/* 24..31 Unspecified */
		proto_tree_add_text(h264_nal_tree, tvb, offset, -1, "Unspecified NAL unit type");
		break;
	}

}
/* Code to actually dissect the packets */
static void
dissect_h264(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	proto_item *item, *ti;
	proto_tree *h264_tree, *h264_nal_tree;


/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "H264");
	if (tree) {

		item = proto_tree_add_item(tree, proto_h264, tvb, 0, -1, FALSE);
		h264_tree = proto_item_add_subtree(item, ett_h264);

		ti = proto_tree_add_text(h264_tree, tvb, offset, 1, "NAL unit header or first byte of the payload");
		h264_nal_tree = proto_item_add_subtree(item, ett_h264_nal);
		/* +---------------+
		 * |0|1|2|3|4|5|6|7|
		 * +-+-+-+-+-+-+-+-+
		 * |F|NRI|  Type   |
		 * +---------------+
		 */

		/* F: 1 bit
		 * forbidden_zero_bit.  A value of 0 indicates that the NAL unit type
		 * octet and payload should not contain bit errors or other syntax
		 * violations.  A value of 1 indicates that the NAL unit type octet
		 * and payload may contain bit errors or other syntax violations.
		 */
		proto_tree_add_item(h264_nal_tree, hf_h264_nal_f_bit, tvb, offset, 1, FALSE);
		proto_tree_add_item(h264_nal_tree, hf_h264_nal_nri, tvb, offset, 1, FALSE);
		proto_tree_add_item(h264_nal_tree, hf_h264_type, tvb, offset, 1, FALSE);
		offset++;
		proto_tree_add_text(h264_tree, tvb, offset, -1, "H264 bitstream");
	}/* if tree */

}


/* Register the protocol with Wireshark */
/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_h264(void)
{
	dissector_handle_t h264_handle;
	static int h264_prefs_initialized = FALSE;
	
	h264_handle = create_dissector_handle(dissect_h264, proto_h264);

	if (!h264_prefs_initialized) {
		h264_prefs_initialized = TRUE;
	  }
	else {
			if ( dynamic_payload_type > 95 )
				dissector_delete("rtp.pt", dynamic_payload_type, h264_handle);
	}
	dynamic_payload_type = temp_dynamic_payload_type;

	if ( dynamic_payload_type > 95 ){
		dissector_add("rtp.pt", dynamic_payload_type, h264_handle);
	}
	dissector_add_string("rtp_dyn_payload_type","H264", h264_handle);

}

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_h264(void)
{                 

	module_t *h264_module;

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_h264_nal_f_bit,
			{ "F bit",           "h264.f",
			FT_BOOLEAN, 8, TFS(&h264_f_bit_vals), 0x80,          
			"F bit", HFILL }
		},
		{ &hf_h264_nal_nri,
			{ "Nal_ref_idc (NRI)",           "h264.nal_nri",
			FT_UINT8, BASE_DEC, NULL, 0x60,          
			"NRI", HFILL }
		},
		{ &hf_h264_type,
			{ "NAL unit type",           "h264.nal_unit_hdr",
			FT_UINT8, BASE_DEC, VALS(h264_type_values), 0x1f,          
			"NAL unit type", HFILL }
		},
		{ &hf_h264_profile,
			{ "Profile",           "h264.profile",
			FT_BYTES, BASE_NONE, NULL, 0x0,          
			"Profile", HFILL }
		},
		{ &hf_h264_profile_idc,
			{ "Profile_idc",           "h264.profile_idc",
			FT_UINT8, BASE_DEC, VALS(h264_profile_idc_values), 0x0,          
			"Profile_idc", HFILL }
		},
		{ &hf_h264_constraint_set0_flag,
			{ "Constraint_set0_flag",           "h264.constraint_set0_flag",
			FT_UINT8, BASE_DEC, NULL, 0x80,          
			"Constraint_set0_flag", HFILL }
		},
		{ &hf_h264_constraint_set1_flag,
			{ "Constraint_set1_flag",           "h264.constraint_set1_flag",
			FT_UINT8, BASE_DEC, NULL, 0x40,          
			"Constraint_set1_flag", HFILL }
		},
		{ &hf_h264_constraint_set2_flag,
			{ "Constraint_set1_flag",           "h264.constraint_set2_flag",
			FT_UINT8, BASE_DEC, NULL, 0x20,          
			"NRI", HFILL }
		},
		{ &hf_h264_constraint_set3_flag,
			{ "Constraint_set3_flag",           "h264.constraint_set3_flag",
			FT_UINT8, BASE_DEC, NULL, 0x10,          
			"Constraint_set3_flag", HFILL }
		},
		{ &hf_h264_reserved_zero_4bits,
			{ "Reserved_zero_4bits",           "h264.reserved_zero_4bits",
			FT_UINT8, BASE_DEC, NULL, 0x0f,          
			"Reserved_zero_4bits", HFILL }
		},
		{ &hf_h264_level_idc,
			{ "Level_id",           "h264.level_id",
			FT_UINT8, BASE_DEC, NULL, 0x0,          
			"Level_id", HFILL }
		},
		{ &hf_h264_nal_unit,
			{ "NAL unit",           "h264.nal_unit",
			FT_BYTES, BASE_NONE, NULL, 0x0,          
			"NAL unit", HFILL }
		},
		{ &hf_h264_forbidden_zero_bit,
			{ "Forbidden_zero_bit",           "h264.forbidden_zero_bit",
			FT_UINT8, BASE_DEC, NULL, 0x80,          
			"forbidden_zero_bit", HFILL }
		},
		{ &hf_h264_nal_ref_idc,
			{ "Nal_ref_idc",           "h264.nal_ref_idc",
			FT_UINT8, BASE_DEC, NULL, 0x60,          
			"nal_ref_idc", HFILL }
		},
		{&hf_h264_nal_unit_type,
			{ "Nal_unit_type",           "h264.nal_unit_type",
			FT_UINT8, BASE_DEC, VALS(h264_nal_unit_type_vals), 0x1f,          
			"nal_unit_type", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_h264,
		&ett_h264_profile,
		&ett_h264_nal,
		&ett_h264_nal_unit,
	};

/* Register the protocol name and description */
	proto_h264 = proto_register_protocol("H.264","H264", "h264");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_h264, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	/* Register a configuration option for port */

	
	h264_module = prefs_register_protocol(proto_h264, proto_reg_handoff_h264);

	prefs_register_uint_preference(h264_module, "dynamic.payload.type",
								   "H264 dynamic payload type",
								   "The dynamic payload type which will be interpreted as H264",
								   10,
								   &temp_dynamic_payload_type);

	
	register_dissector("h264", dissect_h264, proto_h264);
}


