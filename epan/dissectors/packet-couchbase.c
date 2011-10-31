/* packet-couchbase.c
 *
 * Routines for Couchbase Protocol.
 * Copyright 2011, Sergey Avseyev <sergey.avseyev@gmail.com>
 *
 * Based on packet-memcache.c: mecmcache binary protocol.
 *
 * Routines for Memcache Binary Protocol
 * http://code.google.com/p/memcached/wiki/MemcacheBinaryProtocol
 *
 * Copyright 2009, Stig Bjorlykke <stig@bjorlykke.org>
 *
 * Routines for Memcache Textual Protocol
 * http://code.sixapart.com/svn/memcached/trunk/server/doc/protocol.txt
 *
 * Copyright 2009, Rama Chitta <rama@gear6.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>

#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/base64.h>
#include <epan/emem.h>
#include <epan/stats_tree.h>
#include <epan/req_resp_hdrs.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include "packet-tcp.h"

#define PNAME  "Couchbase Protocol"
#define PSNAME "Couchbase"
#define PFNAME "couchbase"

#define COUCHBASE_PORT        11210
#define COUCHBASE_HEADER_LEN   24

/* Magic Byte */
#define MAGIC_REQUEST         0x80
#define MAGIC_RESPONSE        0x81

/* Response Status */
#define PROTOCOL_BINARY_RESPONSE_SUCCESS            0x00
#define PROTOCOL_BINARY_RESPONSE_KEY_ENOENT         0x01
#define PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS        0x02
#define PROTOCOL_BINARY_RESPONSE_E2BIG              0x03
#define PROTOCOL_BINARY_RESPONSE_EINVAL             0x04
#define PROTOCOL_BINARY_RESPONSE_NOT_STORED         0x05
#define PROTOCOL_BINARY_RESPONSE_DELTA_BADVAL       0x06
#define PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET     0x07
#define PROTOCOL_BINARY_RESPONSE_AUTH_ERROR         0x20
#define PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE      0x21
#define PROTOCOL_BINARY_RESPONSE_ERANGE             0x22
#define PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND    0x81
#define PROTOCOL_BINARY_RESPONSE_ENOMEM             0x82
#define PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED      0x83
#define PROTOCOL_BINARY_RESPONSE_EINTERNAL          0x84
#define PROTOCOL_BINARY_RESPONSE_EBUSY              0x85
#define PROTOCOL_BINARY_RESPONSE_ETMPFAIL           0x86

/* Command Opcodes */
#define PROTOCOL_BINARY_CMD_GET                     0x00
#define PROTOCOL_BINARY_CMD_SET                     0x01
#define PROTOCOL_BINARY_CMD_ADD                     0x02
#define PROTOCOL_BINARY_CMD_REPLACE                 0x03
#define PROTOCOL_BINARY_CMD_DELETE                  0x04
#define PROTOCOL_BINARY_CMD_INCREMENT               0x05
#define PROTOCOL_BINARY_CMD_DECREMENT               0x06
#define PROTOCOL_BINARY_CMD_QUIT                    0x07
#define PROTOCOL_BINARY_CMD_FLUSH                   0x08
#define PROTOCOL_BINARY_CMD_GETQ                    0x09
#define PROTOCOL_BINARY_CMD_NOOP                    0x0a
#define PROTOCOL_BINARY_CMD_VERSION                 0x0b
#define PROTOCOL_BINARY_CMD_GETK                    0x0c
#define PROTOCOL_BINARY_CMD_GETKQ                   0x0d
#define PROTOCOL_BINARY_CMD_APPEND                  0x0e
#define PROTOCOL_BINARY_CMD_PREPEND                 0x0f
#define PROTOCOL_BINARY_CMD_STAT                    0x10
#define PROTOCOL_BINARY_CMD_SETQ                    0x11
#define PROTOCOL_BINARY_CMD_ADDQ                    0x12
#define PROTOCOL_BINARY_CMD_REPLACEQ                0x13
#define PROTOCOL_BINARY_CMD_DELETEQ                 0x14
#define PROTOCOL_BINARY_CMD_INCREMENTQ              0x15
#define PROTOCOL_BINARY_CMD_DECREMENTQ              0x16
#define PROTOCOL_BINARY_CMD_QUITQ                   0x17
#define PROTOCOL_BINARY_CMD_FLUSHQ                  0x18
#define PROTOCOL_BINARY_CMD_APPENDQ                 0x19
#define PROTOCOL_BINARY_CMD_PREPENDQ                0x1a
#define PROTOCOL_BINARY_CMD_VERBOSITY               0x1b
#define PROTOCOL_BINARY_CMD_TOUCH                   0x1c
#define PROTOCOL_BINARY_CMD_GAT                     0x1d
#define PROTOCOL_BINARY_CMD_GATQ                    0x1e

/* SASL operations */
#define PROTOCOL_BINARY_CMD_SASL_LIST_MECHS         0x20
#define PROTOCOL_BINARY_CMD_SASL_AUTH               0x21
#define PROTOCOL_BINARY_CMD_SASL_STEP               0x22

/* Range operations.
 * These commands are used for range operations and exist within
 * protocol_binary.h for use in other projects. Range operations are
 * not expected to be implemented in the memcached server itself.
 */
#define PROTOCOL_BINARY_CMD_RGET                    0x30
#define PROTOCOL_BINARY_CMD_RSET                    0x31
#define PROTOCOL_BINARY_CMD_RSETQ                   0x32
#define PROTOCOL_BINARY_CMD_RAPPEND                 0x33
#define PROTOCOL_BINARY_CMD_RAPPENDQ                0x34
#define PROTOCOL_BINARY_CMD_RPREPEND                0x35
#define PROTOCOL_BINARY_CMD_RPREPENDQ               0x36
#define PROTOCOL_BINARY_CMD_RDELETE                 0x37
#define PROTOCOL_BINARY_CMD_RDELETEQ                0x38
#define PROTOCOL_BINARY_CMD_RINCR                   0x39
#define PROTOCOL_BINARY_CMD_RINCRQ                  0x3a
#define PROTOCOL_BINARY_CMD_RDECR                   0x3b
#define PROTOCOL_BINARY_CMD_RDECRQ                  0x3c


/* VBucket commands */
#define PROTOCOL_BINARY_CMD_SET_VBUCKET             0x3d
#define PROTOCOL_BINARY_CMD_GET_VBUCKET             0x3e
#define PROTOCOL_BINARY_CMD_DEL_VBUCKET             0x3f

/* TAP commands */
#define PROTOCOL_BINARY_CMD_TAP_CONNECT             0x40
#define PROTOCOL_BINARY_CMD_TAP_MUTATION            0x41
#define PROTOCOL_BINARY_CMD_TAP_DELETE              0x42
#define PROTOCOL_BINARY_CMD_TAP_FLUSH               0x43
#define PROTOCOL_BINARY_CMD_TAP_OPAQUE              0x44
#define PROTOCOL_BINARY_CMD_TAP_VBUCKET_SET         0x45
#define PROTOCOL_BINARY_CMD_TAP_CHECKPOINT_START    0x46
#define PROTOCOL_BINARY_CMD_TAP_CHECKPOINT_END      0x47

/* Commands from EP (eventually persistent) and bucket engines */
#define PROTOCOL_BINARY_CMD_STOP_PERSISTENCE        0x80
#define PROTOCOL_BINARY_CMD_START_PERSISTENCE       0x81
#define PROTOCOL_BINARY_CMD_SET_FLUSH_PARAM         0x82
#define PROTOCOL_BINARY_CMD_CREATE_BUCKET           0x85
#define PROTOCOL_BINARY_CMD_DELETE_BUCKET           0x86
#define PROTOCOL_BINARY_CMD_LIST_BUCKETS            0x87
#define PROTOCOL_BINARY_CMD_EXPAND_BUCKET           0x88
#define PROTOCOL_BINARY_CMD_SELECT_BUCKET           0x89
#define PROTOCOL_BINARY_CMD_START_REPLICATION       0x90
#define PROTOCOL_BINARY_CMD_STOP_REPLICATION        0x91
#define PROTOCOL_BINARY_CMD_SET_TAP_PARAM           0x92
#define PROTOCOL_BINARY_CMD_EVICT_KEY               0x93
#define PROTOCOL_BINARY_CMD_GET_LOCKED              0x94
#define PROTOCOL_BINARY_CMD_UNLOCK_KEY              0x95
#define PROTOCOL_BINARY_CMD_SYNC                    0x96
#define PROTOCOL_BINARY_CMD_OBSERVE                 0xb1
#define PROTOCOL_BINARY_CMD_UNOBSERVE               0xb2
#define PROTOCOL_BINARY_CMD_LAST_CLOSED_CHECKPOINT  0x97
#define PROTOCOL_BINARY_CMD_RESTORE_FILE            0x98
#define PROTOCOL_BINARY_CMD_RESTORE_ABORT           0x99
#define PROTOCOL_BINARY_CMD_RESTORE_COMPLETE        0x9a
#define PROTOCOL_BINARY_CMD_ONLINE_UPDATE_START     0x9b
#define PROTOCOL_BINARY_CMD_ONLINE_UPDATE_COMPLETE  0x9c
#define PROTOCOL_BINARY_CMD_ONLINE_UPDATE_REVERT    0x9d
#define PROTOCOL_BINARY_CMD_DEREGISTER_TAP_CLIENT   0x9e
#define PROTOCOL_BINARY_CMD_RESET_REPLICATION_CHAIN 0x9f
#define PROTOCOL_BINARY_CMD_GET_META                0xa0
#define PROTOCOL_BINARY_CMD_GETQ_META               0xa1
#define PROTOCOL_BINARY_CMD_SET_WITH_META           0xa2
#define PROTOCOL_BINARY_CMD_SETQ_WITH_META          0xa3
#define PROTOCOL_BINARY_CMD_ADD_WITH_META           0xa4
#define PROTOCOL_BINARY_CMD_ADDQ_WITH_META          0xa5
#define PROTOCOL_BINARY_CMD_SNAPSHOT_VB_STATES      0xa6
#define PROTOCOL_BINARY_CMD_VBUCKET_BATCH_COUNT     0xa7


/* Data Types */
#define DT_RAW_BYTES          0x00

static int proto_couchbase = -1;

static int hf_magic = -1;
static int hf_opcode = -1;
static int hf_extlength = -1;
static int hf_keylength = -1;
static int hf_value_length = -1;
static int hf_datatype = -1;
static int hf_vbucket = -1;
static int hf_status = -1;
static int hf_total_bodylength = -1;
static int hf_opaque = -1;
static int hf_cas = -1;
static int hf_extras = -1;
static int hf_extras_flags = -1;
static int hf_extras_flags_backfill = -1;
static int hf_extras_flags_dump = -1;
static int hf_extras_flags_list_vbuckets = -1;
static int hf_extras_flags_takeover_vbuckets = -1;
static int hf_extras_flags_support_ack = -1;
static int hf_extras_flags_request_keys_only = -1;
static int hf_extras_flags_checkpoint = -1;
static int hf_extras_flags_registered_client = -1;
static int hf_extras_expiration = -1;
static int hf_extras_delta = -1;
static int hf_extras_initial = -1;
static int hf_extras_unknown = -1;
static int hf_extras_missing = -1;
static int hf_key = -1;
static int hf_key_missing = -1;
static int hf_value = -1;
static int hf_value_missing = -1;
static int hf_uint64_response = -1;

static gint ett_couchbase = -1;
static gint ett_extras = -1;
static gint ett_extras_flags = -1;

static const value_string magic_vals[] = {
  { MAGIC_REQUEST,         "Request"            },
  { MAGIC_RESPONSE,        "Response"           },
  { 0, NULL }
};

static const value_string status_vals[] = {
  { PROTOCOL_BINARY_RESPONSE_SUCCESS,           "Success"                   },
  { PROTOCOL_BINARY_RESPONSE_KEY_ENOENT,        "Key not found"             },
  { PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS,       "Key exists"                },
  { PROTOCOL_BINARY_RESPONSE_E2BIG,             "Value too big"             },
  { PROTOCOL_BINARY_RESPONSE_EINVAL,            "Invalid arguments"         },
  { PROTOCOL_BINARY_RESPONSE_NOT_STORED,        "Key not stored"            },
  { PROTOCOL_BINARY_RESPONSE_DELTA_BADVAL,      "Bad value to incr/decr"    },
  { PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET,    "Not my vBucket"            },
  { PROTOCOL_BINARY_RESPONSE_AUTH_ERROR,        "Authentication error"      },
  { PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE,     "Authentication continue"   },
  { PROTOCOL_BINARY_RESPONSE_ERANGE,            "Range error"               },
  { PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND,   "Unknown command"           },
  { PROTOCOL_BINARY_RESPONSE_ENOMEM,            "Out of memory"             },
  { PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED,     "Command isn't supported"   },
  { PROTOCOL_BINARY_RESPONSE_EINTERNAL,         "Internal error"            },
  { PROTOCOL_BINARY_RESPONSE_EBUSY,             "Server is busy"            },
  { PROTOCOL_BINARY_RESPONSE_ETMPFAIL,          "Temporary failure"         },
  { 0, NULL }
};

static const value_string opcode_vals[] = {
  { PROTOCOL_BINARY_CMD_GET,                        "Get"                       },
  { PROTOCOL_BINARY_CMD_SET,                        "Set"                       },
  { PROTOCOL_BINARY_CMD_ADD,                        "Add"                       },
  { PROTOCOL_BINARY_CMD_REPLACE,                    "Replace"                   },
  { PROTOCOL_BINARY_CMD_DELETE,                     "Delete"                    },
  { PROTOCOL_BINARY_CMD_INCREMENT,                  "Increment"                 },
  { PROTOCOL_BINARY_CMD_DECREMENT,                  "Decrement"                 },
  { PROTOCOL_BINARY_CMD_QUIT,                       "Quit"                      },
  { PROTOCOL_BINARY_CMD_FLUSH,                      "Flush"                     },
  { PROTOCOL_BINARY_CMD_GETQ,                       "Get Quietly"               },
  { PROTOCOL_BINARY_CMD_NOOP,                       "NOOP"                      },
  { PROTOCOL_BINARY_CMD_VERSION,                    "Version"                   },
  { PROTOCOL_BINARY_CMD_GETK,                       "Get Key"                   },
  { PROTOCOL_BINARY_CMD_GETKQ,                      "Get Key Quietly"           },
  { PROTOCOL_BINARY_CMD_APPEND,                     "Append"                    },
  { PROTOCOL_BINARY_CMD_PREPEND,                    "Prepend"                   },
  { PROTOCOL_BINARY_CMD_STAT,                       "Statistics"                },
  { PROTOCOL_BINARY_CMD_SETQ,                       "Set Quietly"               },
  { PROTOCOL_BINARY_CMD_ADDQ,                       "Add Quietly"               },
  { PROTOCOL_BINARY_CMD_REPLACEQ,                   "Replace Quietly"           },
  { PROTOCOL_BINARY_CMD_DELETEQ,                    "Delete Quietly"            },
  { PROTOCOL_BINARY_CMD_INCREMENTQ,                 "Increment Quietly"         },
  { PROTOCOL_BINARY_CMD_DECREMENTQ,                 "Decrement Quietly"         },
  { PROTOCOL_BINARY_CMD_QUITQ,                      "Quit Quietly"              },
  { PROTOCOL_BINARY_CMD_FLUSHQ,                     "Flush Quietly"             },
  { PROTOCOL_BINARY_CMD_APPENDQ,                    "Append Quietly"            },
  { PROTOCOL_BINARY_CMD_PREPENDQ,                   "Prepend Quietly"           },
  { PROTOCOL_BINARY_CMD_VERBOSITY,                  "Verbosity"                 },
  { PROTOCOL_BINARY_CMD_TOUCH,                      "Touch"                     },
  { PROTOCOL_BINARY_CMD_GAT,                        "Get and Touch"             },
  { PROTOCOL_BINARY_CMD_GATQ,                       "Gat and Touch Quietly"     },
  { PROTOCOL_BINARY_CMD_SASL_LIST_MECHS,            "List SASL Mechanisms"      },
  { PROTOCOL_BINARY_CMD_SASL_AUTH,                  "SASL Authenticate"         },
  { PROTOCOL_BINARY_CMD_SASL_STEP,                  "SASL Step"                 },
  { PROTOCOL_BINARY_CMD_RGET,                       "Range Get"                 },
  { PROTOCOL_BINARY_CMD_RSET,                       "Range Set"                 },
  { PROTOCOL_BINARY_CMD_RSETQ,                      "Range Set Quietly"         },
  { PROTOCOL_BINARY_CMD_RAPPEND,                    "Range Append"              },
  { PROTOCOL_BINARY_CMD_RAPPENDQ,                   "Range Append Quietly"      },
  { PROTOCOL_BINARY_CMD_RPREPEND,                   "Range Prepend"             },
  { PROTOCOL_BINARY_CMD_RPREPENDQ,                  "Range Prepend Quietly"     },
  { PROTOCOL_BINARY_CMD_RDELETE,                    "Range Delete"              },
  { PROTOCOL_BINARY_CMD_RDELETEQ,                   "Range Delete Quietly"      },
  { PROTOCOL_BINARY_CMD_RINCR,                      "Range Increment"           },
  { PROTOCOL_BINARY_CMD_RINCRQ,                     "Range Increment Quietly"   },
  { PROTOCOL_BINARY_CMD_RDECR,                      "Range Decrement"           },
  { PROTOCOL_BINARY_CMD_RDECRQ,                     "Range Decrement Quietly"   },
  { PROTOCOL_BINARY_CMD_SET_VBUCKET,                "Set VBucket"               },
  { PROTOCOL_BINARY_CMD_GET_VBUCKET,                "Get VBucket"               },
  { PROTOCOL_BINARY_CMD_DEL_VBUCKET,                "Delete VBucket"            },
  { PROTOCOL_BINARY_CMD_TAP_CONNECT,                "TAP Connect"               },
  { PROTOCOL_BINARY_CMD_TAP_MUTATION,               "TAP Mutation"              },
  { PROTOCOL_BINARY_CMD_TAP_DELETE,                 "TAP Delete"                },
  { PROTOCOL_BINARY_CMD_TAP_FLUSH,                  "TAP Flush"                 },
  { PROTOCOL_BINARY_CMD_TAP_OPAQUE,                 "TAP Opaque"                },
  { PROTOCOL_BINARY_CMD_TAP_VBUCKET_SET,            "TAP VBucket Set"           },
  { PROTOCOL_BINARY_CMD_TAP_CHECKPOINT_START,       "TAP Checkpoint Start"      },
  { PROTOCOL_BINARY_CMD_TAP_CHECKPOINT_END,         "TAP Checkpoint End"        },
  { PROTOCOL_BINARY_CMD_STOP_PERSISTENCE,           "Stop Persistence"          },
  { PROTOCOL_BINARY_CMD_START_PERSISTENCE,          "Start Persistence"         },
  { PROTOCOL_BINARY_CMD_SET_FLUSH_PARAM,            "Set Flush Parameter"       },
  { PROTOCOL_BINARY_CMD_CREATE_BUCKET,              "Create Bucket"             },
  { PROTOCOL_BINARY_CMD_DELETE_BUCKET,              "Delete Bucket"             },
  { PROTOCOL_BINARY_CMD_LIST_BUCKETS,               "List Buckets"              },
  { PROTOCOL_BINARY_CMD_EXPAND_BUCKET,              "Expand Bucket"             },
  { PROTOCOL_BINARY_CMD_SELECT_BUCKET,              "Select Bucket"             },
  { PROTOCOL_BINARY_CMD_START_REPLICATION,          "Start Replication"         },
  { PROTOCOL_BINARY_CMD_STOP_REPLICATION,           "Stop Replication"          },
  { PROTOCOL_BINARY_CMD_SET_TAP_PARAM,              "Set TAP Parameter"         },
  { PROTOCOL_BINARY_CMD_EVICT_KEY,                  "Evict Key"                 },
  { PROTOCOL_BINARY_CMD_GET_LOCKED,                 "Get Locked"                },
  { PROTOCOL_BINARY_CMD_UNLOCK_KEY,                 "Unlock Key"                },
  { PROTOCOL_BINARY_CMD_SYNC,                       "Sync"                      },
  { PROTOCOL_BINARY_CMD_OBSERVE,                    "Observe"                   },
  { PROTOCOL_BINARY_CMD_UNOBSERVE,                  "Unobserve"                 },
  { PROTOCOL_BINARY_CMD_LAST_CLOSED_CHECKPOINT,     "Last Closed Checkpoint"    },
  { PROTOCOL_BINARY_CMD_RESTORE_FILE,               "Restore File"              },
  { PROTOCOL_BINARY_CMD_RESTORE_ABORT,              "Restore Abort"             },
  { PROTOCOL_BINARY_CMD_RESTORE_COMPLETE,           "Restore Complete"          },
  { PROTOCOL_BINARY_CMD_ONLINE_UPDATE_START,        "Online Update Start"       },
  { PROTOCOL_BINARY_CMD_ONLINE_UPDATE_COMPLETE,     "Online Update Complete"    },
  { PROTOCOL_BINARY_CMD_ONLINE_UPDATE_REVERT,       "Online Update Revert"      },
  { PROTOCOL_BINARY_CMD_DEREGISTER_TAP_CLIENT,      "Deregister TAP Client"     },
  { PROTOCOL_BINARY_CMD_RESET_REPLICATION_CHAIN,    "Reset Replication Chain"   },
  { PROTOCOL_BINARY_CMD_GET_META,                   "Get Meta"                  },
  { PROTOCOL_BINARY_CMD_GETQ_META,                  "Get Meta Quietly"          },
  { PROTOCOL_BINARY_CMD_SET_WITH_META,              "Set with Meta"             },
  { PROTOCOL_BINARY_CMD_SETQ_WITH_META,             "Set with Meta Quietly"     },
  { PROTOCOL_BINARY_CMD_ADD_WITH_META,              "Add with Meta"             },
  { PROTOCOL_BINARY_CMD_ADDQ_WITH_META,             "Add with Meta Quietly"     },
  { PROTOCOL_BINARY_CMD_SNAPSHOT_VB_STATES,         "Snapshot VBuckets States"  },
  { PROTOCOL_BINARY_CMD_VBUCKET_BATCH_COUNT,        "VBucket Batch Count"       },
  /* Internally defined values not valid here */
  { 0, NULL }
};

static const value_string datatype_vals[] = {
  { DT_RAW_BYTES,          "Raw bytes"          },
  { 0, NULL }
};

/* couchbase message types. */
typedef enum _couchbase_type {
  COUCHBASE_REQUEST,
  COUCHBASE_RESPONSE,
  COUCHBASE_UNKNOWN
} couchbase_type_t;

dissector_handle_t couchbase_tcp_handle;

/* couchbase ports */
static const gchar *couchbase_tcp_ports = NULL;
static const gchar *couchbase_tcp_ports_pref = NULL;

/* desegmentation of COUCHBASE header */
static gboolean couchbase_desegment_headers = TRUE;

/* desegmentation of COUCHBASE payload */
static gboolean couchbase_desegment_body = TRUE;

/* should refer to either the request or the response dissector.
 */
typedef int (*ReqRespDissector)(tvbuff_t*, packet_info *, proto_tree *,
                                int, const guchar*, const guchar*, guint8);

static guint
get_memcache_pdu_len (packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
  guint32 bodylen;

  /* Get the length of the memcache body */
  bodylen = tvb_get_ntohl(tvb, offset+8);

  /* That length doesn't include the header; add that in */
  return bodylen + COUCHBASE_HEADER_LEN;
}

static void
dissect_extras (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                gint offset, guint8 extlen, guint8 opcode, gboolean request)
{
  proto_tree *extras_tree = NULL;
  proto_item *extras_item = NULL, *ti;
  gint        save_offset = offset, ii;
  guint       bpos;
  gboolean    illegal = FALSE;  /* Set when extras shall not be present */
  gboolean    missing = FALSE;  /* Set when extras is missing */
  gboolean    first_flag;
  guint32     flags;
  proto_item *tf;
  proto_tree *field_tree;
  emem_strbuf_t *flags_strbuf = ep_strbuf_new_label("<None>");
  const gchar   *tap_connect_flags[] = {
    "BACKFILL", "DUMP", "LIST_VBUCKETS", "TAKEOVER_VBUCKETS",
    "SUPPORT_ACK", "REQUEST_KEYS_ONLY", "CHECKPOINT", "REGISTERED_CLIENT"
  };

  if (extlen) {
    extras_item = proto_tree_add_item (tree, hf_extras, tvb, offset, extlen, ENC_NA);
    extras_tree = proto_item_add_subtree (extras_item, ett_extras);
  }

  switch (opcode) {

  case PROTOCOL_BINARY_CMD_GET:
  case PROTOCOL_BINARY_CMD_GETQ:
  case PROTOCOL_BINARY_CMD_GETK:
  case PROTOCOL_BINARY_CMD_GETKQ:
    if (extlen) {
      if (request) {
        /* Request shall not have extras */
        illegal = TRUE;
      } else {
        proto_tree_add_item (extras_tree, hf_extras_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
      }
    } else if (!request) {
      /* Response must have extras */
      missing = TRUE;
    }
    break;

  case PROTOCOL_BINARY_CMD_SET:
  case PROTOCOL_BINARY_CMD_SETQ:
  case PROTOCOL_BINARY_CMD_ADD:
  case PROTOCOL_BINARY_CMD_ADDQ:
  case PROTOCOL_BINARY_CMD_REPLACE:
  case PROTOCOL_BINARY_CMD_REPLACEQ:
    if (extlen) {
      if (request) {
        proto_tree_add_item (extras_tree, hf_extras_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item (extras_tree, hf_extras_expiration, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
      } else {
        /* Response shall not have extras */
        illegal = TRUE;
      }
    } else if (request) {
      /* Request must have extras */
      missing = TRUE;
    }
    break;

  case PROTOCOL_BINARY_CMD_INCREMENT:
  case PROTOCOL_BINARY_CMD_INCREMENTQ:
  case PROTOCOL_BINARY_CMD_DECREMENT:
  case PROTOCOL_BINARY_CMD_DECREMENTQ:
    if (extlen) {
      if (request) {
        proto_tree_add_item (extras_tree, hf_extras_delta, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;

        proto_tree_add_item (extras_tree, hf_extras_initial, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;

        proto_tree_add_item (extras_tree, hf_extras_expiration, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
      } else {
        /* Response must not have extras (response is in Value) */
        illegal = TRUE;
      }
    } else if (request) {
      /* Request must have extras */
      missing = TRUE;
    }
    break;

  case PROTOCOL_BINARY_CMD_FLUSH:
  case PROTOCOL_BINARY_CMD_FLUSHQ:
    if (extlen) {
      proto_tree_add_item (extras_tree, hf_extras_expiration, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
    }
    break;

  case PROTOCOL_BINARY_CMD_DELETE:
  case PROTOCOL_BINARY_CMD_DELETEQ:
  case PROTOCOL_BINARY_CMD_QUIT:
  case PROTOCOL_BINARY_CMD_QUITQ:
  case PROTOCOL_BINARY_CMD_VERSION:
  case PROTOCOL_BINARY_CMD_APPEND:
  case PROTOCOL_BINARY_CMD_APPENDQ:
  case PROTOCOL_BINARY_CMD_PREPEND:
  case PROTOCOL_BINARY_CMD_PREPENDQ:
  case PROTOCOL_BINARY_CMD_STAT:
  case PROTOCOL_BINARY_CMD_UNOBSERVE:
    /* Must not have extras */
    if (extlen) {
      illegal = TRUE;
    }
    break;

  case PROTOCOL_BINARY_CMD_OBSERVE:
    if (extlen) {
      proto_tree_add_item (extras_tree, hf_extras_expiration, tvb, offset, 4, ENC_BIG_ENDIAN);
      offset += 4;
    } else if (request) {
      /* Request must have extras */
      missing = TRUE;
    }
    break;

  case PROTOCOL_BINARY_CMD_TAP_CONNECT:
    flags = tvb_get_ntohl (tvb, offset);
    first_flag = TRUE;
    for (ii = 0; ii < 8; ii++) {
      bpos = 1 << ii;
      if (flags & bpos) {
        if (first_flag) {
          ep_strbuf_truncate(flags_strbuf, 0);
        }
        ep_strbuf_append_printf(flags_strbuf, "%s%s",
                                first_flag ? "" : ", ",
                                tap_connect_flags[ii]);
        first_flag = FALSE;
      }
    }
    tf = proto_tree_add_uint_format(extras_tree, hf_extras_flags, tvb, offset, 4,
                                    flags, "Flags: 0x%04x (%s)", flags, flags_strbuf->str);
    field_tree = proto_item_add_subtree(tf, ett_extras_flags);
    proto_tree_add_boolean(field_tree, hf_extras_flags_backfill, tvb, offset, 1, flags);
    proto_tree_add_boolean(field_tree, hf_extras_flags_dump, tvb, offset, 1, flags);
    proto_tree_add_boolean(field_tree, hf_extras_flags_list_vbuckets, tvb, offset, 1, flags);
    proto_tree_add_boolean(field_tree, hf_extras_flags_takeover_vbuckets, tvb, offset, 1, flags);
    proto_tree_add_boolean(field_tree, hf_extras_flags_support_ack, tvb, offset, 1, flags);
    proto_tree_add_boolean(field_tree, hf_extras_flags_request_keys_only, tvb, offset, 1, flags);
    proto_tree_add_boolean(field_tree, hf_extras_flags_checkpoint, tvb, offset, 1, flags);
    offset += 4;
    break;

  case PROTOCOL_BINARY_CMD_TAP_MUTATION:
    break;

  case PROTOCOL_BINARY_CMD_TAP_DELETE:
    break;

  case PROTOCOL_BINARY_CMD_TAP_FLUSH:
    break;

  case PROTOCOL_BINARY_CMD_TAP_OPAQUE:
    break;

  case PROTOCOL_BINARY_CMD_TAP_VBUCKET_SET:
    break;

  case PROTOCOL_BINARY_CMD_TAP_CHECKPOINT_START:
    break;

  case PROTOCOL_BINARY_CMD_TAP_CHECKPOINT_END:
    break;

  default:
    if (extlen) {
      /* Decode as unknown extras */
      proto_tree_add_item (extras_tree, hf_extras_unknown, tvb, offset, extlen, ENC_NA);
      offset += extlen;
    }
    break;
  }

  if (illegal) {
    ti = proto_tree_add_item (extras_tree, hf_extras_unknown, tvb, offset, extlen, ENC_NA);
    expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "%s %s shall not have Extras",
                            val_to_str (opcode, opcode_vals, "Opcode 0x%x"),
                            request ? "Request" : "Response");
    offset += extlen;
  } else if (missing) {
    ti = proto_tree_add_item (tree, hf_extras_missing, tvb, offset, 0, ENC_NA);
    expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "%s %s must have Extras",
                            val_to_str (opcode, opcode_vals, "Opcode 0x%x"),
                            request ? "Request" : "Response");
  }

  if ((offset - save_offset) != extlen) {
    expert_add_info_format (pinfo, extras_item, PI_UNDECODED, PI_WARN,
                            "Illegal Extras length, should be %d", offset - save_offset);
  }
}

static void
dissect_key (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
             gint offset, int keylen, guint8 opcode, gboolean request)
{
  proto_item *ti = NULL;
  gboolean    illegal = FALSE;  /* Set when key shall not be present */
  gboolean    missing = FALSE;  /* Set when key is missing */

  if (keylen) {
    ti = proto_tree_add_item (tree, hf_key, tvb, offset, keylen, ENC_ASCII|ENC_NA);
    offset += keylen;
  }

  /* Sanity check */
  if (keylen) {
    if ((opcode == PROTOCOL_BINARY_CMD_QUIT) || (opcode == PROTOCOL_BINARY_CMD_QUITQ) || (opcode == PROTOCOL_BINARY_CMD_NOOP) || (opcode == PROTOCOL_BINARY_CMD_VERSION)) {
      /* Request and Response must not have key */
      illegal = TRUE;
    }
    if ((opcode == PROTOCOL_BINARY_CMD_SET) || (opcode == PROTOCOL_BINARY_CMD_ADD) || (opcode == PROTOCOL_BINARY_CMD_REPLACE) || (opcode == PROTOCOL_BINARY_CMD_DELETE) ||
        (opcode == PROTOCOL_BINARY_CMD_SETQ) || (opcode == PROTOCOL_BINARY_CMD_ADDQ) || (opcode == PROTOCOL_BINARY_CMD_REPLACEQ) || (opcode == PROTOCOL_BINARY_CMD_DELETEQ) ||
        (opcode == PROTOCOL_BINARY_CMD_FLUSH) || (opcode == PROTOCOL_BINARY_CMD_APPEND) || (opcode == PROTOCOL_BINARY_CMD_PREPEND) ||
        (opcode == PROTOCOL_BINARY_CMD_FLUSHQ) || (opcode == PROTOCOL_BINARY_CMD_APPENDQ) || (opcode == PROTOCOL_BINARY_CMD_PREPENDQ))
    {
      /* Response must not have a key */
      if (!request) {
        illegal = TRUE;
      }
    }
  } else {
    if ((opcode == PROTOCOL_BINARY_CMD_GET) || (opcode == PROTOCOL_BINARY_CMD_GETQ) || (opcode == PROTOCOL_BINARY_CMD_GETK) || (opcode == PROTOCOL_BINARY_CMD_GETKQ) ||
        (opcode == PROTOCOL_BINARY_CMD_SET) || (opcode == PROTOCOL_BINARY_CMD_ADD) || (opcode == PROTOCOL_BINARY_CMD_REPLACE) || (opcode == PROTOCOL_BINARY_CMD_DELETE) ||
        (opcode == PROTOCOL_BINARY_CMD_SETQ) || (opcode == PROTOCOL_BINARY_CMD_ADDQ) || (opcode == PROTOCOL_BINARY_CMD_REPLACEQ) || (opcode == PROTOCOL_BINARY_CMD_DELETEQ) ||
        (opcode == PROTOCOL_BINARY_CMD_INCREMENT) || (opcode == PROTOCOL_BINARY_CMD_DECREMENT) || (opcode == PROTOCOL_BINARY_CMD_INCREMENTQ) || (opcode == PROTOCOL_BINARY_CMD_DECREMENTQ))
    {
      /* Request must have key */
      if (request) {
        missing = TRUE;
      }
    }
  }

  if (illegal) {
    expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "%s %s shall not have Key",
                            val_to_str (opcode, opcode_vals, "Opcode 0x%x"),
                            request ? "Request" : "Response");
  } else if (missing) {
    ti = proto_tree_add_item (tree, hf_key_missing, tvb, offset, 0, ENC_NA);
    expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "%s %s must have Key",
                            val_to_str (opcode, opcode_vals, "Opcode 0x%x"),
                            request ? "Request" : "Response");
  }
}

static void
dissect_value (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               gint offset, guint32 value_len, guint8 opcode, gboolean request)
{
  proto_item *ti = NULL;
  gboolean    illegal = FALSE;  /* Set when value shall not be present */
  gboolean    missing = FALSE;  /* Set when value is missing */

  if (value_len > 0) {
    if (!request && ((opcode == PROTOCOL_BINARY_CMD_INCREMENT) || (opcode == PROTOCOL_BINARY_CMD_DECREMENT))) {
      ti = proto_tree_add_item (tree, hf_uint64_response, tvb, offset, 8, ENC_BIG_ENDIAN);
      if (value_len != 8) {
        expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "Illegal Value length, should be 8");
      }
    } else {
      ti = proto_tree_add_item (tree, hf_value, tvb, offset, value_len, ENC_ASCII|ENC_NA);
    }
    offset += value_len;
  }

  /* Sanity check */
  if (value_len) {
    if ((opcode == PROTOCOL_BINARY_CMD_GET) || (opcode == PROTOCOL_BINARY_CMD_GETQ) || (opcode == PROTOCOL_BINARY_CMD_GETK) || (opcode == PROTOCOL_BINARY_CMD_GETKQ) ||
        (opcode == PROTOCOL_BINARY_CMD_INCREMENT) || (opcode == PROTOCOL_BINARY_CMD_DECREMENT) || (opcode == PROTOCOL_BINARY_CMD_VERSION) ||
        (opcode == PROTOCOL_BINARY_CMD_INCREMENTQ) || (opcode == PROTOCOL_BINARY_CMD_DECREMENTQ))
    {
      /* Request must not have value */
      if (request) {
        illegal = TRUE;
      }
    }
    if ((opcode == PROTOCOL_BINARY_CMD_DELETE) ||  (opcode == PROTOCOL_BINARY_CMD_QUIT) || (opcode == PROTOCOL_BINARY_CMD_FLUSH) || (opcode == PROTOCOL_BINARY_CMD_NOOP) ||
        (opcode == PROTOCOL_BINARY_CMD_DELETEQ) ||  (opcode == PROTOCOL_BINARY_CMD_QUITQ) || (opcode == PROTOCOL_BINARY_CMD_FLUSHQ))
    {
      /* Request and Response must not have value */
      illegal = TRUE;
    }
    if ((opcode == PROTOCOL_BINARY_CMD_SET) || (opcode == PROTOCOL_BINARY_CMD_ADD) || (opcode == PROTOCOL_BINARY_CMD_REPLACE) ||
        (opcode == PROTOCOL_BINARY_CMD_SETQ) || (opcode == PROTOCOL_BINARY_CMD_ADDQ) || (opcode == PROTOCOL_BINARY_CMD_REPLACEQ) ||
        (opcode == PROTOCOL_BINARY_CMD_APPEND) || (opcode == PROTOCOL_BINARY_CMD_PREPEND) || (opcode == PROTOCOL_BINARY_CMD_APPENDQ) || (opcode == PROTOCOL_BINARY_CMD_PREPENDQ))
    {
      /* Response must not have value */
      if (!request) {
        illegal = TRUE;
      }
    }
  } else {
    if ((opcode == PROTOCOL_BINARY_CMD_SET) || (opcode == PROTOCOL_BINARY_CMD_ADD) || (opcode == PROTOCOL_BINARY_CMD_REPLACE) ||
        (opcode == PROTOCOL_BINARY_CMD_SETQ) || (opcode == PROTOCOL_BINARY_CMD_ADDQ) || (opcode == PROTOCOL_BINARY_CMD_REPLACEQ) ||
        (opcode == PROTOCOL_BINARY_CMD_APPEND) || (opcode == PROTOCOL_BINARY_CMD_PREPEND) || (opcode == PROTOCOL_BINARY_CMD_APPENDQ) || (opcode == PROTOCOL_BINARY_CMD_PREPENDQ))
    {
      /* Request must have a value */
      if (request) {
        missing = TRUE;
      }
    }
  }

  if (illegal) {
    expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "%s %s shall not have Value",
                            val_to_str (opcode, opcode_vals, "Opcode 0x%x"),
                            request ? "Request" : "Response");
  } else if (missing) {
    ti = proto_tree_add_item (tree, hf_value_missing, tvb, offset, 0, ENC_NA);
    expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "%s %s must have Value",
                            val_to_str (opcode, opcode_vals, "Opcode 0x%x"),
                            request ? "Request" : "Response");
  }
}

static void
dissect_couchbase (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *couchbase_tree;
  proto_item *couchbase_item, *ti;
  gint        offset = 0;
  guint8      magic, opcode, extlen;
  guint16     keylen, status = 0, vbucket;
  guint32     bodylen, value_len;
  gboolean    request;

  col_set_str (pinfo->cinfo, COL_PROTOCOL, PSNAME);
  col_clear (pinfo->cinfo, COL_INFO);

  couchbase_item = proto_tree_add_item (tree, proto_couchbase, tvb, offset, -1, ENC_NA);
  couchbase_tree = proto_item_add_subtree (couchbase_item, ett_couchbase);

  magic = tvb_get_guint8 (tvb, offset);
  ti = proto_tree_add_item (couchbase_tree, hf_magic, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  if (match_strval (magic, magic_vals) == NULL) {
    expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "Unknown magic byte: 0x%x", magic);
  }

  opcode = tvb_get_guint8 (tvb, offset);
  ti = proto_tree_add_item (couchbase_tree, hf_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  if (match_strval (opcode, opcode_vals) == NULL) {
    expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "Unknown opcode: 0x%x", opcode);
  }

  proto_item_append_text (couchbase_item, ", %s %s, Opcode: 0x%x",
                          val_to_str (opcode, opcode_vals, "Unknown opcode"),
                          val_to_str (magic, magic_vals, "Unknown magic (0x%x)"),
                          opcode);

  col_append_fstr (pinfo->cinfo, COL_INFO, "%s %s, Opcode: 0x%x",
                   val_to_str (opcode, opcode_vals, "Unknown opcode (0x%x)"),
                   val_to_str (magic, magic_vals, "Unknown magic (0x%x)"),
                   opcode);

  keylen = tvb_get_ntohs (tvb, offset);
  proto_tree_add_item (couchbase_tree, hf_keylength, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  extlen = tvb_get_guint8 (tvb, offset);
  proto_tree_add_item (couchbase_tree, hf_extlength, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item (couchbase_tree, hf_datatype, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  if (magic & 0x01) {    /* We suppose this is a response, even when unknown magic byte */
    request = FALSE;
    status = tvb_get_ntohs (tvb, offset);
    ti = proto_tree_add_item (couchbase_tree, hf_status, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (status != 0) {
      expert_add_info_format (pinfo, ti, PI_RESPONSE_CODE, PI_NOTE, "%s: %s",
                              val_to_str (opcode, opcode_vals, "Unknown opcode (0x%x)"),
                              val_to_str (status, status_vals, "Status: 0x%x"));
    }
  } else {
    request = TRUE;
    vbucket = tvb_get_ntohs (tvb, offset);
    proto_tree_add_item (couchbase_tree, hf_vbucket, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_item_append_text (couchbase_item, ", VBucket: 0x%x", vbucket);
    col_append_fstr (pinfo->cinfo, COL_INFO, ", VBucket: 0x%x", vbucket);
  }
  offset += 2;

  bodylen = tvb_get_ntohl (tvb, offset);
  value_len = bodylen - extlen - keylen;
  ti = proto_tree_add_uint (couchbase_tree, hf_value_length, tvb, offset, 0, value_len);
  PROTO_ITEM_SET_GENERATED (ti);

  proto_tree_add_item (couchbase_tree, hf_total_bodylength, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  /* little endian (network) encoding because the client shouldn't apply any
   * conversions */
  proto_tree_add_item (couchbase_tree, hf_opaque, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item (couchbase_tree, hf_cas, tvb, offset, 8, ENC_BIG_ENDIAN);
  offset += 8;

  if (status == 0) {
    dissect_extras (tvb, pinfo, couchbase_tree, offset, extlen, opcode, request);
    offset += extlen;

    dissect_key (tvb, pinfo, couchbase_tree, offset, keylen, opcode, request);
    offset += keylen;

    dissect_value (tvb, pinfo, couchbase_tree, offset, value_len, opcode, request);
    offset += value_len;
  } else if (bodylen) {
    proto_tree_add_item (couchbase_tree, hf_value, tvb, offset, bodylen, ENC_ASCII|ENC_NA);
    offset += bodylen;

    col_append_fstr (pinfo->cinfo, COL_INFO, ", %s",
                     val_to_str (status, status_vals, "Unknown status: 0x%x"));
  } else {
    ti = proto_tree_add_item (couchbase_tree, hf_value_missing, tvb, offset, 0, ENC_NA);
    expert_add_info_format (pinfo, ti, PI_UNDECODED, PI_WARN, "%s with status %s (0x%x) must have Value",
                            val_to_str (opcode, opcode_vals, "Opcode 0x%x"),
                            val_to_str (status, status_vals, "Unknown"), status);
  }
}

/* Dissect tcp packets based on the type of protocol (text/binary) */
static void
dissect_couchbase_tcp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  gint        offset = 0;
  guint8      magic;

  magic = tvb_get_guint8 (tvb, offset);

  if (match_strval (magic, magic_vals) != NULL) {
    tcp_dissect_pdus (tvb, pinfo, tree, couchbase_desegment_body, 12,
                      get_memcache_pdu_len, dissect_couchbase);
  }
}


static void couchbase_prefs(void)
{
  gchar **ports;
  guint32 port;

  if (couchbase_tcp_ports) {
    ports = g_strsplit_set(couchbase_tcp_ports, ", ", 0);
    while (*ports) {
      port = (guint32)g_ascii_strtoull(*ports, NULL, 10);
      if (port > 0) {
        dissector_delete_uint ("tcp.port", port, NULL);
      }
      ++ports;
    }
  }
  couchbase_tcp_ports = g_strdup(couchbase_tcp_ports_pref);
  ports = g_strsplit_set(couchbase_tcp_ports, ", ", 0);
  while (*ports) {
    port = (guint32)g_ascii_strtoull(*ports, NULL, 10);
    if (port > 0) {
      dissector_add_uint ("tcp.port", port, couchbase_tcp_handle);
    }
    ++ports;
  }
}


/* Registration functions; register couchbase protocol,
 * its configuration options and also register the tcp dissectors.
 */
void
proto_register_couchbase (void)
{
  static hf_register_info hf[] = {
    { &hf_magic,
      { "Magic", "couchbase.magic",
        FT_UINT8, BASE_DEC, VALS (magic_vals), 0x0,
        "Magic number", HFILL } },

    { &hf_opcode,
      { "Opcode", "couchbase.opcode",
        FT_UINT8, BASE_DEC, VALS (opcode_vals), 0x0,
        "Command code", HFILL } },

    { &hf_extlength,
      { "Extras length", "couchbase.extras.length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length in bytes of the command extras", HFILL } },

    { &hf_keylength,
      { "Key Length", "couchbase.key.length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Length in bytes of the text key that follows the command extras", HFILL } },

    { &hf_value_length,
      { "Value length", "couchbase.value.length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Length in bytes of the value that follows the key", HFILL } },

    { &hf_datatype,
      { "Data type", "couchbase.datatype",
        FT_UINT8, BASE_DEC, VALS (datatype_vals), 0x0,
        NULL, HFILL } },

    { &hf_vbucket,
      { "VBucket", "couchbase.vbucket",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "VBucket ID", HFILL } },

    { &hf_status,
      { "Status", "couchbase.status",
        FT_UINT16, BASE_DEC, VALS (status_vals), 0x0,
        "Status of the response", HFILL } },

    { &hf_total_bodylength,
      { "Total body length", "couchbase.total_bodylength",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Length in bytes of extra + key + value", HFILL } },

    { &hf_opaque,
      { "Opaque", "couchbase.opaque",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

    { &hf_cas,
      { "CAS", "couchbase.cas",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "Data version check", HFILL } },

    { &hf_extras,
      { "Extras", "couchbase.extras",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },

    { &hf_extras_flags,
      { "Flags", "couchbase.extras.flags",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL } },

    { &hf_extras_flags_backfill,
      { "Backfill age", "couchbase.extras.flags.backfill",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x01,
        NULL, HFILL } },

    { &hf_extras_flags_dump,
      { "Dump", "couchbase.extras.flags.dump",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x02,
        NULL, HFILL } },

    { &hf_extras_flags_list_vbuckets,
      { "List VBuckets", "couchbase.extras.flags.list_vbuckets",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x04,
        NULL, HFILL } },

    { &hf_extras_flags_takeover_vbuckets,
      { "Takeover VBuckets", "couchbase.extras.flags.takeover_vbuckets",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x08,
        NULL, HFILL } },

    { &hf_extras_flags_support_ack,
      { "Support ack", "couchbase.extras.flags.support_ack",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x10,
        NULL, HFILL } },

    { &hf_extras_flags_request_keys_only,
      { "Request keys only", "couchbase.extras.flags.request_keys_only",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x20,
        NULL, HFILL } },

    { &hf_extras_flags_checkpoint,
      { "Checkpoint", "couchbase.extras.flags.checkpoint",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x40,
        NULL, HFILL } },

    { &hf_extras_flags_registered_client,
      { "Registered client", "couchbase.extras.flags.registered_client",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x80,
        NULL, HFILL } },

    { &hf_extras_expiration,
      { "Expiration", "couchbase.extras.expiration",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

    { &hf_extras_delta,
      { "Amount to add", "couchbase.extras.delta",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

    { &hf_extras_initial,
      { "Initial value", "couchbase.extras.initial",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },

    { &hf_extras_unknown,
      { "Unknown", "couchbase.extras.unknown",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Unknown Extras", HFILL } },

    { &hf_extras_missing,
      { "Extras missing", "couchbase.extras.missing",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Extras is mandatory for this command", HFILL } },

    { &hf_key,
      { "Key", "couchbase.key",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },

    { &hf_key_missing,
      { "Key missing", "couchbase.key.missing",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Key is mandatory for this command", HFILL } },

    { &hf_value,
      { "Value", "couchbase.value",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },

    { &hf_value_missing,
      { "Value missing", "couchbase.value.missing",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Value is mandatory for this command", HFILL } },

    { &hf_uint64_response,
      { "Response", "couchbase.extras.response",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },
  };

  static gint *ett[] = {
    &ett_couchbase,
    &ett_extras,
    &ett_extras_flags
  };

  module_t *couchbase_module;

  proto_couchbase = proto_register_protocol (PNAME, PSNAME, PFNAME);
  register_dissector ("couchbase.tcp", dissect_couchbase_tcp, proto_couchbase);

  proto_register_field_array (proto_couchbase, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  /* Register our configuration options */
  couchbase_module = prefs_register_protocol (proto_couchbase, couchbase_prefs);

  prefs_register_bool_preference (couchbase_module, "desegment_headers",
                                 "Reassemble Couchbase headers spanning multiple TCP segments",
                                 "Whether the Couchbase dissector should reassemble headers "
                                 "of a request spanning multiple TCP segments. "
                                 "To use this option, you must also enable "
                                 "\"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                 &couchbase_desegment_headers);

  prefs_register_bool_preference (couchbase_module, "desegment_pdus",
                                  "Reassemble PDUs spanning multiple TCP segments",
                                  "Whether the memcache dissector should reassemble PDUs"
                                  " spanning multiple TCP segments."
                                  " To use this option, you must also enable \"Allow subdissectors"
                                  " to reassemble TCP streams\" in the TCP protocol settings.",
                                  &couchbase_desegment_body);


  couchbase_tcp_ports_pref = NULL;
  couchbase_tcp_ports = NULL;
  prefs_register_string_preference (couchbase_module, "tcp.port", "Couchbase TCP Port",
                                    "Couchbase TCP ports", &couchbase_tcp_ports_pref);
}

/* Register the tcp couchbase dissector. */
void
proto_reg_handoff_couchbase (void)
{
  couchbase_tcp_handle = find_dissector ("couchbase.tcp");
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
