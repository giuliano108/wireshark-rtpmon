/* packet-ospf.c
 * Routines for OSPF packet disassembly
 * (c) Copyright Hannes R. Boehm <hannes@boehm.org>
 *
 * $Id: packet-ospf.c,v 1.8 1998/11/17 04:29:02 gerald Exp $
 *
 * At this time, this module is able to analyze OSPF
 * packets as specified in RFC2328. MOSPF (RFC1584) and other
 * OSPF Extensions which introduce new Packet types
 * (e.g the External Atributes LSA) are not supported.
 *
 * TOS - support is not fully implemented
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

#include <gtk/gtk.h>

#include <stdio.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include "ethereal.h"
#include "packet.h"
#include "packet-ospf.h"


void 
dissect_ospf(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
    e_ospfhdr ospfh;

    GtkWidget *ospf_tree = NULL, *ti; 
    GtkWidget *ospf_header_tree;
    char auth_data[9]="";
    char *packet_type;
    static value_string pt_vals[] = { {OSPF_HELLO,   "Hello Packet"   },
                                      {OSPF_DB_DESC, "DB Descr."      },
                                      {OSPF_LS_REQ,  "LS Request"     },
                                      {OSPF_LS_UPD,  "LS Update"      },
                                      {OSPF_LS_ACK,  "LS Acknowledge" },
                                      {0,             NULL            } };

    memcpy(&ospfh, &pd[offset], sizeof(e_ospfhdr));

    packet_type = match_strval(ospfh.packet_type, pt_vals);
    if (check_col(fd, COL_PROTOCOL))
        col_add_str(fd, COL_PROTOCOL, "OSPF");
    if (check_col(fd, COL_INFO)) {
        if (packet_type != NULL)
            col_add_str(fd, COL_INFO, packet_type); 
        else
            col_add_fstr(fd, COL_INFO, "Unknown (%d)", ospfh.packet_type); 
    }  

    if (tree) {
	ti = add_item_to_tree(GTK_WIDGET(tree), offset, ntohs(ospfh.length), "Open Shortest Path First"); 
	ospf_tree = gtk_tree_new(); 
	add_subtree(ti, ospf_tree, ETT_OSPF);

	ti = add_item_to_tree(GTK_WIDGET(ospf_tree), offset, OSPF_HEADER_LENGTH, "OSPF Header"); 
	ospf_header_tree = gtk_tree_new();
	add_subtree(ti, ospf_header_tree, ETT_OSPF_HDR);

        add_item_to_tree(ospf_header_tree, offset, 1, "OSPF Version: %d", ospfh.version);  
	add_item_to_tree(ospf_header_tree, offset + 1 , 1, "OSPF Packet Type: %d (%s)", 
	                                                   ospfh.packet_type,
							   (packet_type != NULL ?
							     packet_type :
							     "Unknown"));
	add_item_to_tree(ospf_header_tree, offset + 2 , 2, "Packet Legth: %d", 
	                                                   ntohs(ospfh.length));
	add_item_to_tree(ospf_header_tree, offset + 4 , 4, "Source OSPF Router ID: %s", 

	                                                   ip_to_str((guint8 *) &(ospfh.routerid)));
	if (!(ospfh.area)) {
	   add_item_to_tree(ospf_header_tree, offset + 8 , 4, "Area ID: Backbone");
	} else {
	   add_item_to_tree(ospf_header_tree, offset + 8 , 4, "Area ID: %s", ip_to_str((guint8 *) &(ospfh.area)));
	}
	add_item_to_tree(ospf_header_tree, offset + 12 , 2, "Packet Checksum");
	switch( ntohs(ospfh.auth_type) ) {
	    case OSPF_AUTH_NONE:
	         add_item_to_tree(ospf_header_tree, offset + 14 , 2, "Auth Type: none");
	         add_item_to_tree(ospf_header_tree, offset + 16 , 8, "Auth Data (none)");
		 break;
	    case OSPF_AUTH_SIMPLE:
	         add_item_to_tree(ospf_header_tree, offset + 14 , 2, "Auth Type: simple");
                 strncpy(auth_data, (char *) &ospfh.auth_data, 8);
	         add_item_to_tree(ospf_header_tree, offset + 16 , 8, "Auth Data: %s", auth_data);
		 break;
	    case OSPF_AUTH_CRYPT:
	         add_item_to_tree(ospf_header_tree, offset + 14 , 2, "Auth Type: crypt");
	         add_item_to_tree(ospf_header_tree, offset + 16 , 8, "Auth Data (crypt)");
		 break;
            default:
	         add_item_to_tree(ospf_header_tree, offset + 14 , 2, "Auth Type (unknown)");
	         add_item_to_tree(ospf_header_tree, offset + 16 , 8, "Auth Data (unknown)");
	}

    }

    /*  Skip over header */
    offset += OSPF_HEADER_LENGTH;
    switch(ospfh.packet_type){
	case OSPF_HELLO:
	    dissect_ospf_hello(pd, offset, fd, (GtkTree *) ospf_tree); 
	    break;
	case OSPF_DB_DESC:
	    dissect_ospf_db_desc(pd, offset, fd, (GtkTree *) ospf_tree);   
	    break;
	case OSPF_LS_REQ:
	    dissect_ospf_ls_req(pd, offset, fd, (GtkTree *) ospf_tree);   
	    break;
	case OSPF_LS_UPD:
	    dissect_ospf_ls_upd(pd, offset, fd, (GtkTree *) ospf_tree);
	    break;
	case OSPF_LS_ACK:
	    dissect_ospf_ls_ack(pd, offset, fd, (GtkTree *) ospf_tree);
	    break;
	default:
            dissect_data(pd, offset, fd, tree); 
    }
}

void
dissect_ospf_hello(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
    e_ospf_hello ospfhello;
    guint32 *ospfneighbor;
    char options[20]="";
    int options_offset;

    GtkWidget *ospf_hello_tree, *ti; 

    memcpy(&ospfhello, &pd[offset], sizeof(e_ospf_hello));

    if (tree) {
	ti = add_item_to_tree(GTK_WIDGET(tree), offset, (fd->cap_len - offset) , "OSPF Hello Packet"); 
	ospf_hello_tree = gtk_tree_new(); 
	add_subtree(ti, ospf_hello_tree, ETT_OSPF_HELLO);


	add_item_to_tree(ospf_hello_tree, offset , 4, "Network Mask: %s",  ip_to_str((guint8 *) &ospfhello.network_mask));
	add_item_to_tree(ospf_hello_tree, offset + 4, 2, "Hello Intervall: %d seconds",  ntohs(ospfhello.hellointervall));

	/* ATTENTION !!! no check for length of options string */
	options_offset=0;
	if(( ospfhello.options & OSPF_OPTIONS_E ) == OSPF_OPTIONS_E){
	    strcpy( (char *)(options + options_offset), "E");
	    options_offset+=1;
	}
	if(( ospfhello.options & OSPF_OPTIONS_MC ) == OSPF_OPTIONS_MC){
	    strcpy((char *) (options + options_offset), "/MC");
	    options_offset+=3;
	}
	if(( ospfhello.options & OSPF_OPTIONS_NP ) == OSPF_OPTIONS_NP){
	    strcpy((char *) (options + options_offset), "/NP");
	    options_offset+=3;
	}
	if(( ospfhello.options & OSPF_OPTIONS_EA ) == OSPF_OPTIONS_EA){
	    strcpy((char *) (options + options_offset) , "/EA");
	    options_offset+=3;
	}
	if(( ospfhello.options & OSPF_OPTIONS_DC ) == OSPF_OPTIONS_DC){
	    strcpy((char *) (options + options_offset) , "/DC");
	    options_offset+=3;
	}

	add_item_to_tree(ospf_hello_tree, offset + 6, 1, "Options: %d (%s)",  ospfhello.options, options);
	add_item_to_tree(ospf_hello_tree, offset + 7, 1, "Router Priority: %d",  ospfhello.priority);
	add_item_to_tree(ospf_hello_tree, offset + 8, 4, "RouterDeadIntervall: %ld seconds",  (long)ntohl(ospfhello.dead_interval));
	add_item_to_tree(ospf_hello_tree, offset + 12, 4, "Designated Router: %s",  ip_to_str((guint8 *) &ospfhello.drouter));
	add_item_to_tree(ospf_hello_tree, offset + 16, 4, "Backup Designated Router: %s",  ip_to_str((guint8 *) &ospfhello.bdrouter));


	offset+=20;
	while(((int)(fd->cap_len - offset)) >= 4){
	    printf("%d", fd->cap_len - offset);
	    ospfneighbor=(guint32 *) &pd[offset];
	    add_item_to_tree(ospf_hello_tree, offset, 4, "Active Neighbor: %s",  ip_to_str((guint8 *) ospfneighbor));
	    offset+=4;
	}
    }
}

void
dissect_ospf_db_desc(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
    e_ospf_dbd ospf_dbd;
    char options[20]="";
    int options_offset;
    char flags[20]="";
    int flags_offset;

    GtkWidget *ospf_db_desc_tree=NULL, *ti; 

    memcpy(&ospf_dbd, &pd[offset], sizeof(e_ospf_dbd));

    if (tree) {
	ti = add_item_to_tree(GTK_WIDGET(tree), offset, (fd->cap_len - offset) , "OSPF DB Description"); 
	ospf_db_desc_tree = gtk_tree_new(); 
	add_subtree(ti, ospf_db_desc_tree, ETT_OSPF_DESC);

	add_item_to_tree(ospf_db_desc_tree, offset, 2, "Interface MTU: %d", ntohs(ospf_dbd.interface_mtu) );


	options_offset=0;
	if(( ospf_dbd.options & OSPF_OPTIONS_E ) == OSPF_OPTIONS_E){
	    strcpy( (char *)(options + options_offset), "_E_");
	    options_offset+=1;
	}
	if(( ospf_dbd.options & OSPF_OPTIONS_MC ) == OSPF_OPTIONS_MC){
	    strcpy((char *) (options + options_offset), "_MC_");
	    options_offset+=3;
	}
	if(( ospf_dbd.options & OSPF_OPTIONS_NP ) == OSPF_OPTIONS_NP){
	    strcpy((char *) (options + options_offset), "_NP_");
	    options_offset+=3;
	}
	if(( ospf_dbd.options & OSPF_OPTIONS_EA ) == OSPF_OPTIONS_EA){
	    strcpy((char *) (options + options_offset) , "_EA_");
	    options_offset+=3;
	}
	if(( ospf_dbd.options & OSPF_OPTIONS_DC ) == OSPF_OPTIONS_DC){
	    strcpy((char *) (options + options_offset) , "_DC_");
	    options_offset+=3;
	}

	add_item_to_tree(ospf_db_desc_tree, offset + 2 , 1, "Options: %d (%s)", ospf_dbd.options, options );


	flags_offset=0;
	if(( ospf_dbd.flags & OSPF_DBD_FLAG_MS ) == OSPF_DBD_FLAG_MS){
	    strcpy( (char *)(flags + flags_offset), "_I_");
	    flags_offset+=1;
	}
	if(( ospf_dbd.flags & OSPF_DBD_FLAG_M ) == OSPF_DBD_FLAG_M){
	    strcpy((char *) (flags + flags_offset), "_M_");
	    flags_offset+=3;
	}
	if(( ospf_dbd.flags & OSPF_DBD_FLAG_I ) == OSPF_DBD_FLAG_I){
	    strcpy((char *) (flags + flags_offset), "_I_");
	    flags_offset+=3;
	}

	add_item_to_tree(ospf_db_desc_tree, offset + 3 , 1, "Flags: %d (%s)", ospf_dbd.flags, flags );
	add_item_to_tree(ospf_db_desc_tree, offset + 4 , 4, "DD Sequence: %ld", (long)ntohl(ospf_dbd.dd_sequence) );
    }
    /* LS Headers will be processed here */
    /* skip to the end of DB-Desc header */
    offset+=8;
    while( ((int) (fd->cap_len - offset)) >= OSPF_LSA_HEADER_LENGTH ) {
       dissect_ospf_lsa(pd, offset, fd, (GtkTree *) tree, FALSE);
       offset+=OSPF_LSA_HEADER_LENGTH;
    }
}

void
dissect_ospf_ls_req(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
    e_ospf_ls_req ospf_lsr;

    GtkWidget *ospf_lsr_tree, *ti; 


    /* zero or more LS requests may be within a LS Request */
    /* we place every request for a LSA in a single subtree */
    if (tree) {
	while( ((int) ( fd->cap_len - offset)) >= OSPF_LS_REQ_LENGTH ){
             memcpy(&ospf_lsr, &pd[offset], sizeof(e_ospf_ls_req));
	     ti = add_item_to_tree(GTK_WIDGET(tree), offset, OSPF_LS_REQ_LENGTH, "Link State Request"); 
	     ospf_lsr_tree = gtk_tree_new(); 
	     add_subtree(ti, ospf_lsr_tree, ETT_OSPF_LSR);

	     switch( ntohl( ospf_lsr.ls_type ) ){
		 case OSPF_LSTYPE_ROUTER:
	             add_item_to_tree(ospf_lsr_tree, offset, 4, "LS Type: Router-LSA (%ld)", 
	                               (long)ntohl( ospf_lsr.ls_type ) );
		     break;
		 case OSPF_LSTYPE_NETWORK:
	             add_item_to_tree(ospf_lsr_tree, offset, 4, "LS Type: Network-LSA (%ld)", 
	                               (long)ntohl( ospf_lsr.ls_type ) );
		     break;
		 case OSPF_LSTYPE_SUMMERY:
	             add_item_to_tree(ospf_lsr_tree, offset, 4, "LS Type: Summary-LSA (IP network) (%ld)", 
	                               (long)ntohl( ospf_lsr.ls_type ) );
		     break;
		 case OSPF_LSTYPE_ASBR:
	             add_item_to_tree(ospf_lsr_tree, offset, 4, "LS Type: Summary-LSA (ASBR) (%ld)", 
	                               (long)ntohl( ospf_lsr.ls_type ) );
		     break;
		 case OSPF_LSTYPE_ASEXT:
	             add_item_to_tree(ospf_lsr_tree, offset, 4, "LS Type: AS-External-LSA (ASBR) (%ld)", 
	                               (long)ntohl( ospf_lsr.ls_type ) );
		     break;
		 default:
	             add_item_to_tree(ospf_lsr_tree, offset, 4, "LS Type: %ld (unknown)", 
	                               (long)ntohl( ospf_lsr.ls_type ) );
	     }

             add_item_to_tree(ospf_lsr_tree, offset + 4, 4, "Link State ID : %s", 
	                                 ip_to_str((guint8 *) &(ospf_lsr.ls_id)));
             add_item_to_tree(ospf_lsr_tree, offset + 8, 4, "Advertising Router : %s", 
	                                 ip_to_str((guint8 *) &(ospf_lsr.adv_router)));

	     offset+=12;
	}
    }
}
void
dissect_ospf_ls_upd(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {
    e_ospf_lsa_upd_hdr upd_hdr;
    guint32 lsa_counter; 

    GtkWidget *ospf_lsa_upd_tree=NULL, *ti; 

    memcpy(&upd_hdr, &pd[offset], sizeof(e_ospf_lsa_upd_hdr));

    if (tree) {
	ti = add_item_to_tree(GTK_WIDGET(tree), offset, (fd->cap_len - offset) , "LS Update Packet"); 
	ospf_lsa_upd_tree = gtk_tree_new(); 
	add_subtree(ti, ospf_lsa_upd_tree, ETT_OSPF_LSA_UPD);

	add_item_to_tree(ospf_lsa_upd_tree, offset, 4, "Nr oF LSAs: %ld", (long)ntohl(upd_hdr.lsa_nr) );
    }
    /* skip to the beginning of the first LSA */
    offset+=4; /* the LS Upd PAcket contains only a 32 bit #LSAs field */
    
    lsa_counter = 0;
    while(lsa_counter < ntohl(upd_hdr.lsa_nr)){
        offset+=dissect_ospf_lsa(pd, offset, fd, (GtkTree *) ospf_lsa_upd_tree, TRUE);
        lsa_counter += 1;
    }
}

void
dissect_ospf_ls_ack(const u_char *pd, int offset, frame_data *fd, GtkTree *tree) {

    /* the body of a LS Ack packet simply contains zero or more LSA Headers */
    while( ((int)(fd->cap_len - offset)) >= OSPF_LSA_HEADER_LENGTH ) {
       dissect_ospf_lsa(pd, offset, fd, (GtkTree *) tree, FALSE);
       offset+=OSPF_LSA_HEADER_LENGTH;
    }

}

int
dissect_ospf_lsa(const u_char *pd, int offset, frame_data *fd, GtkTree *tree, int disassemble_body) {
    e_ospf_lsa_hdr 	 lsa_hdr;
    char		*lsa_type;

    /* data strutures for the router LSA */
    e_ospf_router_lsa 		router_lsa;
    e_ospf_router_data 		router_data;
    e_ospf_router_metric 	tos_data;
    guint16 			link_counter;
    guint8 			tos_counter;
    char  			*link_type;
    char  			*link_id;

    /* data structures for the network lsa */
    e_ospf_network_lsa 	network_lsa;
    guint32		*attached_router;

    /* data structures for the summary and ASBR LSAs */
    e_ospf_summary_lsa 	summary_lsa;

    /* data structures for the AS-External LSA */
    e_ospf_asexternal_lsa       asext_lsa;
    guint32                   asext_metric;

    GtkWidget *ospf_lsa_tree, *ti; 

    memcpy(&lsa_hdr, &pd[offset], sizeof(e_ospf_lsa_hdr));

             

    switch(lsa_hdr.ls_type) {
        case OSPF_LSTYPE_ROUTER:
	    lsa_type="Router LSA";
            break;
        case OSPF_LSTYPE_NETWORK:
	    lsa_type="Network LSA";
            break;
        case OSPF_LSTYPE_SUMMERY:
	    lsa_type="Summery LSA";
            break;
        case OSPF_LSTYPE_ASBR:
	    lsa_type="ASBR LSA";
            break;
        case OSPF_LSTYPE_ASEXT:
	    lsa_type="AS-external-LSA";
            break;
        default:
	    lsa_type="unknown";
    }

    if (tree) {
	if(disassemble_body){
             ti = add_item_to_tree(GTK_WIDGET(tree), offset, ntohs(lsa_hdr.length), 
	                                              "%s (Type: %d)", lsa_type, lsa_hdr.ls_type); 
        } else {
             ti = add_item_to_tree(GTK_WIDGET(tree), offset, OSPF_LSA_HEADER_LENGTH, "LSA Header"); 
        }
        ospf_lsa_tree = gtk_tree_new(); 
        add_subtree(ti, ospf_lsa_tree, ETT_OSPF_LSA);

	
        add_item_to_tree(ospf_lsa_tree, offset, 2, "LS Age: %d seconds", ntohs(lsa_hdr.ls_age));
        add_item_to_tree(ospf_lsa_tree, offset + 2, 1, "Options: %d ", lsa_hdr.options);
        add_item_to_tree(ospf_lsa_tree, offset + 3, 1, "LSA Type: %d (%s)", lsa_hdr.ls_type, lsa_type);

        add_item_to_tree(ospf_lsa_tree, offset + 4, 4, "Linke State ID: %s ", 
	                                             ip_to_str((guint8 *) &(lsa_hdr.ls_id)));

        add_item_to_tree(ospf_lsa_tree, offset + 8, 4, "Advertising Router: %s ", 
	                                             ip_to_str((guint8 *) &(lsa_hdr.adv_router)));
        add_item_to_tree(ospf_lsa_tree, offset + 12, 4, "LS Sequence Number: 0x%04lx ", 
	                                             (unsigned long)ntohl(lsa_hdr.ls_seq));
        add_item_to_tree(ospf_lsa_tree, offset + 16, 2, "LS Checksum: %d ", ntohs(lsa_hdr.ls_checksum));

        add_item_to_tree(ospf_lsa_tree, offset + 18, 2, "Length: %d ", ntohs(lsa_hdr.length));

	if(!disassemble_body){
           return OSPF_LSA_HEADER_LENGTH;
        }

	/* the LSA body starts afte 20 bytes of LSA Header */
	offset+=20;

        switch(lsa_hdr.ls_type){
            case(OSPF_LSTYPE_ROUTER):
                memcpy(&router_lsa, &pd[offset], sizeof(e_ospf_router_lsa));

		/* again: flags should be secified in detail */
		add_item_to_tree(ospf_lsa_tree, offset, 1, "Flags: 0x%02x ", router_lsa.flags);
		add_item_to_tree(ospf_lsa_tree, offset + 2, 2, "Nr. of Links: %d ", 
		                                                   ntohs(router_lsa.nr_links));
		offset += 4;
		/* router_lsa.nr_links links follow 
		 * maybe we should put each of the links into its own subtree ???
		 */
		for(link_counter = 1 ; link_counter <= ntohs(router_lsa.nr_links); link_counter++){

                    memcpy(&router_data, &pd[offset], sizeof(e_ospf_router_data));
		    /* check the Link Type and ID */
                    switch(router_data.link_type) {
                        case OSPF_LINK_PTP:
                	    link_type="Point-to-point connection to another router";
			    link_id="Neighboring router's Router ID";
                            break;
                        case OSPF_LINK_TRANSIT:
                	    link_type="Connection to a transit network";
			    link_id="IP address of Designated Router";
                            break;
                        case OSPF_LINK_STUB:
                	    link_type="Connection to a stub network";
			    link_id="IP network/subnet number";
                            break;
                        case OSPF_LINK_VIRTUAL:
                	    link_type="Virtual link";
			    link_id="Neighboring router's Router ID";
                            break;
                        default:
	                    link_type="unknown link type";
			    link_id="unknown link id";
                    }

		    add_item_to_tree(ospf_lsa_tree, offset, 4, "%s: %s", link_id,
		                                   ip_to_str((guint8 *) &(router_data.link_id)));

		    /* link_data should be specified in detail (e.g. network mask) (depends on link type)*/
		    add_item_to_tree(ospf_lsa_tree, offset + 4, 4, "Link Data: %s", 
		                                   ip_to_str((guint8 *) &(router_data.link_data)));

		    add_item_to_tree(ospf_lsa_tree, offset + 8, 1, "Link Type: %d - %s", 
		                                              router_data.link_type, link_type);
		    add_item_to_tree(ospf_lsa_tree, offset + 9, 1, "Nr. of TOS metrics: %d", router_data.nr_tos);
		    add_item_to_tree(ospf_lsa_tree, offset + 10, 2, "TOS 0 metric: %d", ntohs( router_data.tos0_metric ));

		    offset += 12;

		    /* router_data.nr_tos metrics may follow each link 
		     * ATTENTION: TOS metrics are not tested (I don't have TOS based routing)
		     * please send me a mail if it is/isn't working
		     */

		    for(tos_counter = 1 ; link_counter <= ntohs(router_data.nr_tos); tos_counter++){
                        memcpy(&tos_data, &pd[offset], sizeof(e_ospf_router_metric));
			add_item_to_tree(ospf_lsa_tree, offset, 1, "TOS: %d, Metric: %d", 
			                        tos_data.tos, ntohs(tos_data.metric));
			offset += 4;
		    }
		}
                break;
            case(OSPF_LSTYPE_NETWORK):
                memcpy(&network_lsa, &pd[offset], sizeof(e_ospf_network_lsa));
		add_item_to_tree(ospf_lsa_tree, offset, 4, "Netmask: %s", 
                                                 ip_to_str((guint8 *) &(network_lsa.network_mask)));
		offset += 4;

		while( ((int) (fd->cap_len - offset)) >= 4){
		    attached_router = (guint32 *) &pd[offset];
		    add_item_to_tree(ospf_lsa_tree, offset, 4, "Attached Router: %s", 
                                                 ip_to_str((guint8 *) attached_router));
		    offset += 4;
		}
                break;
            case(OSPF_LSTYPE_SUMMERY):
                /* Type 3 and 4 LSAs have the same format */
            case(OSPF_LSTYPE_ASBR):
                memcpy(&summary_lsa, &pd[offset], sizeof(e_ospf_summary_lsa));
                add_item_to_tree(ospf_lsa_tree, offset, 4, "Netmask: %s", 
                                                 ip_to_str((guint8 *) &(summary_lsa.network_mask)));
                /* returns only the TOS 0 metric (even if there are more TOS metrics) */
                break;
            case(OSPF_LSTYPE_ASEXT):
                memcpy(&summary_lsa, &pd[offset], sizeof(e_ospf_summary_lsa));
                add_item_to_tree(ospf_lsa_tree, offset, 4, "Netmask: %s", 
                                                  ip_to_str((guint8 *) &(summary_lsa.network_mask)));

                /* asext_lsa = (e_ospf_asexternal_lsa *) &pd[offset + 4]; */
                memcpy(&asext_lsa, &pd[offset + 4], sizeof(asext_lsa));
                if( (asext_lsa.options & 128) == 128 ) { /* check wether or not E bit is set */
                   add_item_to_tree(ospf_lsa_tree, offset, 1, 
                            "External Type: Type 2 (metric is larger than any other link state path)");
                } else {
                   add_item_to_tree(ospf_lsa_tree, offset + 4, 1, 
                            "External Type: Type 1 (metric is specified in the same units as interface cost)");
                }
                /* the metric field of a AS-external LAS is specified in 3 bytes -> not well aligned */
                /* this routine returns only the TOS 0 metric (even if there are more TOS metrics) */
                memcpy(&asext_metric, &pd[offset+4], 4); 
                
                /* erase the leading 8 bits (the dont belong to the metric */
                asext_metric = ntohl(asext_metric) & 0x00ffffff ;

                add_item_to_tree(ospf_lsa_tree, offset + 5,  3,"Metric: %d", asext_metric);
                add_item_to_tree(ospf_lsa_tree, offset + 8,  4,"Forwarding Address: %s", 
                                                 ip_to_str((guint8 *) &(asext_lsa.gateway)));
                add_item_to_tree(ospf_lsa_tree, offset + 12, 4,"External Route Tag: %ld", (long)ntohl(asext_lsa.external_tag)); 
                    
                break;
            default:
               /* unknown LSA type */
	        add_item_to_tree(ospf_lsa_tree, offset, (fd->cap_len - offset), "Unknown LSA Type");
        }
    }
    /* return the length of this LSA */
    return ntohs(lsa_hdr.length);
}
