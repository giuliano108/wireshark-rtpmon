/* etypes.h
 * Defines ethernet packet types, similar to tcpdump's ethertype.h
 *
 * $Id: etypes.h,v 1.5 1999/06/11 15:30:37 gram Exp $
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

#ifndef __ETYPES_H__
#define __ETYPES_H__

#ifndef ETHERTYPE_UNK
#define ETHERTYP_UNK 0x0000
#endif

/* Sources:
 * http://www.isi.edu/in-notes/iana/assignments/ethernet-numbers
 * TCP/IP Illustrated, Volume 1
 * RFCs 894, 1042, 826
 * tcpdump's ethertype.h
 * http://www.cavebear.com/CaveBear/Ethernet/
 */

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif

#ifndef ETHERTYPE_IPv6
#define ETHERTYPE_IPv6 0x086dd
#endif

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif

#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP 0x8035
#endif

#ifndef ETHERTYPE_ATALK
#define ETHERTYPE_ATALK 0x809b
#endif

#ifndef ETHERTYPE_AARP
#define ETHERTYPE_AARP 0x80f3
#endif

#ifndef ETHERTYPE_IPX
#define ETHERTYPE_IPX 0x8137
#endif

#ifndef ETHERTYPE_VINES
#define ETHERTYPE_VINES 0xbad
#endif

#ifndef ETHERTYPE_CDP
#define ETHERTYPE_CDP 0x2000	/* Cisco Discovery Protocol */
#endif

#ifndef ETHERTYPE_LOOP
#define ETHERTYPE_LOOP 0x9000 	/* used for layer 2 testing (do i see my own frames on the wire) */
#endif

#ifndef ETHERTYPE_PPPOED
#define ETHERTYPE_PPPOED 0x8863 /* PPPoE Discovery Protocol */
#endif

#ifndef ETHERTYPE_PPPOES
#define ETHERTYPE_PPPOES 0x8864 /* PPPoE Session Protocol */
#endif


#endif /* etypes.h */
