/* capture_prefs.h
 * Definitions for capture preferences window
 *
 * $Id: capture_prefs.h,v 1.2 2002/08/28 21:03:46 jmayer Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef __CAPTURE_PREFS_H__
#define __CAPTURE_PREFS_H__

GtkWidget *capture_prefs_show(void);
void capture_prefs_fetch(GtkWidget *w);
void capture_prefs_apply(GtkWidget *w);
void capture_prefs_destroy(GtkWidget *w);

#endif
