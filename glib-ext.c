/*
 * glib-ext.c
 *
 *  Created on: 2011-1-5
 *      Author: saint
 */

/*
   Spock Proxy - http://spockproxy.sourceforge.net
   Copyright (C) 2008 Spock.com

   Copyright (C) 2007 MySQL AB

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <glib.h>

#include "glib-ext.h"
#include "sys-pedantic.h"

void g_list_string_free(gpointer data, gpointer UNUSED_PARAM(user_data)) {
	g_string_free((GString*)data, TRUE);
}

void g_hash_table_string_free(gpointer data) {
	g_string_free((GString*)data, TRUE);
}

guint g_hash_table_string_hash(gconstpointer _key) {
	return g_string_hash((const GString*) _key);
}

gboolean g_hash_table_string_equal(gconstpointer _a, gconstpointer _b) {
	return g_string_equal((const GString*) _a, (const GString*) _b);
}

gboolean g_hash_table_true(gpointer UNUSED_PARAM(key), gpointer UNUSED_PARAM(value), gpointer UNUSED_PARAM(u)) {
	return TRUE;
}

GString *g_string_dup(GString *src) {
	GString *dst = g_string_sized_new(src->len);

	g_string_assign(dst, src->str);

	return dst;
}
