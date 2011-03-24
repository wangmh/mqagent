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
#ifndef _SYS_PEDANTIC_H_
#define _SYS_PEDANTIC_H_

/**
 * a set of macros to make programming C easier 
 */

#ifdef UNUSED_PARAM
#elif defined(__GNUC__)
# define UNUSED_PARAM(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED_PARAM(x) /*@unused@*/ x
#else
# define UNUSED_PARAM(x) x
#endif

#define F_SIZE_T "%"G_GSIZE_FORMAT
#define F_U64 "%"G_GUINT64_FORMAT

#endif
