/*-------------------------------------------------------------------------
 *  xattr.h: *xattr syscalls for C libraries that don't have it.
 *
 *  Copyright (C) 1999-2002 by Erik Hendriks <erik@hendriks.cx>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Library General Public License for more details.
 *
 *  You should have received a copy of the GNU Library General Public
 *  License along with this library; if not, write to the 
 *  Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 *  Boston, MA  02111-1307  USA.
 *
 * $Id: xattr.h,v 1.1 2003/10/28 23:49:28 mkdist Exp $
 *-----------------------------------------------------------------------*/
extern int __bproc_setxattr(const char *path, const char *name,
			    const void *value, int size, int flags);
extern int __bproc_getxattr(const char *path, const char *name,
			    void *value, int size);
/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
