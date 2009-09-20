/* nss_bproc.h: convenience prototypes for nss funcs that we export.
 *
 * Written 19^H^H2000 by Daniel Ridge in support of:
 *   Scyld Computing Corporation.
 *
 * The author may be reached as newt@scyld.com or C/O
 *   Scyld Computing Corporation
 *   410 Severn Ave, Suite 210
 *   Annapolis, MD 21403
 *
 * Copyright (C) 2000 Scyld Computing Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
 *
 */

extern enum nss_status _nss_bproc_gethostbyname_r(const char *name, struct hostent *host, char *buf, int buflen, int *errnop, int *h_errnop);
extern enum nss_status _nss_bproc_gethostbyaddr_r(const char *addr, int addrlen, int type, struct hostent *host, char *buffer, size_t buflen, int *errnop, int *h_errnop);
extern enum nss_status _nss_bproc_getpwuid_r(uid_t uid, struct passwd *pwd, char *buffer, size_t buflen, int *errnop);
extern enum nss_status _nss_bproc_getpwname_r(const char *name, struct passwd *pwd, char *buffer, size_t buflen, int *errnop);
