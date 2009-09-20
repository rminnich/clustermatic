/*------------------------------------------------------------ -*- C -*-
 * cmconf.h: the clustermatic configuration file library
 * Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 * Copyright(C) 2002 University of California.
 *
 * This software has been authored by an employee or employees of the
 * University of California, operator of the Los Alamos National
 * Laboratory under Contract No.  W-7405-ENG-36 with the U.S.
 * Department of Energy.  The U.S. Government has rights to use,
 * reproduce, and distribute this software. If the software is
 * modified to produce derivative works, such modified software should
 * be clearly marked, so as not to confuse it with the version
 * available from LANL.
 *
 * Additionally, this program is free software; you can distribute it
 * and/or modify it under the terms of the GNU General Public License
 * as published by the Free Software foundation; either version 2 of
 * the License, or any later version.  Accordingly, this program is
 * distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANY; without even the implied warranty of MARCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more detail.
 *
 *  $Id: cmconf.h,v 1.1 2003/09/24 20:30:34 mkdist Exp $
 *--------------------------------------------------------------------*/
#ifndef _CMCONF_H_
#define _CMCONF_H_

struct cmconf;
struct cmconf_line;

struct cmconf_option {
    char *tag;
    int minargs;                /* Number of config args */
    int maxargs;                /* Max # of args. */
    int pass;                   /* What pass should this one be active on ? */
    int (*callback)(struct cmconf *, char **args);
};

#ifdef __cplusplus
extern "C" {
#endif

/* Configuration file load / save */
extern struct cmconf * cmconf_read (const char *filename, int keep_open);
extern int             cmconf_write(struct cmconf *conf);
extern void            cmconf_print(FILE *f, struct cmconf *conf);

extern void cmconf_close(struct cmconf *conf);
extern void cmconf_free(struct cmconf *conf);

/* Configuration file processing calls */
extern int cmconf_process_file  (const char *,         struct cmconf_option *);
extern int cmconf_process       (struct cmconf *,      struct cmconf_option *);
extern int cmconf_process_line  (struct cmconf_line *, struct cmconf_option *);
extern int cmconf_process_string(const char *,         struct cmconf_option *);
extern int cmconf_process_args  (struct cmconf *, char **,
				 struct cmconf_option *);
    
/* Configuration file line access */
extern const char *cmconf_get_line(struct cmconf_line *);
extern struct cmconf_line *cmconf_first(struct cmconf *);
extern struct cmconf_line *cmconf_next(struct cmconf *, struct cmconf_line *);

/* Configuration file editing */
extern void cmconf_set_line(struct cmconf_line *, const char *);
extern void cmconf_delete(struct cmconf_line *);
extern void cmconf_insert_before(struct cmconf_line *, const char *);
extern void cmconf_insert_after(struct cmconf_line *, const char *);
extern void cmconf_append(struct cmconf *, const char *);

/* Parser state access */
extern const char *cmconf_file(struct cmconf *conf);
extern int         cmconf_lineno(struct cmconf *conf); /* 1 based lineno */
extern int         cmconf_pass(struct cmconf *conf);
extern struct cmconf_line * cmconf_line(struct cmconf *conf);

#ifdef __cplusplus
}
#endif
#endif
/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
