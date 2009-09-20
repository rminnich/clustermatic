/*------------------------------------------------------------ -*- C -*-
 * sexp.h:
 * Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 * This program is part of Clustermatic tools
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
 *  $Id: sexp.h,v 1.1 2004/11/03 17:49:02 mkdist Exp $
 *--------------------------------------------------------------------*/
#ifndef _SEXP_H
#define _SEXP_H

//#define MAX_SEXPR_ATOM_SIZE    1024

typedef enum { SEXP_VALUE, SEXP_LIST } sexp_elt_t;
struct sexp_t {
    sexp_elt_t ty;
    struct sexp_t *list;
    struct sexp_t *next;
    char  val[0];
    //char  val[MAX_SEXPR_ATOM_SIZE];
};
typedef struct sexp_t sexpr_t;
typedef struct sexp_t sexp_t;

#define sexp_is_value(sx) ((sx)->ty == SEXP_VALUE)
#define sexp_is_list(sx)  ((sx)->ty == SEXP_LIST)

struct sexp_parser_state_t;

#ifdef __cplusplus
extern "C" {
#endif
extern void sexp_free(struct sexp_t *);

extern struct sexp_parser_state_t * sexp_parser_new(void);
extern void sexp_parser_reset(struct sexp_parser_state_t *);
extern void sexp_parser_destroy(struct sexp_parser_state_t *s);
extern void sexp_parser_limit(struct sexp_parser_state_t *s, long bytes);

extern int  sexp_parser_parse(const char *str_, int len,
			      struct sexp_t **sx_out,
			      struct sexp_parser_state_t *s);

extern struct sexp_t *sexp_find_list(struct sexp_t *sx, ...);
/* XXX This really requires stdio... gross */

/*--- Utility functions for building sexps -------------------------*/
extern struct sexp_t *sexp_create(const char *val);
extern struct sexp_t *sexp_create_list(const char *str1, ...);
extern struct sexp_t *sexp_create_list_v(char **strs);
extern struct sexp_t *sexp_concat(struct sexp_t *sx1, struct sexp_t *sx2);
extern void           sexp_append_sx(struct sexp_t *sx, struct sexp_t *sx2);
extern struct sexp_t *sexp_append_atom(struct sexp_t *sx, const char *val);
extern struct sexp_t *sexp_copy(struct sexp_t *sx);
extern struct sexp_t *sexp_copy_list(struct sexp_t *sx);
extern struct sexp_t *sexp_nth(struct sexp_t *sx, int n);
extern int            sexp_length(struct sexp_t *sx);

/* printing utilities */
extern int   sexp_snprint(char *str_, int len, struct sexp_t *sx);
extern int   sexp_sprint(char *str_, struct sexp_t *sx);
extern int   sexp_strlen(struct sexp_t *sx);
extern void  sexp_print(FILE *f, struct sexp_t *sx);
extern char *sexp_string(struct sexp_t *sx);
#ifdef __cplusplus
}
#endif
#endif

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
