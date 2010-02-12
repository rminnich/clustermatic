/*------------------------------------------------------------ -*- C -*-
 * sexp.c:
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
 *  $Id: sexp.c,v 1.1 2004/11/03 17:49:02 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include "sexp.h"

/* This is as deep as you're allowed to make your sexps */
#define SEXP_PARSER_STACK_SIZE 100

enum sexp_parser_states {
	SE_NONE,
	SE_ATOM,
	SE_ATOM_ESC
};

struct sexp_parser_state_t {
	enum sexp_parser_states state;

	/* Information for current atom */
	char *atom;		/* atom buffer */
	int atom_size;		/* size of atom buffer */
	int val;		/* value index for constructing atoms */
	int incr;		/* atom size increment (for realloc) */

	/* Stack to keep track of current structure */
	struct sexp_t *top;	/* top of sexp to return to user */
	int sp;			/* stack pointer */
	struct sexp_t **stack[SEXP_PARSER_STACK_SIZE];

	/* Resource limiting - max number of bytes to eat */
	long max_bytes;		/* Maximum number of bytes */
	long bytes;		/* Number of bytes currently used */
};

/*
#include "prof.h"
#undef prof1
#undef prof2
*/

#define PUSH(ptr) \
do { \
    if (++sp == SEXP_PARSER_STACK_SIZE) { \
	fprintf(stderr, "sexp_free: sexp stack overflow\n"); \
	abort(); \
    } \
    stack[sp] = (ptr); \
} while(0)

void sexp_free(struct sexp_t *sx)
{
	int sp = 0;
	struct sexp_t *stack[SEXP_PARSER_STACK_SIZE];

	if (!sx)
		return;
	stack[sp] = sx;
	while (sp >= 0) {
		sx = stack[sp--];
		if (sx->next)
			PUSH(sx->next);
		if (sx->list)
			PUSH(sx->list);
		free(sx);
	}
}

void sexp_parser_reset(struct sexp_parser_state_t *s)
{
	if (s->top)
		sexp_free(s->top);
	if (s->atom)
		free(s->atom);
	s->state = SE_NONE;
	s->val = 0;
	s->atom = 0;
	s->atom_size = 0;
	s->incr = 64;

	s->top = 0;
	s->sp = 0;
	s->stack[0] = &s->top;

	s->max_bytes = 0;
	s->bytes = 0;
}

struct sexp_parser_state_t *sexp_parser_new(void)
{
	struct sexp_parser_state_t *s;
	s = malloc(sizeof(*s));
	if (s) {
		s->top = 0;
		s->atom = 0;
		sexp_parser_reset(s);
	}
	return s;
}

void sexp_parser_limit(struct sexp_parser_state_t *s, long bytes)
{
	s->max_bytes = bytes;
}

void sexp_parser_destroy(struct sexp_parser_state_t *s)
{
	/* Free any partially build s-expressions */
	if (s->top)
		sexp_free(s->top);
	if (s->atom)
		free(s->atom);
	free(s);
}

/* This is like sexp_create for the parser */
static inline struct sexp_t *malloc_sx(struct sexp_parser_state_t *s, int size)
{
	struct sexp_t *sx;

	/* check limits */
	if (s->max_bytes && (s->bytes + sizeof(*sx) + size) > s->max_bytes) {
		fprintf(stderr, "Max bytes exceeded. %d %d %d\n",
			(int)s->max_bytes, (int)s->bytes,
			(int)sizeof(*sx) + size);
		return 0;
	}

	/* allocate it */
	sx = malloc(sizeof(*sx) + size);
	if (!sx) {
		fprintf(stderr, "Out of memory.\n");
		return 0;
	}
	s->bytes += sizeof(*sx) + size;
	sx->ty = size ? SEXP_VALUE : SEXP_LIST;
	sx->list = sx->next = 0;
	return sx;
}

static inline int complete_atom(struct sexp_parser_state_t *s)
{
	struct sexp_t *sx;

	sx = malloc_sx(s, s->val + 1);
	if (!sx)
		return -1;
	memcpy(sx->val, s->atom, s->val + 1);
	s->val = 0;

	/* Attach this new element to the sexp we're working on */
	*s->stack[s->sp] = sx;
	s->stack[s->sp] = &sx->next;
	return 0;
}

static inline int add_to_atom(struct sexp_parser_state_t *s, char c)
{
	char *tmp;

	/* resource limits */
	if (s->max_bytes &&
	    (s->bytes + sizeof(struct sexp_t) + s->val + 2) > s->max_bytes) {
		fprintf(stderr, "Max bytes exceeded. %d %d %d\n",
			(int)s->max_bytes, (int)s->bytes,
			(int)sizeof(struct sexp_t) + s->val + 2);
		return -1;
	}

	/* check if we need to grow the atom buffer */
	if (s->val >= s->atom_size - 1) {
		tmp = realloc(s->atom, s->atom_size + s->incr + 10);
		if (!tmp) {
			fprintf(stderr, "Out of memory.\n");
			return -1;
		}
		s->atom = tmp;
		s->atom_size += s->incr;
	}

	s->atom[s->val++] = c;
	s->atom[s->val] = 0;	/* keep it null terminated */
	return 0;
}

int sexp_parser_parse(const char *str_, int len, struct sexp_t **sx_out,
		      struct sexp_parser_state_t *s)
{
	const char *end, *str = str_;
	char c;
	struct sexp_t *sx;

	if (sx_out)
		*sx_out = 0;
	end = (len == -1) ? 0 : str + len;
	while (str != end && *str) {
		c = *str;

		switch (s->state) {
		case SE_NONE:
			if (c == '(') {
				str++;	/* consume ( */
				if (!(sx = malloc_sx(s, 0))) {
					fprintf(stderr, "Out of memory.\n");
					return -1;
				}

				if (s->sp + 1 >= SEXP_PARSER_STACK_SIZE) {
					fprintf(stderr, "Stack overflow.\n");
					return -1;
				}

				*(s->stack[s->sp]) = sx;
				s->stack[s->sp] = &sx->next;

				if (s->sp + 1 >= SEXP_PARSER_STACK_SIZE) {
					fprintf(stderr, "Stack overflow.\n");
					return -1;
				}

				s->sp++;
				s->stack[s->sp] = &sx->list;
				break;
			} else if (c == ')') {
				str++;	/* consume ) */
				if (s->sp == 0) {
					fprintf(stderr, "Stack underflow.\n");
					return -1;
				}
				s->sp--;
				if (s->sp == 0) {	/* Finished sexpr */
					if (sx_out)
						*sx_out = s->top;
					else
						sexp_free(s->top);
					/* clean out continuation state */
					s->top = 0;
					sexp_parser_reset(s);
					return str - str_;
				}
				break;
			} else if (isspace(c)) {
				str++;
			} else {
				s->state = SE_ATOM;
			}
			break;
		case SE_ATOM:
			if (s->sp == -1) {
				fprintf(stderr,
					"stack empty; no atom allowed here.\n");
				return -1;
			}
			if (c == '(' || c == ')' || isspace(c)) {
				s->state = SE_NONE;
				if (complete_atom(s))
					return -1;
				break;
			}
			if (c == '\\') {
				s->state = SE_ATOM_ESC;
				str++;
				break;
			}

			/* Normal addition to an atom */
			if (add_to_atom(s, c))
				return -1;
			str++;
			break;
		case SE_ATOM_ESC:
			s->state = SE_ATOM;
			if (add_to_atom(s, c))
				return -1;
			str++;
			break;
		}
	}
	return str - str_;
}

/*-------------------------------------------------------------------------
 *  Utility functions to make dealing with sexps a little easier.
 */
struct sexp_t *sexp_find_list(struct sexp_t *sx, ...)
{
	struct sexp_t *sxl;
	char *atom;
	va_list va;

	if (sx->ty != SEXP_LIST)
		return 0;
	for (sx = sx->list; sx; sx = sx->next) {
		/* Look for lists in this list */
		if (sx->ty == SEXP_LIST) {
			va_start(va, sx);

			sxl = sx->list;
			atom = va_arg(va, char *);
			while (sxl && sexp_is_value(sxl) && atom) {
				if (strcmp(sxl->val, atom))
					break;

				sxl = sxl->next;
				atom = va_arg(va, char *);
			}
			va_end(va);
			if (!atom) {
				/* Match! */
				return sx;
			}
		}
	}
	return 0;
}

/*-------------------------------------------------------------------------
 *  Functions to simplify building sexps.
 */
struct sexp_t *sexp_create(const char *val)
{
	int len;
	struct sexp_t *s;
	if (val) {
		len = strlen(val);
		if (!(s = malloc(sizeof(*s) + len + 1)))
			return 0;
		s->ty = SEXP_VALUE;
		s->list = s->next = 0;
		memcpy(s->val, val, len + 1);
	} else {
		if (!(s = malloc(sizeof(*s))))
			return 0;
		s->ty = SEXP_LIST;
		s->list = s->next = 0;
	}
	return s;
}

struct sexp_t *sexp_create_list(const char *str1, ...)
{
	struct sexp_t *first, **sx;
	const char *p;
	va_list va;

	first = sexp_create(0);
	if (!first)
		return 0;
	sx = &first->list;

	va_start(va, str1);
	for (p = str1; p; p = va_arg(va, char *)) {
		*sx = sexp_create(p);
		if (!*sx) {
			sexp_free(first);
			return 0;
		}
		sx = &(*sx)->next;
	}
	return first;
}

struct sexp_t *sexp_create_list_v(char **strs)
{
	int i;
	struct sexp_t *first, **sx;

	first = sexp_create(0);
	if (!first)
		return 0;
	sx = &first->list;

	for (i = 0; strs[i]; i++) {
		*sx = sexp_create(strs[i]);
		if (!*sx) {
			sexp_free(first);
			return 0;
		}
		sx = &(*sx)->next;
	}
	return first;
}

struct sexp_t *sexp_concat(struct sexp_t *sx1, struct sexp_t *sx2)
{
	struct sexp_t **sxp;

	/* Find end of list */
	for (sxp = &sx1->list; *sxp; sxp = &(*sxp)->next) ;
	*sxp = sx2->list;
	free(sx2);
	return sx1;
}

void sexp_append_sx(struct sexp_t *sx, struct sexp_t *sx2)
{
	struct sexp_t **sxp;

	for (sxp = &sx->list; *sxp; sxp = &(*sxp)->next) ;
	*sxp = sx2;
}

struct sexp_t *sexp_append_atom(struct sexp_t *sx, const char *val)
{
	struct sexp_t **sxp;
	struct sexp_t *new_sx;

	new_sx = sexp_create(val);
	if (!new_sx)
		return 0;

	/* Follow to end of SX */
	for (sxp = &sx->list; *sxp; sxp = &(*sxp)->next) ;
	*sxp = new_sx;
	return new_sx;
}

struct sexp_t *sexp_copy(struct sexp_t *sx)
{
	struct sexp_t *new_sx;
	new_sx = sexp_create(sexp_is_value(sx) ? sx->val : 0);

	new_sx->list = sx->list ? sexp_copy(sx->list) : 0;
	new_sx->next = sx->next ? sexp_copy(sx->next) : 0;
	return new_sx;
}

struct sexp_t *sexp_copy_list(struct sexp_t *sx)
{
	struct sexp_t *new_sx;
	new_sx = sexp_create(0);
	new_sx->list = sx->list ? sexp_copy(sx->list) : 0;
	return new_sx;
}

struct sexp_t *sexp_nth(struct sexp_t *sx, int n)
{
	int i;
	sx = sx->list;
	if (!sx)
		return 0;
	for (i = 0; sx && i < n; i++)
		sx = sx->next;
	return sx;
}

int sexp_length(struct sexp_t *sx)
{
	int ct = 0;
	for (sx = sx->list; sx; sx = sx->next)
		ct++;
	return ct;
}

/*-------------------------------------------------------------------------
 *  Functions to simplify printing sexps.
 */
/* XXX We need some more useful stuff for doing sexp->string */

#undef PUSH
#define PUSH(ptr) \
do { \
    if (++sp == SEXP_PARSER_STACK_SIZE) { \
	fprintf(stderr, "%s: sexp stack overflow\n", __FUNCTION__); \
	abort(); \
    } \
    stack[sp] = (ptr); \
} while(0)

int sexp_strlen(struct sexp_t *sx)
{
	int len, sp = 0;
	char *p;
	struct sexp_t *stack[SEXP_PARSER_STACK_SIZE];

	len = 2;		/* open paren + last null */
	stack[0] = sx->list;
	while (sp >= 0) {
		sx = stack[sp--];
		if (sx) {
			if (sexp_is_list(sx)) {
				len += 2;	/* open, close paren */
				if (sp + 2 >= SEXP_PARSER_STACK_SIZE) {
					fprintf(stderr, "Stack overflow.\n");
					return -1;
				}
				PUSH(sx->next);
				PUSH(sx->list);
			} else {
				/* no need to check stack size here since we just did -- */
				PUSH(sx->next);
				for (p = sx->val; *p; p++) {
					char c = *p;
					if (isspace(c) || c == '(' || c == ')'
					    || c == '\\')
						len++;	/* backslash */
					len++;	/* character */
				}
				len++;	/* space after the atom */
			}
		}
	}
	return len;
}

int sexp_snprint(char *str_, int len, struct sexp_t *sx)
{
	int sp = 0;
	int last_atom = 0;
	char *p;
	char *str = str_, *end;
	struct sexp_t *stack[SEXP_PARSER_STACK_SIZE];

	end = (len == -1) ? 0 : str + len;
	*(str++) = '(';
	stack[0] = sx->list;
	while (sp >= 0 && str != end) {
		sx = stack[sp--];
		if (sx) {
			if (sexp_is_list(sx)) {
				if (sp + 2 >= SEXP_PARSER_STACK_SIZE) {
					fprintf(stderr, "Stack overflow.\n");
					return -1;
				}
				PUSH(sx->next);
				PUSH(sx->list);

				*(str++) = '(';
				if (str == end)
					break;
				last_atom = 0;
			} else {
				PUSH(sx->next);
				/* Print this atom */
				if (last_atom)
					*(str++) = ' ';
				for (p = sx->val; *p; p++) {
					char c = *p;
					if (isspace(c) || c == '(' || c == ')'
					    || c == '\\') {
						*(str++) = '\\';
						if (str == end)
							break;
					}
					*(str++) = c;
					if (str == end)
						break;
				}
				if (str == end)
					break;
				last_atom = 1;
			}
		} else {
			*(str++) = ')';
			last_atom = 0;
		}
	}
	*str = 0;
	return str - str_;
}

void sexp_print(FILE * f, struct sexp_t *sx_)
{
	int sp = 0, last_atom = 0;
	char *p;
	struct sexp_t *sx;
	struct sexp_t *stack[SEXP_PARSER_STACK_SIZE];

	fputc('(', f);
	stack[0] = sx_->list;
	while (sp >= 0) {
		sx = stack[sp--];
		if (sx) {
			if (sexp_is_list(sx)) {
				PUSH(sx->next);
				PUSH(sx->list);

				fputc('(', f);
				last_atom = 0;
			} else {
				PUSH(sx->next);
				/* Print this atom */
				if (last_atom)
					fputc(' ', f);
				for (p = sx->val; *p; p++) {
					char c = *p;
					if (isspace(c) || c == '(' || c == ')'
					    || c == '\\')
						fputc('\\', f);
					fputc(c, f);
				}
				last_atom = 1;
			}
		} else {
			fputc(')', f);
			last_atom = 0;
		}
	}
}

char *sexp_string(struct sexp_t *sx)
{
	int len;
	char *buf;
	len = sexp_strlen(sx);
	buf = malloc(len + 1);
	if (buf)
		sexp_snprint(buf, len, sx);
	return buf;
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
