/*------------------------------------------------------------ -*- C -*-
 * cmconf.c: the clustermatic configuration file library
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
 *  $Id: cmconf.c,v 1.1 2004/11/03 17:13:58 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include "list.h"
#include "cmconf.h"

struct cmconf_line {
    struct list_head list;
    char *line;
};

struct cmconf {
    FILE *f;
    struct list_head lines;

    /* State for nice parser error messages */
    char *filename;		/* filename */
    int   lineno;		/* 1 based current line number */
    int   pass;
    struct cmconf_line *line;	/* current line for parser */
};

#define LINELEN 1024

static
struct cmconf_line *mkline(const char *str) {
    struct cmconf_line *line;
    line = malloc(sizeof(*line));
    if (!line) return 0;
    line->line = strdup(str);
    if (!line->line) {
	free(line);
	return 0;
    }
    return line;
}

/*--------------------------------------------------------------------
 *  Processor primitives
 */
static
char **getargs(char *line) {
    int i,j;
    int nargs = 10;
    int currarg = 0;
    char **args, **newargs;
    char *ptr;
    char quote = 0; 

    if (!(args = malloc(sizeof(char *)*nargs)))
	return 0;

    i = 0;
    while (1) {
	/* "seek" to the beginning of the next argument */
	while(line[i] && isspace(line[i])) i++; /* Skip over white space */
	if (!line[i]) break;
	
	/* Tag an argument */
	ptr = &line[i];
	for (j=i; line[i] && (quote || !isspace(line[i])); ) {
	    if (line[i] == quote) {
		quote = 0;
		i++;
		continue;
	    }

	    if (!quote && (line[i] == '"' || line[i] == '\'')) {
		quote = line[i++];
		continue;
	    }

	    if (line[i] == '\\') {
		i++;
		/* Handle other quotings here... */
	    }

	    line[j++] = line[i++];
	}
	if (line[i])  i++;
	line[j] = 0;		/* Cut off this argument */
	args[currarg++] = ptr;	/* strdup here? */

	/* Check to make sure our args array is big enough. */
	if (currarg == nargs) {
	    nargs += 10;
	    newargs = realloc(args, sizeof(char *)*nargs);
	    if (!newargs) {
		free(args);
		fprintf(stderr, "Out of memory.\n");
		return 0;
	    }
	    args = newargs;
	}
    }
    args[currarg] = 0;
    
    return args;
}

int cmconf_process_args(struct cmconf *conf, char **args,
		 struct cmconf_option *options) {
    int i, matched_any=0;
    struct cmconf_option *opt;

    if (!args[0]) return 0;	/* empty line */
    for(opt=options; opt->tag; opt++) {
	if (strcmp(opt->tag, args[0]) == 0) matched_any = 1;

	if ((conf->pass == -1 || opt->pass == conf->pass) &&
	    (strcmp(opt->tag, args[0]) == 0 ||
	     (strcmp(opt->tag, "*") == 0 && !matched_any))) {

	    /* option matches, check argument counts. */
	    for (i=0; args[i]; i++);
	    if (opt->maxargs != -1 && i-1 > opt->maxargs) {
		fprintf(stderr,"%s:%d Too many arguments for %s. (max = %d)\n",
			conf->filename, conf->lineno, opt->tag, opt->maxargs);
		return -1;
	    }
	    if (i-1 < opt->minargs) {
		fprintf(stderr,"%s:%d Too few arguments for %s. (min = %d)\n",
			conf->filename, conf->lineno, opt->tag, opt->minargs);
		return -1;
	    }
	    if (opt->callback && opt->callback(conf, args))
		return -1;
	    break;
	}
    }
    return 0;
}

static
int options_left(struct cmconf_option *options, int pass) {
    struct cmconf_option *opt;
    for(opt=options; opt->tag; opt++)
	if (opt->pass >= pass) return 1;
    return 0;
}

static
int process_line(struct cmconf *conf, struct cmconf_line *line,
		 struct cmconf_option *options) {
    char *linestr, *p;
    char **args;
    int result;
    
    if (!(linestr = strdup(line->line))) {
	errno = ENOMEM;
	return -1;
    }
    if ((p = strchr(linestr, '#'))) *p = 0; 	/* Remove comments */

    if (!(args = getargs(linestr))) {	/* Scan the line into arguments. */
	free(linestr);
	errno = ENOMEM;
	return -1;
    }
    result = cmconf_process_args(conf, args, options);
    free(linestr);
    free(args);
    return result;
}

int cmconf_process(struct cmconf *conf, struct cmconf_option *options) {
    struct cmconf_line *line, *next;

    conf->lineno = 0;
    for (conf->pass=0; options_left(options, conf->pass); conf->pass++) {
	for (line = cmconf_first(conf); line; line = next) {
	    next = cmconf_next(conf,line);
	    conf->lineno++;
	    conf->line = line;
	    if (process_line(conf, line, options))
		return -1;
	}
    }
    return 0;
}

int cmconf_process_line(struct cmconf_line *line,
			struct cmconf_option *options) {
    struct cmconf conf;
    conf.filename = "";
    conf.lineno     = 0;
    conf.pass     = -1;
    conf.line    = line;

    return process_line(&conf, line, options);
}

int cmconf_process_file(const char *filename, struct cmconf_option *options) {
    int r;
    struct cmconf *c;

    c = cmconf_read(filename, 0);
    if (!c) return -1;

    r = cmconf_process(c, options);
    cmconf_free(c);
    return r;
}

/*--------------------------------------------------------------------
 *  Parser state primitives
 */
const char *cmconf_file(struct cmconf *conf) {
    return conf->filename;
}

int cmconf_lineno(struct cmconf *conf) {
    return conf->lineno;
}

int cmconf_pass(struct cmconf *conf) {
    return conf->pass;
}

struct cmconf_line * cmconf_line(struct cmconf *conf) {
    return conf->line;
}

/*--------------------------------------------------------------------
 *  Config file access primitives
 */
const char *cmconf_get_line(struct cmconf_line *line) {
    return line->line;
}

void cmconf_set_line(struct cmconf_line *line, const char *str) {
    free(line->line);
    line->line = strdup(str);
}

void cmconf_delete(struct cmconf_line *line) {
    list_del(&line->list);
    free(line);
}

void cmconf_insert_before(struct cmconf_line *line, const char *str) {
    struct cmconf_line *newline;
    newline = mkline(str);
    list_add_tail(&newline->list, &line->list);
}

void cmconf_insert_after(struct cmconf_line *line, const char *str) {
    struct cmconf_line *newline;
    newline = mkline(str);
    list_add_tail(&newline->list, &line->list);
}

void cmconf_append(struct cmconf *conf, const char *str) {
    struct cmconf_line *newline;
    newline = mkline(str);
    list_add_tail(&newline->list, &conf->lines);
}

struct cmconf_line *cmconf_first(struct cmconf *conf) {
    if (list_empty(&conf->lines))
	return 0;
    return list_entry(conf->lines.next, struct cmconf_line, list);
}

struct cmconf_line *cmconf_next(struct cmconf *conf,
				  struct cmconf_line *line) {
    if (line->list.next == &conf->lines)
	return 0;
    return list_entry(line->list.next, struct cmconf_line, list);
}

struct cmconf * cmconf_read(const char *filename, int keep_open) {
    char line[LINELEN], *p;
    struct cmconf *c;
    struct cmconf_line *l;
    struct flock lock;

    if (!(c = malloc (sizeof(*c)))) {
	errno = ENOMEM;
	return 0;
    }
    memset(c, 0, sizeof(*c));
    INIT_LIST_HEAD(&c->lines);

    c->filename = strdup(filename);
    if (!c->filename) {
	free(c);
	return 0;
    }

    c->f = fopen(filename, keep_open ? "r+" : "r");
    if (!c->f) {
	free(c->filename);
	free(c);
	return 0;
    }


    /* Lock the file appropriately */
    lock.l_type   = keep_open ? F_WRLCK : F_RDLCK;
    lock.l_start  = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len    = 0;

    if (fcntl(fileno(c->f), F_SETLK, &lock)) {
	fclose(c->f);
	free(c);
	errno = ENOMEM;
	return 0;
    }

    /* Read the lines in this file */
    while (fgets(line, LINELEN, c->f)) {
	line[LINELEN-1] = 0;
	if ((p = strchr(line, '\n'))) *p = 0; /* remove new line */
	if (!(l = malloc(sizeof(*l)))) {
	    cmconf_free(c);
	    errno = ENOMEM;
	    return 0;
	}
	if (!(l->line = strdup(line))) {
	    free(l);
	    cmconf_free(c);
	    errno = ENOMEM;
	    return 0;
	}
	list_add_tail(&l->list, &c->lines);
    }

    if (!keep_open) {
	fclose(c->f);
	c->f = 0;
    }
    return c;
}

int cmconf_write(struct cmconf *conf) {
    if (!conf->f) {
	errno = EINVAL;
	return -1;
    }

    if (fseek(conf->f, 0, SEEK_SET))
	return -1;

    if (ftruncate(fileno(conf->f), 0))
	return -1;
    
    cmconf_print(conf->f, conf);
    fflush(conf->f);
    return 0;
}

void cmconf_print(FILE *f, struct cmconf *conf) {
    struct list_head *l;
    struct cmconf_line *line;
    for (l = conf->lines.next; l != &conf->lines; l = l->next) {
	line = list_entry(l, struct cmconf_line, list);
	fprintf(f, "%s\n", line->line);
    }
}

void cmconf_free(struct cmconf *conf) {
    struct cmconf_line *l;

    if (conf->f) fclose(conf->f);
    if (conf->filename) free(conf->filename);
    while (!list_empty(&conf->lines)) {
	l = list_entry(conf->lines.next, struct cmconf_line, list);
	list_del(&l->list);
	free(l->line);
	free(l);
    }
    free(conf);
}


/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
