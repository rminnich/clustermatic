/*
 * Support functions.  Exported functions are prototyped in sundries.h.
 * sundries.c,v 1.1.1.1 1993/11/18 08:40:51 jrs Exp
 *
 * added fcntl locking by Kjetil T. (kjetilho@math.uio.no) - aeb, 950927
 *
 * 1999-02-22 Arkadiusz Mi¶kiewicz <misiek@pld.ORG.PL>
 * - added Native Language Support
 *
 * 2002-05-28 Erik Hendriks <hendriks@lanl.gov>
 * - severely truncated for beoboot environment
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sundries.h"

void die(char *s)
{
	printf(s);
	exit(1);
}

void *xmalloc(size_t size)
{
	void *t;

	if (size == 0)
		return NULL;

	t = malloc(size);
	if (t == NULL)
		die("not enough memory");

	return t;
}

char *xstrdup(const char *s)
{
	char *t;

	if (s == NULL)
		return NULL;

	t = strdup(s);

	if (t == NULL)
		die("not enough memory");

	return t;
}

char *xstrndup(const char *s, int n)
{
	char *t;

	if (s == NULL)
		die("bug in xstrndup call");

	t = xmalloc(n + 1);
	strncpy(t, s, n);
	t[n] = 0;

	return t;
}
