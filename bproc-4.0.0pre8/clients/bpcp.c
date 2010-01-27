/*-------------------------------------------------------------------------
 *  bpcp.c: rcp using bproc instead for rcmd.
 *
 *  NOTE: This version should NOT be suid root.  (No special
 *  privileges are required.)
 *
 *  Erik Hendriks <erik@hendriks.cx>
 *  Copyright (c) 2000 Scyld Computing Corporation
 *
 * $Id: bpcp.c,v 1.12 2003/08/29 21:46:56 mkdist Exp $
 *-----------------------------------------------------------------------*/
/*
 * Copyright (c) 1983, 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define _FILE_OFFSET_BITS 64
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/bproc.h>

#define	_PATH_CP	"/bin/cp"
#define	OPTIONS "dfprt"

static int errs = 0, rem = 0;
static int pflag, iamremote, iamrecursive, targetshouldbedirectory;
static char **saved_environ;

typedef struct _buf {
	int cnt;
	char *buf;
} BUF;

static void lostconn(int);
static char *colon(char *);
static int response(void);
static void verifydir(const char *cp);
static void source(int argc, char *argv[]);
static void rsource(char *name, struct stat *statp);
static void sink(int argc, char *argv[]);
static BUF *allocbuf(BUF * bp, int fd, int blksize);
static void nospace(void);
static void usage(char *arg0);
static void toremote(const char *targ, int argc, char *argv[]);
static void tolocal(int argc, char *argv[]);
static void error(const char *fmt, ...);

static
int setup_socket(int *portno)
{
	int fd, addrsize;
	struct sockaddr_in addr;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		perror("socket");
		exit(1);
	}
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = 0;
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		perror("bind");
		exit(1);
	}

	if (listen(fd, 5) == -1) {
		perror("listen");
		exit(1);
	}
	addrsize = sizeof(addr);
	getsockname(fd, (struct sockaddr *)&addr, &addrsize);
	*portno = ntohs(addr.sin_port);
	return fd;
}

int main(int argc, char *argv[]);
int remote_proc(char *host, ...)
{				/*char *direction_flag, char *targ) { */
	int node, pid, argc;
	int listenfd, fd, addrsize;
	int port;
	char **argv, *argstr;
	struct sockaddr_in addr;
	va_list arg;
	struct bproc_io_t io;
	char *check;

	node = strtol(host, &check, 0);
	if (*check) {
		fprintf(stderr, "Invalid node number: %s\n", host);
		exit(1);
	}

	listenfd = setup_socket(&port);

	/* (ab)use BProc to setup the connection between our two procs */
	io.fd = STDIN_FILENO;
	io.type = BPROC_IO_SOCKET;
	io.flags = 0;
	((struct sockaddr_in *)&io.d.addr)->sin_family = AF_INET;
	((struct sockaddr_in *)&io.d.addr)->sin_addr.s_addr = 0;
	((struct sockaddr_in *)&io.d.addr)->sin_port = htons(port);

	pid = bproc_rfork_io(node, &io, 1);
	if (pid == -1) {
		perror("rfork");
		exit(1);
	}
	if (pid == 0) {
		va_start(arg, host);
		for (argc = 1; va_arg(arg, char *); argc++) ;	/* count arguments. */
		va_end(arg);

		argv = malloc(sizeof(char *) * (argc + 1));
		if (!argv)
			nospace();

		va_start(arg, host);
		argv[0] = "rcp";
		for (argc = 1; (argstr = va_arg(arg, char *)); argc++)
			argv[argc] = argstr;
		argv[argc] = 0;
		va_end(arg);

		rem = 0;	/* reinitialize some state... */
		optind = 0;
		exit(main(argc, argv));	/* jump back in.... */
	}
	addrsize = sizeof(addr);
	fd = accept(listenfd, (struct sockaddr *)&addr, &addrsize);
	if (fd == -1) {
		perror("accept");
		exit(1);
	}
	close(listenfd);
	return fd;
}

int main(int argc, char *argv[])
{
	int ch, fflag, tflag;
	char *targ;
	char *null = NULL;
	char *arg0 = argv[0];

	saved_environ = __environ;
	__environ = &null;

	fflag = tflag = 0;
	while ((ch = getopt(argc, argv, OPTIONS)) != EOF)
		switch (ch) {
			/* user-visible flags */
		case 'h':
			usage(arg0);
			exit(0);
		case 'v':
			printf("%s version %s\n", arg0, PACKAGE_VERSION);
			exit(0);
		case 'p':	/* preserve access/mod times */
			++pflag;
			break;
		case 'r':
			++iamrecursive;
			break;
			/* rshd-invoked options (server) */
		case 'd':
			targetshouldbedirectory = 1;
			break;
		case 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			break;
		case 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
			break;

		case '?':
		default:
			usage(arg0);
		}
	argc -= optind;
	argv += optind;

	if (fflag) {
		/* follow "protocol", send data */
		(void)response();
		source(argc, argv);
		exit(errs);
	}

	if (tflag) {
		/* receive data */
		sink(argc, argv);
		exit(errs);
	}

	if (argc < 2)
		usage(arg0);
	if (argc > 2)
		targetshouldbedirectory = 1;

	rem = -1;
	(void)signal(SIGPIPE, lostconn);

	if ((targ = colon(argv[argc - 1])) != NULL) {
		/* destination is remote host */
		*targ++ = 0;
		toremote(targ, argc, argv);
	} else {
		tolocal(argc, argv);	/* destination is local host */
		if (targetshouldbedirectory)
			verifydir(argv[argc - 1]);
	}
	exit(errs);
}

static void toremote(const char *targ, int argc, char *argv[])
{
	int i, tos;
	char *bp, *host, *src, *thost;

	if (*targ == 0)
		targ = ".";

	if ((thost = strchr(argv[argc - 1], '@')) != NULL) {
		*thost++ = 0;	/* user@host */
	} else {
		thost = argv[argc - 1];
	}

	for (i = 0; i < argc - 1; i++) {
		src = colon(argv[i]);
		if (src) {	/* remote to remote */
			static char dot[] = ".";
			*src++ = 0;
			if (*src == 0)
				src = dot;
			host = strchr(argv[i], '@');
			host = host ? host + 1 : argv[i];
			if (!(bp = malloc(strlen(thost) + strlen(targ) + 2)))
				nospace();
			sprintf(bp, "%s:%s", thost, targ);
			remote_proc(host, src, bp, 0);
			(void)free(bp);
		} else {	/* local to remote */
			if (rem == -1) {
				host = thost;
				rem = remote_proc(host, "-t", targ, 0);
				if (rem < 0)
					exit(1);
#ifdef IP_TOS
				tos = IPTOS_THROUGHPUT;
				if (setsockopt(rem, IPPROTO_IP, IP_TOS,
					       (char *)&tos, sizeof(int)) < 0)
					perror("rcp: setsockopt TOS (ignored)");
#endif
				if (response() < 0)
					exit(1);
			}
			source(1, argv + i);
		}
	}
}

static void tolocal(int argc, char *argv[])
{
	static char dot[] = ".";
	int i, len, tos;
	char *bp, *host, *src;

	for (i = 0; i < argc - 1; i++) {
		if (!(src = colon(argv[i]))) {	/* local to local */
			len = strlen(_PATH_CP) + strlen(argv[i]) +
			    strlen(argv[argc - 1]) + 20;
			if (!(bp = malloc(len)))
				nospace();
			(void)snprintf(bp, len, "%s%s%s %s %s", _PATH_CP,
				       iamrecursive ? " -r" : "",
				       pflag ? " -p" : "", argv[i],
				       argv[argc - 1]);
			system(bp);
			(void)free(bp);
			continue;
		}
		*src++ = 0;
		if (*src == 0)
			src = dot;
		host = strchr(argv[i], '@');
		host = host ? host + 1 : argv[i];
		rem = remote_proc(host, "-f", src, 0);
		if (rem < 0) {
			++errs;
			continue;
		}
#ifdef IP_TOS
		tos = IPTOS_THROUGHPUT;
		if (setsockopt(rem, IPPROTO_IP, IP_TOS,
			       (char *)&tos, sizeof(int)) < 0)
			perror("rcp: setsockopt TOS (ignored)");
#endif
		sink(1, argv + argc - 1);
		(void)close(rem);
		rem = -1;
	}
}

static void verifydir(const char *cp)
{
	struct stat stb;

	if (stat(cp, &stb) >= 0) {
		if ((stb.st_mode & S_IFMT) == S_IFDIR)
			return;
		errno = ENOTDIR;
	}
	error("rcp: %s: %s.\n", cp, strerror(errno));
	exit(1);
}

static char *colon(char *cp)
{
	for (; *cp; ++cp) {
		if (*cp == ':')
			return (cp);
		if (*cp == '/')
			return NULL;
	}
	return NULL;
}

typedef void (*sighandler) (int);

static void source(int argc, char *argv[])
{
	struct stat stb;
	static BUF buffer;
	BUF *bp;
	off_t i;
	int x, readerr, f, amt;
	char *last, *name, buf[BUFSIZ];

	for (x = 0; x < argc; x++) {
		name = argv[x];
		if ((f = open(name, O_RDONLY, 0)) < 0) {
			error("rcp: %s: %s\n", name, strerror(errno));
			continue;
		}
		if (fstat(f, &stb) < 0)
			goto notreg;
		switch (stb.st_mode & S_IFMT) {

		case S_IFREG:
			break;

		case S_IFDIR:
			if (iamrecursive) {
				(void)close(f);
				rsource(name, &stb);
				continue;
			}
			/* FALLTHROUGH */
		default:
		      notreg:(void)close(f);
			error("rcp: %s: not a plain file\n", name);
			continue;
		}
		last = strrchr(name, '/');
		if (last == 0)
			last = name;
		else
			last++;
		if (pflag) {
			/*
			 * Make it compatible with possible future
			 * versions expecting microseconds.
			 */
			(void)snprintf(buf, sizeof(buf),
				       "T%ld 0 %ld 0\n", stb.st_mtime,
				       stb.st_atime);
			(void)write(rem, buf, (int)strlen(buf));
			if (response() < 0) {
				(void)close(f);
				continue;
			}
		}
		(void)snprintf(buf, sizeof(buf),
			       "C%04o %Ld %s\n", stb.st_mode & 07777,
			       (long long)stb.st_size, last);
		(void)write(rem, buf, (int)strlen(buf));
		if (response() < 0) {
			(void)close(f);
			continue;
		}
		if ((bp = allocbuf(&buffer, f, BUFSIZ)) == 0) {
			(void)close(f);
			continue;
		}
		readerr = 0;
		for (i = 0; i < stb.st_size; i += bp->cnt) {
			amt = bp->cnt;
			if (i + amt > stb.st_size)
				amt = stb.st_size - i;
			if (readerr == 0 && read(f, bp->buf, amt) != amt)
				readerr = errno;
			(void)write(rem, bp->buf, amt);
		}
		(void)close(f);
		if (readerr == 0)
			(void)write(rem, "", 1);
		else
			error("rcp: %s: %s\n", name, strerror(readerr));
		(void)response();
	}
}

static void rsource(char *name, struct stat *statp)
{
	DIR *dirp;
	struct dirent *dp;
	char *last, *vect[1], path[MAXPATHLEN];

	if (!(dirp = opendir(name))) {
		error("rcp: %s: %s\n", name, strerror(errno));
		return;
	}
	last = strrchr(name, '/');
	if (last == 0)
		last = name;
	else
		last++;
	if (pflag) {
		(void)snprintf(path, sizeof(path),
			       "T%ld 0 %ld 0\n", statp->st_mtime,
			       statp->st_atime);
		(void)write(rem, path, (int)strlen(path));
		if (response() < 0) {
			closedir(dirp);
			return;
		}
	}
	(void)snprintf(path, sizeof(path),
		       "D%04o %d %s\n", statp->st_mode & 07777, 0, last);
	(void)write(rem, path, (int)strlen(path));
	if (response() < 0) {
		closedir(dirp);
		return;
	}
	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_ino == 0)
			continue;
		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;
		if (strlen(name) + 1 + strlen(dp->d_name) >= MAXPATHLEN - 1) {
			error("%s/%s: name too long.\n", name, dp->d_name);
			continue;
		}
		(void)snprintf(path, sizeof(path), "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	closedir(dirp);
	(void)write(rem, "E\n", 2);
	(void)response();
}

static int response(void)
{
	register char *cp;
	char ch, resp, rbuf[BUFSIZ];

	if (read(rem, &resp, sizeof(resp)) != sizeof(resp))
		lostconn(0);

	cp = rbuf;
	switch (resp) {
	case 0:		/* ok */
		return 0;
	default:
		*cp++ = resp;
		/* FALLTHROUGH */
	case 1:		/* error, followed by err msg */
	case 2:		/* fatal error, "" */
		do {
			if (read(rem, &ch, sizeof(ch)) != sizeof(ch))
				lostconn(0);
			*cp++ = ch;
		} while (cp < &rbuf[BUFSIZ] && ch != '\n');

		if (!iamremote)
			write(2, rbuf, cp - rbuf);
		++errs;
		if (resp == 1)
			return -1;
		exit(1);
	}
	 /*NOTREACHED*/ return 0;
}

static void lostconn(int ignore)
{
	(void)ignore;

	if (!iamremote)
		(void)fprintf(stderr, "rcp: lost connection\n");
	exit(1);
}

static void sink(int argc, char *argv[])
{
	register char *cp;
	static BUF buffer;
	struct stat stb;
	struct timeval tv[2];
	enum { YES, NO, DISPLAYED } wrerr;
	BUF *bp;
	off_t i, j;
	char ch, *targ;
	const char *why;
	off_t size;
	int amt, count, exists, first, mask, mode;
	int ofd, setimes, targisdir;
	char *np, *vect[1], buf[BUFSIZ];

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; goto screwup; }

	setimes = targisdir = 0;
	mask = umask(0);
	if (!pflag)
		(void)umask(mask);
	if (argc != 1) {
		error("rcp: ambiguous target\n");
		exit(1);
	}
	targ = *argv;
	if (targetshouldbedirectory)
		verifydir(targ);
	(void)write(rem, "", 1);
	if (stat(targ, &stb) == 0 && (stb.st_mode & S_IFMT) == S_IFDIR)
		targisdir = 1;
	for (first = 1;; first = 0) {
		cp = buf;
		if (read(rem, cp, 1) <= 0)
			return;
		if (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		do {
			if (read(rem, &ch, sizeof(ch)) != sizeof(ch))
				SCREWUP("lost connection");
			*cp++ = ch;
		} while (cp < &buf[BUFSIZ - 1] && ch != '\n');
		*cp = 0;

		if (buf[0] == '\01' || buf[0] == '\02') {
			if (iamremote == 0)
				(void)write(2, buf + 1, (int)strlen(buf + 1));
			if (buf[0] == '\02')
				exit(1);
			errs++;
			continue;
		}
		if (buf[0] == 'E') {
			(void)write(rem, "", 1);
			return;
		}

		if (ch == '\n')
			*--cp = 0;

#define getnum(t) (t) = 0; while (isdigit(*cp)) (t) = (t) * 10 + (*cp++ - '0');
		cp = buf;
		if (*cp == 'T') {
			setimes++;
			cp++;
			getnum(mtime.tv_sec);
			if (*cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			getnum(mtime.tv_usec);
			if (*cp++ != ' ')
				SCREWUP("mtime.usec not delimited");
			getnum(atime.tv_sec);
			if (*cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			getnum(atime.tv_usec);
			if (*cp++ != '\0')
				SCREWUP("atime.usec not delimited");
			(void)write(rem, "", 1);
			continue;
		}
		if (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			if (first) {
				error("%s\n", cp);
				exit(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		for (++cp; cp < buf + 5; cp++) {
			if (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		if (*cp++ != ' ')
			SCREWUP("mode not delimited");
		size = 0;
		while (isdigit(*cp))
			size = size * 10 + (*cp++ - '0');
		if (*cp++ != ' ')
			SCREWUP("size not delimited");
		if (targisdir) {
			static char *namebuf;
			static int cursize;
			int need;

			need = strlen(targ) + strlen(cp) + 250;
			if (need > cursize) {
				if (!(namebuf = malloc(need)))
					error("out of memory\n");
			}
			(void)snprintf(namebuf, need, "%s%s%s", targ,
				       *targ ? "/" : "", cp);
			np = namebuf;
		} else
			np = targ;
		exists = stat(np, &stb) == 0;
		if (buf[0] == 'D') {
			if (exists) {
				if ((stb.st_mode & S_IFMT) != S_IFDIR) {
					errno = ENOTDIR;
					goto bad;
				}
				if (pflag)
					(void)chmod(np, mode);
			} else if (mkdir(np, mode) < 0)
				goto bad;
			vect[0] = np;
			sink(1, vect);
			if (setimes) {
				setimes = 0;
				if (utimes(np, tv) < 0)
					error
					    ("rcp: can't set times on %s: %s\n",
					     np, strerror(errno));
			}
			continue;
		}
		if ((ofd = open(np, O_WRONLY | O_CREAT, mode)) < 0) {
		      bad:error("rcp: %s: %s\n", np,
			      strerror(errno));
			continue;
		}
		if (exists && pflag)
			(void)fchmod(ofd, mode);
		(void)write(rem, "", 1);
		if ((bp = allocbuf(&buffer, ofd, BUFSIZ)) == 0) {
			(void)close(ofd);
			continue;
		}
		cp = bp->buf;
		count = 0;
		wrerr = NO;
		for (i = 0; i < size; i += BUFSIZ) {
			amt = BUFSIZ;
			if (i + amt > size)
				amt = size - i;
			count += amt;
			do {
				j = read(rem, cp, amt);
				if (j <= 0) {
					error("rcp: %s\n",
					      j ? strerror(errno) :
					      "dropped connection");
					exit(1);
				}
				amt -= j;
				cp += j;
			} while (amt > 0);
			if (count == bp->cnt) {
				if (wrerr == NO &&
				    write(ofd, bp->buf, count) != count)
					wrerr = YES;
				count = 0;
				cp = bp->buf;
			}
		}
		if (count != 0 && wrerr == NO &&
		    write(ofd, bp->buf, count) != count)
			wrerr = YES;
		if (ftruncate(ofd, size)) {
			error("rcp: can't truncate %s: %s\n", np,
			      strerror(errno));
			wrerr = DISPLAYED;
		}
		(void)close(ofd);
		(void)response();
		if (setimes && wrerr == NO) {
			setimes = 0;
			if (utimes(np, tv) < 0) {
				error("rcp: can't set times on %s: %s\n",
				      np, strerror(errno));
				wrerr = DISPLAYED;
			}
		}
		switch (wrerr) {
		case YES:
			error("rcp: %s: %s\n", np, strerror(errno));
			break;
		case NO:
			(void)write(rem, "", 1);
			break;
		case DISPLAYED:
			break;
		}
	}
      screwup:
	error("rcp: protocol screwup: %s\n", why);
	exit(1);
}

static BUF *allocbuf(BUF * bp, int fd, int blksize)
{
	struct stat stb;
	int size;

	if (fstat(fd, &stb) < 0) {
		error("rcp: fstat: %s\n", strerror(errno));
		return (0);
	}
	size = roundup(stb.st_blksize, blksize);
	if (size == 0)
		size = blksize;
	if (bp->cnt < size) {
		if (bp->buf != 0)
			free(bp->buf);
		bp->buf = malloc(size);
		if (!bp->buf) {
			error("rcp: malloc: out of memory\n");
			return NULL;
		}
	}
	bp->cnt = size;
	return (bp);
}

void error(const char *fmt, ...)
{
	static FILE *fp;
	char buf[1000];

	++errs;
	if (!fp && !(fp = fdopen(rem, "w")))
		return;

	/* (fmt,...) might need to go to two streams.
	 *
	 * In { va_start ; vfprintf ; vfprintf ; va_end }, second
	 * vfprintf didn't restart (ie: vfprintf affects ap) (glibc)
	 *
	 * Is { va_start ; vfprintf ; va_end} * 2 even allowed?
	 *
	 * => Dump (fmt,...) to buffer.  */

	{
		va_list ap;
		va_start(ap, fmt);
		vsnprintf(buf, sizeof(buf), fmt, ap);
		buf[sizeof(buf) - 1] = 0;
		va_end(ap);
	}

	fprintf(fp, "%c%s", 0x01, buf);
	fflush(fp);

	if (!iamremote)
		fputs(buf, stderr);
}

static void nospace(void)
{
	(void)fprintf(stderr, "rcp: out of memory.\n");
	exit(1);
}

static void usage(char *arg0)
{
	printf("Usage: %s [-p] f1 f2\n"
	       "       %s [-r] [-p] f1 ... fn directory\n"
	       "\n"
	       "       -h     Display this message and exit.\n"
	       "       -v     Display version information and exit.\n"
	       "       -p     Preserve file timestamps.\n"
	       "       -r     Copy recursively.\n", arg0, arg0);
	exit(1);
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
