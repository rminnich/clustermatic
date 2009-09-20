/*------------------------------------------------------------ -*- C -*-
 * exec: fork and exec a command on the node
 *
 * Joshua Aune <luken@linuxnetworx.com>
 *
 * Copyright(C) 2003 Linux Networx
 *
 * This software may be used and distributed according to the terms of
 * the GNU General Public License, incorporated herein by reference to
 * http://www.gnu.org/licenses/gpl.html.
 *
 * This software is provided by the author(s) "as is" and any express
 * or implied warranties, including, but not limited to, the implied
 * warranties of merchantability and fitness for a particular purpose
 * are disclaimed.  In no event shall the author(s) be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability,
 * whether in contract, strict liability, or tort (including
 * negligence or otherwise) arising in any way out of the use of this
 * software, even if advised of the possibility of such damage.
 *
 * $Id: exec.c,v 1.1 2004/03/12 20:20:25 mkdist Exp $
 *--------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/wait.h>


/* useful if compiling outside of node_up for testing */
#if NO_NODEUP
#define LOG_INFO 1
#define LOG_ERROR 1

#include <stdarg.h>
void log_print(int level, char *fmt, ...) {
	va_list valist;
	int len;
	char buffer[1024];

	va_start(valist, fmt);
	len = vsnprintf(buffer, 1024, fmt, valist);
	write(STDOUT_FILENO, buffer, len);
	va_end(valist);
}	

#else /* NO_NODEUP */
#include "node_up.h"
#endif /* NO_NODEUP */

int nodeup_postmove(int argc, char *argv[]) {
	pid_t pid = 0;
	int wait_status = -1;
	int rv;
	int i;
	char log_str[80];
	char log_str_cpy[80];

	bzero((void *)log_str, 80);
	bzero((void *)log_str_cpy, 80);

	/* Don't want to exec ourselves */
	argc--;
	argv++;

	if (! argv[0] || argv[argc]) {
		log_print(LOG_ERROR, "argv[0] or argv[%d] invalid\n", argc);
		return -1;
	}
	
	pid = fork();
	if (pid == -1) {
		log_print(LOG_ERROR, "fork died: %s: %s\n", argv[0], strerror(errno));
		return -1;
	}
	if (pid == 0) {
		for(i=0; i<argc; i++) {
			// Just drop anything past 80
			strncpy(log_str_cpy, log_str, 80);
			snprintf(log_str, 80, "%s %s", log_str_cpy, argv[i]);
		}
		log_print(LOG_INFO, "exec:%s\n", log_str);

		execvp(argv[0], argv);
		log_print(LOG_ERROR, "execvp failed for %s: %s\n", 
			argv[0], strerror(errno));
		return -1;
	}

	while ((rv = waitpid(pid, &wait_status, 0)) == -1 && (errno == EINTR));

	if (rv == -1) 	{
		log_print(LOG_ERROR, "wait for %s: %d died: %s\n", 
			argv[0], pid, strerror(errno));
		return -1;
	}

	if (!WIFEXITED(wait_status)) {
		if (WIFSIGNALED(wait_status)) {
			log_print(LOG_ERROR, "child failed with signal %d\n", WTERMSIG(wait_status));
		}
		else {
			log_print(LOG_ERROR, "child failed with funny status\n");
		}
	}

	return WIFEXITED(wait_status) ? WEXITSTATUS(wait_status): -1;
}

#if NO_NODEUP
int main(int argc, char *argv[])
{
	return nodeup_postmove(argc, argv);
}
#endif /* NO_NODEUP */


/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
