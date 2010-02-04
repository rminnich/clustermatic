/*------------------------------------------------------------ -*- C -*-
 * nodeup: Definitions for modules
 * Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 * Copyright(C) 2001 University of California.  LA-CC Number 01-67.
 * This software has been authored by an employee or employees of the
 * University of California, operator of the Los Alamos National
 * Laboratory under Contract No.  W-7405-ENG-36 with the U.S.
 * Department of Energy.  The U.S. Government has rights to use,
 * reproduce, and distribute this software. If the software is
 * modified to produce derivative works, such modified software should
 * be clearly marked, so as not to confuse it with the version
 * available from LANL.
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
 * $Id: node_up.h,v 1.13 2003/09/24 20:38:37 mkdist Exp $
 *--------------------------------------------------------------------*/
#ifndef _NODE_UP_H
#define _NODE_UP_H

enum loglevel {
	LOG_FATAL,
	LOG_ERROR,
	LOG_WARNING,
	LOG_INFO,
	LOG_DEBUG
};

struct sockaddr_in;
struct node_t;

extern struct sockaddr_in nodeup_master;

/* DESC - the short one-liner description
 * INFO - detailed information on how to use the module
 */
#define MODULE_DESC(x) char nodeup_desc[] = x
#define MODULE_INFO(x) char nodeup_info[] = x

#ifdef __cplusplus
extern "C" {
#endif

/* These functions are provided by nodeup */
	void log_print(int level, char *fmt, ...);
	void console_print(char *fmt, ...);
	int nodeup_rpc(int (*funcp) (void *, int, void **, int *),
		       const void *in_data, int in_size,
		       void **out_data_, int *out_size_);
	void **nodeup_private(const char *tag);

/* The module should define these.  I have prototypes here so that
 * there's no confusion about what the prototype should be. */
	int nodeup_premove(int, char **);
	int nodeup_postmove(int, char **);

	int nodeup_node(void);

/* A handy little crutch for plugins that need /proc. */

/* nodeup_mnt_proc mounts procfs at the path specified.  It will be
 * automatically unmounted when the plugin function returns.  It can
 * also be manually unmounted with nodeup_umnt_proc().
 * nodeup_mnt_proc should not be called more than once. */
	int nodeup_mnt_proc(const char *path);
	void nodeup_umnt_proc(void);

#ifdef __cplusplus
}
#endif
#endif
/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
