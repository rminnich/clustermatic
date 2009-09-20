/*------------------------------------------------------------ -*- C -*-
 * beoserv.c:
 * Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 * Copyright(C) 2003 University of California.  LA-CC Number 01-67.
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
 *  $Id: beoboot_boothooks.h,v 1.10 2004/05/03 23:57:22 mkdist Exp $
 *--------------------------------------------------------------------*/
#ifndef _BEOBOOT_BOOTHOOKS_H
#define _BEOBOOT_BOOTHOOKS_H

#include <stdarg.h>

struct cmconf_option;
struct boot_hook_t {
    struct boot_hook_t *next;
    char *name;		/* for logging purposes */
    void (*func)(void);
};

struct boot_conf_t {
    struct boot_conf_t *next;
    int phase;
    char *tag;
    struct cmconf_option *conflist;
};

/* These adding functions just add to the front of the list.  We have
 * very little control over what order these things get run in right
 * now... */
#define BOOT_ADD_HOOK(hn, nm, fc) \
static void __bh_ ## hn ## fc (void)__attribute__((constructor)); \
static void __bh_ ## hn ## fc (void) {                            \
    static struct boot_hook_t p;                                  \
    p.name = nm;                                                  \
    p.func = fc;                                                  \
    p.next = boot_hook_ ## hn ;                                   \
    boot_hook_ ## hn = &p;                                        \
}

#define BOOT_ADD_CONFIG(ph, tg, cf) \
static void __bc_ ## ph (void) __attribute__((constructor)); \
static void __bc_ ## ph (void) {                             \
    static struct boot_conf_t bc;                            \
    bc.phase = ph;                                           \
    bc.tag   = tg;                                           \
    bc.conflist = cf;                                        \
    bc.next = boot_conf;                                     \
    boot_conf = &bc;                                         \
}

/*--------------------------------------------------------------------
 * Hook names and explanations
 * first            - first thing - before boot does anything (phase 1 & 2)
 * phase1_pre_rarp  - After driver load, before RARPing in phase 1
 * phase2_pre_rarp  - After driver load, before RARPing in phase 2
 * phase1_post_rarp - After RARPing in phase 1, before image download
 * phase2_post_rarp - After RARPing in phase 2, before starting BProc
 * phsae2_last      - last thing before becoming init in phase 2
 */
extern struct boot_hook_t *boot_hook_first;
extern struct boot_hook_t *boot_hook_phase1_pre_rarp;
extern struct boot_hook_t *boot_hook_phase2_pre_rarp;
extern struct boot_hook_t *boot_hook_phase1_pre_rarp_every;
extern struct boot_hook_t *boot_hook_phase2_pre_rarp_every;
extern struct boot_hook_t *boot_hook_phase1_post_rarp;
extern struct boot_hook_t *boot_hook_phase2_post_rarp;
extern struct boot_hook_t *boot_hook_phase2_last;

extern struct boot_conf_t *boot_conf;
/* Boot stuff for use by hook using functions */

extern void fatal(char *fmt, ...);
extern void console_log(char *fmt, ...);
extern void console_log_v(char *fmt, va_list va);
#endif
/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
