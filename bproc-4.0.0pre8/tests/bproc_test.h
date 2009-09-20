#ifndef _BPROC_TEST_H
#define _BPROC_TEST_H


#define BPROC_TEST_NODES_MAX 3

struct bproc_test_info_t {
    int nprocs;			/* number of procs in arrangement */
    int arr;			/* process arrangement */
    int node[BPROC_TEST_NODES_MAX];	/* process nodes */
    int pid [BPROC_TEST_NODES_MAX];	/* process PIDs */

    /* For ue by tests */
    int scratch;		/* bit vector of attached children */
};

struct bproc_test_t {
    char *name;
    char *desc;
    int (*func)(int, struct bproc_test_info_t *);
    int np_min, np_max;
    int flags;

    int runflag;		/* flag for use by test driver */
};

#define BPROC_TEST(x,npmin,npmax,flags) \
    { #x, desc_ ## x, test_ ## x, (npmin), (npmax), (flags), 0 }

/* These flags control the kinds of arrangements that this test driver
 * will generate.
 *
 * detach     - Skip arrangements where the "children" aren't actually
 *              child processes of the parent.
 * no_attach  - Skip arrangements where the "children" are actually
 *              child processes of the parent.
 * invalid    - Try using invalid node numbers.  This probably only
 *              makes sense if you're not using the test driver to
 *              setup the processes.
 */

enum bproc_test_flags {
    /* Process placement flags */
    bproc_test_detach    = 0x01,
    bproc_test_no_attach = 0x02,
    bproc_test_invalid   = 0x04,

    /* Process creation flags */
    bproc_test_no_auto_create=0x100,
};


int bproc_test_init(const char *nstr);

int   bproc_test_run(struct bproc_test_t *t);
int  _bproc_test_run(struct bproc_test_t *t, int nproc);
int __bproc_test_run(struct bproc_test_t *t, int nproc, int arr);

/* Functions to pick apart process arrangements */
enum proc_loc      { proc_fe=0, proc_sl,   proc_sl2,   proc_sl3,
		     proc_inv,  proc_sl_d, proc_sl2_d, proc_sl3_d,
		     proc_last };

#define proc_shift 3
#define proc_arr(arr,x)    (((arr) >> ((x)*proc_shift)) & ((1<<proc_shift)-1))
#define proc_str(a)        (proc_names[(a)])
#define proc_isdetach(arr) ((arr) >= proc_sl_d && (arr) <= proc_sl3_d)
#define proc_isattach(arr) ((arr) >= proc_fe   && (arr) <= proc_sl3)
#define proc_samenode(a,b) (((a)&3) == ((b)&3) && \
                            (a) != proc_inv && (b) != proc_inv)

extern char *proc_names[];


#endif

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */

