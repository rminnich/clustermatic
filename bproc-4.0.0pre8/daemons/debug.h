#ifndef _BPROC_DEBUG_H
#define _BPROC_DEBUG_H

#include "bproc.h"

enum msg_dst {
	BPROC_DEBUG_MSG_TO_KERNEL,
	BPROC_DEBUG_MSG_FROM_KERNEL,
	BPROC_DEBUG_MSG_TO_SLAVE,
	BPROC_DEBUG_MSG_FROM_SLAVE,
	BPROC_DEBUG_MSG_TO_MASTER,
	BPROC_DEBUG_MSG_FROM_MASTER,
	BPROC_DEBUG_OTHER
};

struct debug_hdr_t {
	struct timeval time;
	int tofrom;		/* to/from */
	int node;		/* slave node id in the case of to slave */
	void *connection;	/* connection id for slave nodes */
	/*struct bproc_request_t req; */
};

struct bproc_debug_1000_msg_t {
	struct bproc_message_hdr_t hdr;
	int pid;
	int node;
	int last;
};

struct bproc_debug_1001_msg_t {
	struct bproc_message_hdr_t hdr;
	void *connection;
};

#define bproc_debug_msg(x)  ((void*)((x)+1))

#define SPEW1(extra) do{printf("%s:%d (%s) " extra "\n",__FILE__,__LINE__,__FUNCTION__);}while(0)
#define SPEW2(extra, foo ...) do{printf("%s:%d (%s) " extra "\n",__FILE__,__LINE__,__FUNCTION__, foo);}while(0)

#endif
/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
