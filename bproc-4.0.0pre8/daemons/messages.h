#ifndef _MESSAGES_H
#define _MESSAGES_H

/* these message types are only used by the daemons and therefore not
 * included in the kernel headers */

struct bproc_version_msg_t {
    struct bproc_message_hdr_t hdr;

    /* This is a weird message.  When the daemons connect to one
     * another, this is the first message sent.  We want sensible
     * behavior if there's an architecture mismatch so here's a little
     * hack to make this message the compatible between the two
     * architectures.  The issue is that id and result in the header
     * are bigger on 64 bit systems.  Those are ignored for this
     * message so we just used some padding to make sure that the
     * version (which is arch-indepentent) lands in the same spot.
     *
     * FIX ME FIX ME FIX ME:  There are still byte order issues.
     */
#if defined(__i386__) || defined(powerpc)
    long __pad1, __pad2;
#endif
    
    struct bproc_version_t vers;
    uint64_t cookie;
};

struct bproc_ping_msg_t {
    struct bproc_message_hdr_t hdr;
    long time_sec;	   	/* Current time of day... */
    long time_usec;
};

struct bproc_master_t {
    int tag;
    struct sockaddr addr;
};

struct bproc_conf_msg_t {
    struct bproc_message_hdr_t hdr;
    long time_sec;	   	/* Current time of day... */
    long time_usec;

    int ping_timeout;
    int private_namespace;

    /* Information about other masters in the system. */
    int masters;		/* offset to list of masters */
    int masters_size;
};

#endif

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
