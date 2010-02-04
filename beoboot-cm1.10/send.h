/*------------------------------------------------------------ -*- C -*-
 * send: unicast file sending stuff
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
 *  $Id: send.h,v 1.5 2003/03/25 17:18:12 mkdist Exp $
 *--------------------------------------------------------------------*/
#ifndef _SEND_H
#define _SEND_H

/* Defaults */
#define DEFAULT_REQUEST_PORT       4711
#define DEFAULT_SENDER_TIMEOUT  5000000	/* usec */
#define DEFAULT_CONNECT_TIMEOUT 2500000	/* usec */
#define DEFAULT_IO_TIMEOUT      5000000	/* usec */
#define DEFAULT_RETRY           2000000	/* usec */
#define DEFAULT_MAX_TRIES           100

#define MAX_FILE_NAME 127

#define SEND_REQUEST_MAGIC  0xa530595c
#define SEND_RESPONSE_MAGIC 0x167f56a0
#define SEND_DATA_MAGIC     0xea5f67d6

/* Send errors */
#define SEND_ERROR_ENOENT          100

/* This is for the datagram request / response protocol */

#define SEND_DEPTH_NONE 0

struct send_request_t {
	uint32_t magic;		/* client magic to identify the response */
	uint32_t req_magic;	/* magic indicating message type */
	uint32_t depth;		/* My depth */

	uint16_t resend_port;	/* port that I'm ready to resend on */
	char filename[MAX_FILE_NAME + 1];

	/* Report any download failures to the server here */
	uint32_t fail_addr;
	uint16_t fail_port;
};

struct send_response_t {
	uint32_t magic;
	uint32_t req_magic;
	uint32_t status;

	uint32_t depth;		/* This is my "depth" in the tree */

	uint32_t addr;		/* This is where to get the file from */
	uint16_t port;

	/* Configuration tidbits */
	uint32_t sender_timeout;
	uint32_t connect_timeout;
	uint32_t io_timeout;
};

struct send_data_t {
	uint32_t magic;
	uint32_t status;

	uint32_t size;
	uint32_t mode;
	uint32_t user;
	uint32_t group;
};

/* These are for the UDP part of the protocol...  The remaining
 * parameters are provided as part of the UDP response. */
struct recv_arg_t {
	int initial_delay;
	int max_delay;
	float backoff;
	int max_time;
	float rand;
};

#define RECV_INITIAL_DELAY  1000000	/* (usec) 1s   between rarp requests */
#define RECV_MAX_DELAY    100000000	/* (usec) 100s max delay between requests */
#define RECV_BACKOFF            1.2	/* Factor for exponential backoff */
#define RECV_MAX_TIME           600	/* (sec) total maximum time for recv */
#define RECV_RAND               0.1	/* fraction of delay to randomly +/- */

extern int recv_file(struct sockaddr_in *addr, const char *filename,
		     void **buffer, long *len);

#endif

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
