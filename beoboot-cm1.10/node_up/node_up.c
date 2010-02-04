/*------------------------------------------------------------ -*- C -*-
 * nodeup: driver
 * Erik Arjan Hendriks <hendriks@lanl.gov>
 *
 * Copyright(C) 2002 University of California.  LA-CC Number 01-67.
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
 * $Id: node_up.c,v 1.53 2004/11/03 17:13:58 mkdist Exp $
 *--------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>		/* for clone() */
#include <dlfcn.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/bproc.h>

#include "../cmconf.h"

#include "node_up.h"

#define DEFAULT_CONFIG_FILE CONFIGDIR "/node_up.conf"

#define MAX_NODES ((FD_SETSIZE-10)/2)

#define LOG_LINE_SIZE 250
#define SERVER_CONNECT_RETRY_DELAY 1000000	/* usec */

/* Magic values for the RPC function pointer */
#define MSG_LOG  ((void *)0)

/* Node states */
enum node_state {
	NODE_IDLE,		/* waiting for something from child */
	NODE_DATA_IN,		/* reading RPC data from child */
	NODE_RPC_HDR_OUT,	/* returning RPC result to child */
	NODE_RPC_DATA_OUT,	/* returning RPC result to child */
	NODE_LOG_HDR_OUT,	/* forwarding log message to client */
	NODE_LOG_OUT,		/* forwarding log message to client */
	NODE_EXIT_FW,		/* fowarding exit status */
	NODE_DONE		/* node completed */
};

struct node_priv_t {
	struct node_priv_t *next;
	void *data;
	char tag[0];
};

struct req_hdr_t {
	int (*funcp) (void *, int, void **, int *);
	long len;

	struct plugin_t *curr_plugin;	/* This might be nice for the front end */
};

struct resp_hdr_t {
	int retval;
	long len;
};

/* Header for client messages */
struct clnt_hdr_t {
	int type;
	int len;
};

/* There's one of these for every node that we're running node_up for */
struct node_t {
	int node;		/* node number */
	int pid;		/* PID of child process on node */
	int slave_fd;		/* connection to slave node */
	int control_fd;		/* connection to node_up requestor */
	int exit_status;

	enum node_state state;	/* for little front end state machine */

	/* Data buffering stuff */
	union {
		struct req_hdr_t req;
		struct resp_hdr_t resp;
		struct clnt_hdr_t clnt;	/* Header int  */
	} hdr;
	int bptr;		/* buffer pointer for reading/writing */
	void *buffer;

	/* Some stuff to make per-node private data structures easy on the
	 * master */
	struct node_priv_t *plugin_data;
};

#define PLUGIN_IGNORE_FAILURE 1

struct plugin_t {
	struct plugin_t *next;
	int flags;		/* stuff like IGNORE_FAILURE */
	char *name, *desc;
	char **args;
	void *handle;
};

/*--- Globals for the plugins to use -------------------------------*/
struct sockaddr_in nodeup_master;
struct node_t *nodeup_self = 0;
/*--- Globals not for use by the plugins ---------------------------*/
static char *cnffile = DEFAULT_CONFIG_FILE;
static int report_size = 0;
static int set_to_up = 0;
static int client_server_mode = 0;
static int common_exit_status = 0;
static int nodeup_numnodes;
static struct node_t nodes[MAX_NODES];
static char *server_socket_path = "/tmp/.node_up";

static struct node_t *curr_node = 0;
static struct plugin_t *curr_plugin = 0;

int log_level = LOG_DEBUG;
int indent = 0;

static
long read_all(int fd, void *buf, long count)
{
	long r, bytes = count;
	while (bytes) {
		r = read(fd, buf, bytes);
		if (r < 0)
			return r;
		if (r == 0)
			return count - bytes;
		bytes -= r;
		buf += r;
	}
	return count;
}

static
long write_all(int fd, const void *buf, long count)
{
	long r, bytes = count;
	while (bytes) {
		r = write(fd, buf, bytes);
		if (r < 0)
			return r;
		if (r == 0)
			return count - bytes;
		bytes -= r;
		buf += r;
	}
	return count;
}

void **nodeup_private(const char *tag)
{
	struct node_priv_t *p;
	if (!curr_node)
		return 0;

	/* Search for it */
	for (p = curr_node->plugin_data; p; p = p->next) {
		if (strcmp(tag, p->tag) == 0)
			return &p->data;
	}

	/* Allocate new if there isn't one */
	p = malloc(sizeof(*p) + strlen(tag) + 1);
	if (!p) {
		log_print(LOG_ERROR, "Out of memory.\n");
		return 0;
	}

	strcpy(p->tag, tag);
	p->data = 0;
	p->next = curr_node->plugin_data;
	curr_node->plugin_data = p;
	return &p->data;
}

int nodeup_node(void)
{
	struct node_t *node;
	if (nodeup_self)
		return nodeup_self->node;

	node = curr_node;
	if (node)
		return node->node;

	log_print(LOG_FATAL, "nodeup_node called w/o node or nodeup_self\n");
	exit(1);
}

/*------------------------------------------------------------------*/
static
void log_print_slave(int fd, void *data, int len)
{
	struct req_hdr_t hdr = { MSG_LOG, len, curr_plugin };
	if (write_all(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		fprintf(stderr, "Doh 0!\n");
		return;
	}
	if (write_all(fd, data, len) != len) {
		fprintf(stderr, "Doh 2!\n");
		return;
	}
}

static
void log_print_client(struct node_t *n, void *data, int len)
{
	int flags;
	struct clnt_hdr_t hdr = { 0, len };

	/* XXX FIX ME: Blocking writes to nodes are BAD!... but our
	 * buffering scheme doesn't allow us to add a log message mid RPC
	 * right now. */
	flags = fcntl(n->control_fd, F_GETFL);
	flags &= ~O_NONBLOCK;
	fcntl(n->control_fd, F_SETFL, flags);

	/* XXX FIX ME: we're ignoring write errors here... */
	write_all(n->control_fd, &hdr, sizeof(hdr));
	write_all(n->control_fd, data, len);

	flags |= O_NONBLOCK;
	fcntl(n->control_fd, F_SETFL, flags);
}

void log_print(int level, char *fmt, ...)
{
	int len, i;
	char buffer[LOG_LINE_SIZE];
	va_list valist;
	char *prefix;

	va_start(valist, fmt);
	if (level > log_level)
		return;

	/* Figure out what the prefix for this log message will be */
	prefix = curr_plugin ? curr_plugin->name : "nodeup";

	/* Build the log message */
	len = snprintf(buffer, LOG_LINE_SIZE, "%-10s: %*s", prefix, indent, "");
	len += vsnprintf(buffer + len, LOG_LINE_SIZE - len, fmt, valist);

	/* If nodeup_self is set, then we're on a slave node and log
	 * messages shoul dbe sent to the front end. */
	if (nodeup_self) {
		log_print_slave(nodeup_self->slave_fd, buffer, len);
		return;
	}

	if (curr_node) {
		if (curr_node->control_fd != -1)
			log_print_client(curr_node, buffer, len);
		else
			write(STDOUT_FILENO, buffer, len);
		return;
	}

	/* No current node, write this message to all clients or stdout */
	if (client_server_mode) {
		for (i = 0; i < nodeup_numnodes; i++) {
			if (nodes[i].control_fd != -1)
				log_print_client(&nodes[i], buffer, len);
		}
	} else {
		write(STDOUT_FILENO, buffer, len);
	}
}

void console_print(char *fmt, ...)
{
	va_list valist;
	int len;
	char buffer[1024];
	va_start(valist, fmt);
	len = snprintf(buffer, 1024, "%-10s: %*s",
		       curr_plugin ? curr_plugin->name : "nodeup", indent, "");
	len += vsnprintf(buffer + len, 1024 - len, fmt, valist);
	write(STDOUT_FILENO, buffer, len);
	va_end(valist);
}

/*--------------------------------------------------------------------
 *  Code for dealing with the list of plugins
 *------------------------------------------------------------------*/
static struct plugin_t *plugin_list;
static char replace_plugin_path = 1;
static char *plugin_path = 0;
int path_callback(struct cmconf *cnf, char **args)
{
	if (plugin_path && !replace_plugin_path)
		return 0;
	if (plugin_path) {
		log_print(LOG_WARNING, "Warning: replacing plugin path.\n");
		free(plugin_path);
	}
	plugin_path = strdup(args[1]);
	if (!plugin_path) {
		log_print(LOG_FATAL, "Out of memory.\n");
		return -1;
	}
	return 0;
}

static
void *plugin_load(const char *plugin)
{
	void *handle;
	char *mypath, *ptr, *end, tmpfile[PATH_MAX + 1];
	/* Do a path-walk type thing to find the .so file we're looking
	 * for. */
	mypath = plugin[0] == '/' ? 0 : plugin_path;
	if (!mypath)
		mypath = "/";

	ptr = mypath;
	while (*ptr) {
		end = strchr(ptr, ':');
		if (!end)
			end = ptr + strlen(ptr);
		strncpy(tmpfile, ptr, end - ptr);
		tmpfile[end - ptr] = 0;
		strcat(tmpfile, "/");
		strcat(tmpfile, plugin);

		if (access(tmpfile, R_OK | X_OK) == 0)
			break;

		strcat(tmpfile, ".so");	/* try it with another .so on the end */
		if (access(tmpfile, R_OK | X_OK) == 0)
			break;

		/* Advance to next path element */
		ptr = *end ? end + 1 : end;
	}

	handle = dlopen(tmpfile, RTLD_NOW | RTLD_GLOBAL);
	if (!handle) {
		log_print(LOG_ERROR, "Failed to open %s: %s\n", tmpfile,
			  dlerror());
	}
	return handle;
}

static
struct plugin_t *plugin_new(char **args)
{
	/* Add this plugin to our list of plugins */
	struct plugin_t *newp;
	int i;

	if (!(newp = malloc(sizeof(*newp)))) {
		log_print(LOG_FATAL, "Out of memory.\n");
		return 0;
	}

	if (strcmp(args[0], "plugin") != 0)
		args--;

	newp->handle = plugin_load(args[1]);
	if (!newp->handle) {
		free(newp);
		return 0;
	}

	newp->flags = 0;
	newp->name = strdup(args[1]);
	newp->desc = dlsym(newp->handle, "nodeup_desc");
	if (!newp->desc)
		newp->desc = "";

	log_print(LOG_INFO, "  Loaded %s: %s\n", newp->name, newp->desc);

	/* Save module arguments */
	for (i = 1; args[i]; i++) ;	/* count arguments */
	newp->args = malloc(sizeof(char *) * i);
	for (i = 1; args[i]; i++)
		newp->args[i - 1] = strdup(args[i]);
	newp->args[i - 1] = 0;

	/* Stick this on the end of the list */
	newp->next = 0;
	if (!plugin_list)
		plugin_list = newp;
	else {
		struct plugin_t *p;
		for (p = plugin_list; p->next; p = p->next) ;
		p->next = newp;
	}
	return newp;
}

static
int plugin_callback(struct cmconf *cnf, char **args)
{
	struct plugin_t *newp;
	newp = plugin_new(args);
	if (!newp)
		return -1;
	return 0;
}

static struct cmconf_option nodeup_opts[];
static
int failok_callback(struct cmconf *cnf, char **args)
{
	struct plugin_t *newp;
	newp = plugin_new(args + 1);
	if (!newp)
		return -1;
	newp->flags |= PLUGIN_IGNORE_FAILURE;
	return 0;
}

static
struct cmconf_option nodeup_opts[] = {
	{"path", 1, 1, 0, path_callback},
	{"plugin", 1, 101, 1, plugin_callback},
	{"failok", 1, 101, 1, failok_callback},
	{"*", 0, 100, 1, plugin_callback},
	{0,}
};

static
void plugins_load(char *cnffile)
{
	log_print(LOG_INFO, "Loading configuration from: %s\n", cnffile);
	if (cmconf_process_file(cnffile, nodeup_opts)) {
		log_print(LOG_FATAL, "Failed to load config from: %s\n",
			  cnffile);
		exit(1);
	}
}

static
void plugins_runfunc(const char *name)
{
	struct plugin_t *p;
	char funcname[100];
	int argc, retval;
	int (*plugin_func) (int, char **);

	sprintf(funcname, "nodeup_%s", name);

	log_print(LOG_INFO, "Running %s functions\n", name);
	for (p = plugin_list; p; p = p->next) {
		plugin_func = dlsym(p->handle, funcname);
		if (plugin_func) {
			for (argc = 0; p->args[argc]; argc++) ;	/* count args */
			log_print(LOG_INFO, "  Calling %s for %s\n", name,
				  p->name);
			curr_plugin = p;
			optind = 0;	/* Reset getopt for the plugin */
			opterr = 0;
			indent += 4;
			retval = plugin_func(argc, p->args);
			indent -= 4;
			curr_plugin = 0;
			if (retval) {
				if (p->flags & PLUGIN_IGNORE_FAILURE) {
					log_print(LOG_WARNING,
						  "  Plugin %s returned %d (error)\n",
						  p->name, retval);
				} else {
					log_print(LOG_FATAL,
						  "  Plugin %s returned %d (error)\n",
						  p->name, retval);
					exit(1);
				}
			} else {
				log_print(LOG_INFO,
					  "  Plugin %s returned status %d (ok)\n",
					  p->name, retval);
			}

			/* Get rid of the temporary /proc mount if any */
			nodeup_umnt_proc();
		} else {
			log_print(LOG_DEBUG, "  No %s function for %s\n", name,
				  p->name);
		}
	}
}

/*--------------------------------------------------------------------
 *  Socket code
 */
static
int socket_listen(int *port)
{
	int fd, addrsize;
	struct sockaddr_in listen_addr;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		log_print(LOG_FATAL, "socket: %s\n", strerror(errno));
		exit(1);
	}
	listen_addr.sin_family = AF_INET;
	listen_addr.sin_addr.s_addr = INADDR_ANY;
	listen_addr.sin_port = 0;
	if (bind(fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) ==
	    -1) {
		log_print(LOG_FATAL, "bind: %s\n", strerror(errno));
		exit(1);
	}

	if (listen(fd, 1024) == -1) {
		log_print(LOG_FATAL, "listen: %s\n", strerror(errno));
		exit(1);
	}
	addrsize = sizeof(listen_addr);
	getsockname(fd, (struct sockaddr *)&listen_addr, &addrsize);
	*port = ntohs(listen_addr.sin_port);
	return fd;
}

static
int socket_accept(int fd)
{
	struct sockaddr_in sa;
	int sa_size, flags, new_fd, index;
	/*struct timeval tv; */

	sa_size = sizeof(sa);
	new_fd = accept(fd, (struct sockaddr *)&sa, &sa_size);
	if (new_fd == -1) {
		if (errno == EINTR && errno == EAGAIN)
			return -1;
		log_print(LOG_FATAL, "accept: %s\n", strerror(errno));
		exit(1);
	}

	/* Figure out which child this connection goes with and which
	 * connection it is... */
	if (read_all(new_fd, &index, sizeof(index)) != sizeof(index)) {
		log_print(LOG_ERROR, "I/O error talking to child\n");
		close(new_fd);
		return -1;
	}

	/*log_print(LOG_DEBUG, "Received connect with index %d\n", index); */

	if (index < 0 || index >= nodeup_numnodes) {
		log_print(LOG_ERROR, "Received invalid index from child: %d\n",
			  index);
		close(new_fd);
		return -1;
	}

	if (nodes[index].slave_fd != -1) {
		log_print(LOG_ERROR, "Too many connections from child."
			  "  node=%d\n", nodes[index].node);
		close(new_fd);
		return -1;
	}

	nodes[index].slave_fd = new_fd;

	/* XXX FIX ME: Move this up to right after the accept and turn the
	 * whole second half of this function into some part of the select
	 * state machine to avoid blocking. */
	flags = fcntl(new_fd, F_GETFL);
	flags |= O_NONBLOCK;
	fcntl(new_fd, F_SETFL, flags);

	/*log_print(LOG_DEBUG, "Got I/O connect for child %d.  "
	   "fd=%d\n", index, new_fd); */
	return 0;
}

#if 0
static
int socket_connect(int port)
{
	int fd;
	struct sockaddr_in sa;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		log_print(LOG_FATAL, "socket: %s\n", strerror(errno));
		exit(1);
	}

	sa.sin_family = AF_INET;
	sa.sin_addr = nodeup_master.sin_addr;
	sa.sin_port = htons(port);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		console_print(LOG_FATAL, "connect(%s:%d): %s\n",
			      inet_ntoa(sa.sin_addr), (int)ntohs(sa.sin_port),
			      strerror(errno));
		exit(1);
	}

	return fd;
}
#endif

/*--------------------------------------------------------------------
 *  Signal handling goop
 *------------------------------------------------------------------*/

/*--------------------------------------------------------------------
 *--------------------------------------------------------------------
 *  Slave-side code
 *--------------------------------------------------------------------
 *------------------------------------------------------------------*/
int nodeup_rpc(int (*funcp) (void *, int, void **, int *),
	       const void *in_data, int in_size,
	       void **out_data_, int *out_size_)
{
	void *out_data;
	struct req_hdr_t req;
	struct resp_hdr_t resp;

	req.funcp = funcp;
	req.len = in_size;
	req.curr_plugin = curr_plugin;

	if (write_all(nodeup_self->slave_fd, &req, sizeof(req)) != sizeof(req)) {
		console_print("I/O error during nodeup_rpc: write: %s\n",
			      strerror(errno));
		exit(1);
	}

	if (write_all(nodeup_self->slave_fd, in_data, in_size) != in_size) {
		console_print("I/O error during nodeup_rpc: write: %s\n",
			      strerror(errno));
		exit(1);
	}

	if (read_all(nodeup_self->slave_fd, &resp, sizeof(resp)) !=
	    sizeof(resp)) {
		console_print("I/O error during nodeup_rpc: read: %s\n",
			      strerror(errno));
		exit(1);
	}

	out_data = malloc(resp.len);
	if (!out_data) {
		console_print("Out of memory allocating %ld bytes for RPC"
			      " response.\n", resp.len);
		exit(1);
	}

	if (read_all(nodeup_self->slave_fd, out_data, resp.len) != resp.len) {
		console_print("I/O error during nodeup_rpc: read: %s\n",
			      strerror(errno));
		exit(1);
	}

	/* Store the result if the pointers are valid */
	if (out_data_)
		*out_data_ = out_data;
	else
		free(out_data);
	if (out_size_)
		*out_size_ = resp.len;

	return resp.retval;
}

static const char *procmnt = 0;
int nodeup_mnt_proc(const char *path)
{
	if (procmnt) {
		log_print(LOG_ERROR,
			  "nodeup_mnt_proc: procfs already mounted at %s\n",
			  procmnt);
		return -1;
	}

	if (mkdir(path, 0755))
		log_print(LOG_ERROR, "mount(\"%s\"): %s\n", path,
			  strerror(errno));
	if (mount("none", path, "proc", MS_MGC_VAL, 0) == -1) {
		if (errno != EBUSY) {
			log_print(LOG_ERROR, "mount(\"%s\"): %s\n", path,
				  strerror(errno));
			rmdir(path);
			return -1;
		}
	}
	procmnt = path;
	return 0;
}

void nodeup_umnt_proc(void)
{
	if (!procmnt)
		return;

	if (umount(procmnt))
		log_print(LOG_ERROR, "umount(\"%s\"): %s\n", procmnt,
			  strerror(errno));
	rmdir(procmnt);
	procmnt = 0;
}

static
int open_console(void)
{
	int fd;
	/* Try to create /dev/console if it doesn't already exist.  This
	 * allows us to run on a completely blank file system. */

	fd = open("/dev/console", O_RDWR);
	if (fd == -1 && errno == ENOENT) {
		/* try to create the device node and reopen... */
		mkdir("/dev", 0755);
		mknod("/dev/console", S_IFCHR | 0600, 0x501);
		fd = open("/dev/console", O_RDWR);
	}
	return fd;
}

static
int sync_rpc(void *a, int b, void **c, int *d)
{
	return 0;
}

static
int do_slave_side(int port, int idx)
{
	int console, sa_size;
	char hostname[20];
	/*struct timeval tv; */

    /*---- Child -----------------------------------------------*/
	/* NOTE: We can't use log_print() until after nodeup_self is setup. */

	/* Setup own data structures */
	nodeup_self = &nodes[idx];

	/* Open the console - we would just do with the usual vrfork IO
	 * setup stuff but /dev/console will probably not exist before we
	 * get here. */
	console = open_console();
	if (console == -1) {
		/* There's not much we can do here in the way of an error
		 * message - just quit with a recognizable exit status */
		exit(10);
	}
	dup2(console, STDIN_FILENO);
	dup2(console, STDOUT_FILENO);
	dup2(console, STDERR_FILENO);
	if (console > STDERR_FILENO)
		close(console);
	setlinebuf(stdout);

	console_print("****** This is node %d ******\n", nodeup_self->node);

	/* Connect to the front and and:
	 * Do PID/ID exchange to figure out who we are.
	 * Set the time of day */
	/*fd = socket_connect(port); */
	nodeup_self->slave_fd = 3;
	if (write(nodeup_self->slave_fd, &idx, sizeof(idx)) != sizeof(idx)) {
		printf("Write error sending PID to master: %s\n",
		       strerror(errno));
		exit(1);
	}

	/* Ok, our connections are setup - we can start using
	 * log_print again and get output on the front end. */

	/* Make note of the master's address */
	sa_size = sizeof(nodeup_master);
	if (getpeername(nodeup_self->slave_fd,
			(struct sockaddr *)&nodeup_master, &sa_size)) {

		log_print(LOG_ERROR, "Failed to get address of master node.\n");
		nodeup_rpc(sync_rpc, 0, 0, 0, 0);	/* Sync up with the front end */
		exit(1);
	}

	/* Before we do anything to this system - a quick sanity check to
	 * make sure this is a clean system. */
	{
		struct stat buf;
		if (stat("/etc/passwd", &buf) == 0) {
			log_print(LOG_WARNING,
				  "This node appears to have its own root"
				  " file system - exiting.\n");
			nodeup_rpc(sync_rpc, 0, 0, 0, 0);	/* Sync up with the front end */
			exit(0);
		}
	}

	/* Set my host name */
	sprintf(hostname, "n%d", nodeup_self->node);
	if (sethostname(hostname, strlen(hostname))) {
		log_print(LOG_ERROR, "Failed to set hostname to %s: %s\n",
			  hostname, strerror(errno));
	}

	plugins_runfunc("postmove");
	log_print(LOG_INFO, "Node setup completed successfully.\n");

	nodeup_rpc(sync_rpc, 0, 0, 0, 0);	/* Sync up with the front end */
	console_print("Node setup completed successfully.\n");
	return 0;
}

/*--------------------------------------------------------------------
 *  Main I/O loop for the master
 *------------------------------------------------------------------*/
static
void node_exit(struct node_t *node, int status)
{
	int is_boot;
	char nodestatus[BPROC_STATE_LEN + 1];

	node->exit_status = status;
	if (status > common_exit_status)
		common_exit_status = status;
	if (node->slave_fd != -1) {
		close(node->slave_fd);
		node->slave_fd = -1;
	}

	if (node->control_fd != -1) {
		node->state = NODE_EXIT_FW;
		node->hdr.clnt.type = 1;
		node->hdr.clnt.len = node->exit_status;
	} else {
		node->state = NODE_DONE;
	}

	bproc_nodestatus(node->node, nodestatus, sizeof(nodestatus));
	is_boot = (strcmp(nodestatus, "boot") == 0);

	if (status == 0) {
		if (is_boot || set_to_up) {
			bproc_chmod(node->node, 0111);
			bproc_nodesetstatus(node->node, "up");
		}
	} else {
		if (is_boot)
			bproc_nodesetstatus(node->node, "error");
	}
}

static
void kill_child(struct node_t *node)
{
	if (node->pid)
		kill(node->pid, SIGKILL);
	node_exit(node, 99);
}

static
void cleanup_children(void)
{
	int pid, status, i;
	struct node_t *node = 0;

	pid = waitpid(-1, &status, WNOHANG);
	while (pid > 0) {
		/* Find the node this one goes with */
		for (i = 0; i < nodeup_numnodes; i++) {
			if (nodes[i].pid == pid) {
				node = &nodes[i];
				break;
			}
		}
		if (!node) {
			log_print(LOG_ERROR,
				  "Child process %d exited but it doesn't"
				  " seem to belong to any node.\n", pid);
			return;
		}

		node->pid = 0;	/* We no longer have a child for this node */

		/* Worry about this only if we don't have a status yet. */
		if (!WIFEXITED(status)) {
			if (WIFSIGNALED(status)) {
				fprintf(stderr,
					"Child process for node %d died with"
					" signal %d\n", node->node,
					WTERMSIG(status));
				log_print(LOG_FATAL,
					  "Child process for node %d died with"
					  " signal %d\n", node->node,
					  WTERMSIG(status));
				status = 1;
			} else {
				fprintf(stderr,
					"Child process for node %d exited "
					"abnormally.\n", node->node);
				log_print(LOG_FATAL,
					  "Child process for node %d exited "
					  "abnormally.\n", node->node);
				status = 1;
			}
		} else {
			if (WEXITSTATUS(status) != 0) {
				log_print(LOG_FATAL,
					  "Child process for node %d returned "
					  "error %d\n", node->node,
					  WEXITSTATUS(status));
				status = 1;
			} else {
				status = WEXITSTATUS(status);
				/*log_print(LOG_INFO, "slave side for node %d exited with"
				   " status %d\n", node->node, node->exit_status); */
			}
		}
		node_exit(node, status);

		pid = waitpid(-1, &status, WNOHANG);
	}
}

static
void node_serve_rpc(struct node_t *node)
{
	int rval;
	int out_size = 0;
	void *out_data = 0;

	/* node state is set early so that the plugin function can
	 * override it.  This is a hack specifically for EXIT_WAIT... */
	curr_plugin = node->hdr.req.curr_plugin;
	rval = node->hdr.req.funcp(node->buffer, node->hdr.req.len,
				   &out_data, &out_size);
	curr_plugin = 0;
	if (node->buffer)
		free(node->buffer);

	node->state = NODE_RPC_HDR_OUT;
	node->hdr.resp.retval = rval;
	node->hdr.resp.len = out_size;
	node->bptr = 0;
	node->buffer = out_data;
}

static
void node_do_request(struct node_t *node)
{
	switch ((long)node->hdr.req.funcp) {
	case (long)MSG_LOG:
		/* Ignore zero length log messages */
		if (node->hdr.req.len == 0) {
			node->state = NODE_IDLE;
			break;
		}

		if (node->control_fd != -1) {
			node->state = NODE_LOG_HDR_OUT;
			/* Be a little careful in these assignments - hdr is a union */
			node->hdr.clnt.len = node->hdr.req.len;
			node->hdr.clnt.type = 0;
		} else {
			node->state = NODE_IDLE;
			write(STDOUT_FILENO, node->buffer, node->hdr.req.len);
			free(node->buffer);
			node->buffer = 0;
		}
		break;

	default:
		node_serve_rpc(node);
		break;
	}
}

/*--------------------------------------------------------------------
 *  Node I/O code
 */
static
int node_read_bytes(struct node_t *node, void *buf, int len)
{
	int r;
	r = read(node->slave_fd, buf, len);
	if (r == -1 && errno != EAGAIN) {
		log_print(LOG_ERROR, "Read error from node %d: %s\n",
			  node->node, strerror(errno));
		kill_child(node);
	}
	return r;
}

static
int node_write_bytes(struct node_t *node, const void *buf, int len)
{
	int r;
	r = write(node->slave_fd, buf, len);
	if (r == -1 && errno != EAGAIN) {
		log_print(LOG_ERROR, "Write error to node %d: %s\n",
			  node->node, strerror(errno));
		kill_child(node);
	}
	if (r == 0) {		/* XXX can this ever happen? */
		log_print(LOG_ERROR, "Short write to node %d.\n", node->node);
		kill_child(node);
	}
	return r;
}

static
int node_write_bytes_ctrl(struct node_t *node, const void *buf, int len)
{
	int r;
	r = write(node->control_fd, buf, len);
	if (r == -1 && errno != EAGAIN) {
		log_print(LOG_ERROR, "Write error to node %d: %s\n",
			  node->node, strerror(errno));
		close(node->control_fd);
		node->control_fd = -1;
		kill_child(node);
	}
	if (r == 0) {		/* XXX can this ever happen? */
		log_print(LOG_ERROR, "Short write to node %d.\n", node->node);
		close(node->control_fd);
		node->control_fd = -1;
		kill_child(node);
	}
	return r;
}

static
void node_read(struct node_t *node)
{
	int r;

	switch (node->state) {
	case NODE_IDLE:
		r = node_read_bytes(node, ((void *)&node->hdr) + node->bptr,
				    sizeof(node->hdr) - node->bptr);
		if (r == 0) {
			/* EOF from node - this is ok as long as the next thing
			 * the node does is exit :) */
			close(node->slave_fd);
			node->slave_fd = -1;
		}
		if (r <= 0)
			return;
		node->bptr += r;
		if (node->bptr == sizeof(node->hdr)) {
			node->bptr = 0;
			if (node->hdr.req.len > 0) {
				node->state = NODE_DATA_IN;
				node->buffer = malloc(node->hdr.req.len);
				if (!node->buffer) {
					log_print(LOG_ERROR,
						  "Failed to allocate %ld bytes for"
						  " client RPC.\n",
						  node->hdr.req.len);
					kill_child(node);
				}
			} else {
				/* Things in here will set the appropriate node state */
				node_do_request(node);
			}
		}
		break;
	case NODE_DATA_IN:
		r = node_read_bytes(node, node->buffer + node->bptr,
				    node->hdr.req.len - node->bptr);
		if (r == 0) {
			/* EOF from node - this is bad since we were expecting more */
			log_print(LOG_ERROR, "Short read from node %d.\n",
				  node->node);
			kill_child(node);
		}
		if (r <= 0)
			return;
		node->bptr += r;
		if (node->bptr == node->hdr.req.len) {
			node->bptr = 0;
			node_do_request(node);
		}
		break;
	case NODE_RPC_HDR_OUT:
		abort();	/* SHOULD NEVER HAPPEN */
	case NODE_RPC_DATA_OUT:
		abort();	/* SHOULD NEVER HAPPEN */
	case NODE_LOG_HDR_OUT:
		abort();	/* SHOULD NEVER HAPPEN */
	case NODE_LOG_OUT:
		abort();	/* SHOULD NEVER HAPPEN */
	case NODE_EXIT_FW:
		abort();	/* SHOULD NEVER HAPPEN */
	case NODE_DONE:
		abort();	/* SHOULD NEVER HAPPEN */
	}
}

static
void node_write(struct node_t *node)
{
	int r;
	switch (node->state) {
	case NODE_IDLE:
		abort();	/* SHOULD NEVER HAPPEN */
	case NODE_DATA_IN:
		abort();	/* SHOULD NEVER HAPPEN */
	case NODE_RPC_HDR_OUT:
		r = node_write_bytes(node,
				     ((void *)&node->hdr.resp) + node->bptr,
				     sizeof(node->hdr.resp) - node->bptr);
		if (r <= 0)
			break;
		node->bptr += r;
		if (node->bptr == sizeof(node->hdr.resp)) {
			node->bptr = 0;
			node->state =
			    node->hdr.resp.len ? NODE_RPC_DATA_OUT : NODE_IDLE;
		}
		break;
	case NODE_RPC_DATA_OUT:
		r = node_write_bytes(node, node->buffer + node->bptr,
				     node->hdr.resp.len - node->bptr);
		if (r <= 0)
			break;
		node->bptr += r;
		if (node->bptr == node->hdr.resp.len) {
			node->bptr = 0;
			node->state = NODE_IDLE;

			free(node->buffer);
			node->buffer = 0;
		}
		break;
	case NODE_LOG_HDR_OUT:
		r = node_write_bytes_ctrl(node,
					  ((void *)&node->hdr.clnt) +
					  node->bptr,
					  sizeof(node->hdr.clnt) - node->bptr);
		if (r <= 0)
			break;
		node->bptr += r;
		if (node->bptr == sizeof(node->hdr.clnt)) {
			node->bptr = 0;
			if (node->hdr.req.len > 0)
				node->state = NODE_LOG_OUT;
			else
				node->state = NODE_IDLE;
		}
		break;
	case NODE_LOG_OUT:
		r = node_write_bytes_ctrl(node, node->buffer + node->bptr,
					  node->hdr.clnt.len - node->bptr);
		if (r <= 0)
			break;
		node->bptr += r;
		if (node->bptr == node->hdr.clnt.len) {
			node->bptr = 0;
			node->state = NODE_IDLE;

			free(node->buffer);
			node->buffer = 0;
		}
		break;
	case NODE_EXIT_FW:
		r = node_write_bytes_ctrl(node,
					  ((void *)&node->hdr.clnt) +
					  node->bptr,
					  sizeof(node->hdr.clnt) - node->bptr);
		if (r <= 0)
			break;
		node->bptr += r;
		if (node->bptr == sizeof(node->hdr.clnt)) {
			node->bptr = 0;
			node->state = NODE_DONE;
			close(node->control_fd);
			node->control_fd = -1;
		}
		break;
	case NODE_DONE:
		abort();	/* SHOULD NEVER HAPPEN */
	}
}

/* This is a hack to deal with the fact that pselect isn't implemented
 * on linux */
static struct timeval select_tmo;
static
void signal_handler(void)
{
	/* This is an ugly hack to get out of select since pselect isn't
	 * implemented on linux */
	select_tmo.tv_sec = select_tmo.tv_usec = 0;
}

#define add_fd(x,fdset) \
do { \
    if ((x) != -1) { \
	if ((x) > maxfd) maxfd = (x); \
	FD_SET((x), (fdset)); \
    } \
} while(0);
#define check_fd(x,fdset) ((x) != -1 && FD_ISSET((x),(fdset)))
static
int master_request_loop(int listen_fd)
{
	int r, maxfd, i;
	fd_set rset, wset;
	sigset_t sset;
	int children_left;
	struct node_t *node;

	sigemptyset(&sset);
	sigaddset(&sset, SIGCHLD);

	/* Check if we still have any nodes working */
	children_left = 0;
	for (i = 0; i < nodeup_numnodes; i++) {
		if (nodes[i].state != NODE_DONE) {
			children_left = 1;
			break;
		}
	}

	while (children_left) {
		FD_ZERO(&rset);
		FD_ZERO(&wset);
		select_tmo.tv_sec = 10;
		select_tmo.tv_usec = 0;

		maxfd = listen_fd;	/* Always listen for new connections */
		FD_SET(listen_fd, &rset);

		/* Wait for new requests from everybody who has no worker right now */
		for (i = 0; i < nodeup_numnodes; i++) {
			node = &nodes[i];

			switch (node->state) {
			case NODE_IDLE:
			case NODE_DATA_IN:
				add_fd(node->slave_fd, &rset);
				break;
			case NODE_RPC_HDR_OUT:
			case NODE_RPC_DATA_OUT:
				add_fd(node->slave_fd, &wset);
				break;
			case NODE_LOG_HDR_OUT:
			case NODE_LOG_OUT:
			case NODE_EXIT_FW:
				add_fd(node->control_fd, &wset);
				break;
			case NODE_DONE:
				/* Do nothing */
				break;
			}
		}

		/* This is the little window where we worry about things like
		 * children who complete their work. */
		sigprocmask(SIG_UNBLOCK, &sset, 0);
		r = select(maxfd + 1, &rset, &wset, 0, &select_tmo);
		if (r == -1 && errno != EINTR) {
			log_print(LOG_ERROR, "select: %s\n", strerror(errno));
			abort();
		}
		sigprocmask(SIG_BLOCK, &sset, 0);

		/* Clean up child processes ... */
		cleanup_children();

		if (r > 0) {
			for (i = 0; i < nodeup_numnodes; i++) {
				curr_node = &nodes[i];
				if (check_fd(curr_node->slave_fd, &rset))
					node_read(curr_node);
				if (check_fd(curr_node->slave_fd, &wset) ||
				    check_fd(curr_node->control_fd, &wset))
					node_write(curr_node);
			}
			if (FD_ISSET(listen_fd, &rset))	/* Accept new connection */
				socket_accept(listen_fd);
		}

		/* Check if we still have any nodes working */
		children_left = 0;
		for (i = 0; i < nodeup_numnodes; i++) {
			if (nodes[i].state != NODE_DONE) {
				children_left = 1;
				break;
			}
		}
	}
	return 0;
}

/*------------------------------------------------------------------*/
void module_info(int argc, char **argv)
{
	int i;
	void *h;
	char *desc, *info;

	/* HACK to get the configfile (and therefore the default plugin
	 * path) loaded.  I try not to trip on errors too much here. */
	nodeup_opts[1].tag = 0;
	cmconf_process_file(cnffile, nodeup_opts);

	/* report_info - Print information about the modules named on the
	 * command line. */
	for (i = optind; i < argc; i++) {
		h = plugin_load(argv[i]);
		if (!h)
			exit(1);
		desc = dlsym(h, "nodeup_desc");
		info = dlsym(h, "nodeup_info");

		if (desc)
			printf("%s: %s\n", argv[i], desc);
		if (info)
			fputs(info, stdout);
	}
}

int node_setup(void)
{
	int r, i, fd, port;
	sigset_t sset;
	struct sigaction sa;
	int *nodeup_nodes;	/* this gets fed in to vrfork */
	int *nodeup_pids;	/* this gets fed in to vrfork */
	struct bproc_io_t io;

	if (nodeup_numnodes == 0) {
		log_print(LOG_ERROR, "No nodes.\n");
		exit(1);
	}
	chdir("/");
	umask(0);

	/*log_print(LOG_INFO, "Running nodeup for node %d\n", nodeup_node); */
	plugins_load(cnffile);	/* We get the configuration at this point */
	plugins_runfunc("premove");

	fd = socket_listen(&port);

	log_print(LOG_INFO, "Starting %d child processes.\n", nodeup_numnodes);

	if (report_size) {
		int nullfd;
		long size;
		if ((nullfd = open("/dev/null", O_WRONLY)) == -1) {
			perror("/dev/null");
			exit(1);
		}
		size = bproc_dump(nullfd, BPROC_DUMP_ALL);
		log_print(LOG_INFO, "dump size (all): %ld\n", size);
		close(nullfd);
	}

	/* Setup our signal situation
	 * We get SIGCHLD when our remote workers exit
	 *
	 * Both signals are blocked except when we're going to do some
	 * blocking I/O.
	 */
	sigemptyset(&sset);
	sigaddset(&sset, SIGCHLD);
	sigprocmask(SIG_BLOCK, &sset, 0);

	/* Setup signal handlers so that signals will bounce us out of
	 * system calls. */
	sa.sa_handler = (void (*)(int))signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGCHLD, &sa, 0);

	/* Also... don't explode on writing down dead sockets */
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGPIPE, &sa, 0);

	/* Bleah... nodeup_pids is both the input and the output for
	 * vrfork so we copy the node list into it here. */
	nodeup_nodes = malloc(sizeof(int) * nodeup_numnodes);
	if (!nodeup_nodes) {
		fprintf(stderr, "Out of memory.\n");
		exit(1);
	}
	nodeup_pids = malloc(sizeof(int) * nodeup_numnodes);
	if (!nodeup_pids) {
		fprintf(stderr, "Out of memory.\n");
		exit(1);
	}
	for (i = 0; i < nodeup_numnodes; i++) {
		nodeup_nodes[i] = nodes[i].node;
		nodeup_pids[i] = 0;
	}

	io.fd = 3;
	io.type = BPROC_IO_SOCKET;
	io.flags = BPROC_IO_DELAY;
	((struct sockaddr_in *)&io.d.addr)->sin_family = AF_INET;
	((struct sockaddr_in *)&io.d.addr)->sin_addr.s_addr = 0;
	((struct sockaddr_in *)&io.d.addr)->sin_port = htons(port);
	r = _bproc_vrfork_io(nodeup_numnodes, nodeup_nodes, nodeup_pids,
			     &io, 1, BPROC_DUMP_ALL);
	if (r == -1) {
		log_print(LOG_FATAL, "bproc_rfork failed: %s\n",
			  strerror(errno));
		exit(1);
	}
	if (r >= 0 && r != nodeup_numnodes) {
		free(nodeup_nodes);
		free(nodeup_pids);

		exit(do_slave_side(port, r));
	}

    /*---- Parent --------------------------------------------------*/
	log_print(LOG_INFO, "Finished creating child processes.\n");
	for (i = 0; i < nodeup_numnodes; i++) {
		struct node_t *n = &nodes[i];
		if (nodeup_pids[i] <= 0) {
			log_print(LOG_ERROR, "Failed to create child process on"
				  " node %d: %s\n", nodes[i].node,
				  bproc_strerror(nodeup_pids[i]));
			node_exit(n, 99);
		} else {
			n->pid = nodeup_pids[i];
		}
	}

	free(nodeup_nodes);
	free(nodeup_pids);
	master_request_loop(fd);
	return 0;
}

static
void init_nodes(void)
{
	int i;

	nodeup_numnodes = 0;
	for (i = 0; i < MAX_NODES; i++) {
		nodes[i].slave_fd = -1;
		nodes[i].control_fd = -1;

		nodes[i].exit_status = -1;
		nodes[i].state = NODE_IDLE;

		/* Data buffering/forwarding crud */
		nodes[i].bptr = 0;
		nodes[i].buffer = 0;

		nodes[i].plugin_data = 0;
	}
}

/*--------------------------------------------------------------------
 *  This is the client side which simply contacts a server via a UNIX
 *  domain socket to do the node setup.
 *------------------------------------------------------------------*/
static
int node_setup_client(int node) __attribute__ ((noreturn));
static
int node_setup_client(int node)
{
	int fd, r, try = 1;
	void *data;
	struct sockaddr_un addr;
	struct clnt_hdr_t hdr;

	log_print(LOG_INFO, "Running node_up client for node %d.\n", node);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		perror("socket(AF_UNIX,SOCK_STREAM,0);");
		exit(1);
	}

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, server_socket_path);

	/* Retry connects for a while in case the server is over loaded or
	 * not running right this instant. */

	r = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	while (r == -1 && try < 30) {
		try++;
		log_print(LOG_ERROR, "connect(\"%s\"): %s  (retrying)\n",
			  server_socket_path, strerror(errno));
		usleep(SERVER_CONNECT_RETRY_DELAY);
		r = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	}
	if (r == -1) {
		log_print(LOG_ERROR, "connect(\"%s\"): %s\n",
			  server_socket_path, strerror(errno));

		log_print(LOG_WARNING,
			  "Falling back to stand-alone setup mode.\n");
		init_nodes();
		nodeup_numnodes = 1;
		nodes[0].node = node;
		exit(node_setup());
	}

	if (write_all(fd, &node, sizeof(node)) != sizeof(node)) {
		log_print(LOG_ERROR,
			  "Error sending node number to setup server.\n");
		exit(1);
	}

	/* Now we sit in a loop waiting for log messages from the remote side. */
	if (read_all(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		log_print(LOG_ERROR, "Error reading log message from node"
			  " setup server.\n");
		exit(1);
	}
	while (hdr.type == 0) {
		data = malloc(hdr.len);
		if (!data) {
			log_print(LOG_FATAL, "Out of memory.\n");
			exit(1);
		}
		if (read_all(fd, data, hdr.len) != hdr.len) {
			log_print(LOG_ERROR,
				  "Error reading log message from node"
				  " setup server.\n");
			exit(1);
		}
		write(STDOUT_FILENO, data, hdr.len);
		free(data);
		if (read_all(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
			log_print(LOG_ERROR,
				  "Error reading log message from node"
				  " setup server.\n");
			exit(1);
		}
	}
#if 0
	/* End of log stream - get the exit status */
	if (read_all(fd, &status, sizeof(status)) != sizeof(status)) {
		log_print(LOG_ERROR,
			  "Error reading status from setup server.\n");
		exit(1);
	}
#endif
	log_print(LOG_INFO, "Node setup returned status %d\n", hdr.len);
	exit(hdr.len);
}

/*------------------------------------------------------------------*/
static
void usage(char *arg0)
{
	printf("Usage: %s nodenumber           (client mode)\n"
	       "       %s -s nodenumbers ...   (stand-alone setup mode)\n"
	       "       %s -i modules ...       (module information)\n"
	       "\n"
	       "       -h       Display this message and exit.\n"
	       "       -V       Display version information and exit.\n"
	       "       -p path  Override the plugin path in the configuration file.\n"
	       "       -C file  Load configuration from file.\n"
	       "                default=%s\n"
	       "       -S       Report process size before migration.\n"
	       "       -s       Stand-alone mode.\n"
	       "       -i       Print usage information for the modules named on the\n"
	       "                command line.\n"
	       "       -u       Set node state to up, ---x--x--x  upon successful\n"
	       "                completion.\n"
	       "       -l level Set the log level to level.\n", arg0, arg0,
	       arg0, DEFAULT_CONFIG_FILE);
}

int main(int argc, char *argv[])
{
	int c, i, node;
	char *check;
	int report_info = 0;
	int stand_alone = 0;
	int config_changed = 0;
	int flags;

	while ((c = getopt(argc, argv, "hVC:Sp:isful:")) != -1) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			exit(0);
		case 'V':
			printf("nodeup version %s\n", PACKAGE_VERSION);
			exit(0);
		case 'C':
			cnffile = optarg;
			config_changed = 1;
			break;
		case 'S':
			report_size = 1;
			break;
		case 'p':
			replace_plugin_path = 0;
			plugin_path = optarg;
			break;
		case 'i':
			report_info = 1;
			break;
		case 's':
			stand_alone = 1;
			break;
		case 'f':
			client_server_mode = 1;
			break;
		case 'u':
			set_to_up = 1;
			break;
		case 'l':
			log_level = strtol(optarg, &check, 0);
			if (*check) {
				fprintf(stderr, "Invalid log level: %s\n",
					optarg);
				exit(1);
			}
			break;
		default:
			exit(1);
		}
	}

	if (report_info) {
		module_info(argc, argv);
		exit(0);
	}

	if ((config_changed || report_size) && stand_alone) {
		log_print(LOG_FATAL, "-C and -S only work with -s.\n");
		exit(1);
	}

	if (geteuid()) {
		log_print(LOG_FATAL, "nodeup requires root privilege.\n");
		exit(1);
	}

	if (client_server_mode) {
		init_nodes();

		nodeup_numnodes = argc - optind;
		for (i = 0; i < nodeup_numnodes; i++) {
			nodes[i].control_fd =
			    strtol(argv[i + optind], &check, 0);
			if (*check || nodes[i].control_fd < 0) {
				fprintf(stderr, "Invalid file descriptor: %s\n",
					argv[i + optind]);
				exit(1);
			}
			/* Read the node number from the client */
			if (read_all(nodes[i].control_fd, &nodes[i].node,
				     sizeof(nodes[i].node)) !=
			    sizeof(nodes[i].node)) {
				fprintf(stderr,
					"Error reading node number from client\n");
				/* XXX We should really recover here */
				exit(1);
			}

			/* Turn on NONBLOCKING mode */
			flags = fcntl(nodes[i].control_fd, F_GETFL);
			flags |= O_NONBLOCK;
			fcntl(nodes[i].control_fd, F_SETFL, flags);
		}
		node_setup();
		exit(common_exit_status);
	}

	if (stand_alone) {
		init_nodes();

		nodeup_numnodes = argc - optind;
		for (i = 0; i < nodeup_numnodes; i++) {
			nodes[i].node = strtol(argv[i + optind], &check, 0);
			if (*check || nodes[i].node < 0) {
				fprintf(stderr, "Invalid node number: %s\n",
					argv[i + optind]);
				exit(1);
			}
			/* Log messages go to the console */
			nodes[i].control_fd = -1;
		}
		node_setup();
		exit(common_exit_status);
	}

	/* Client mode */
	if (argc - optind != 1) {
		usage(argv[0]);
		exit(0);
	}
	node = strtol(argv[optind], &check, 0);
	if (*check || node < 0) {
		fprintf(stderr, "Invalid node number: %s\n", argv[optind]);
		exit(1);
	}
	node_setup_client(node);
	/* XXX NOT REACHED */
}

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
