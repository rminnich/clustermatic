/* nss module for BProc
 *
 * Written 19^H^H2000 by Daniel Ridge in support of:
 *   Scyld Computing Corporation.
 *
 * The author may be reached as newt@scyld.com or C/O
 *   Scyld Computing Corporation
 *   410 Severn Ave, Suite 210
 *   Annapolis, MD 21403
 *
 * Copyright (C) 2000 Scyld Computing Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <nss.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/bproc.h>

#include <arpa/inet.h>

#include "nss_bproc.h"

static void *buffer_alloc(void **buffer,int *size,int req);
static enum nss_status bproc_gethostbynode_r(int node, struct hostent *host, char *buffer, size_t buflen, int *errnop, int *h_errnop);

enum nss_status _nss_bproc_gethostbyname_r(const char *name, struct hostent *host, char *buf, int buflen, int *errnop, int *h_errnop);
enum nss_status _nss_bproc_gethostbyaddr_r(const char *addr, int addrlen, int type, struct hostent *host, char *buffer, size_t buflen, int *errnop, int *h_errnop);
enum nss_status _nss_bproc_getpwuid_r(uid_t uid, struct passwd *pwd, char *buffer, size_t buflen, int *errnop);
enum nss_status _nss_bproc_getpwnam_r(const char *name, struct passwd *pwd, char *buffer, size_t buflen, int *errnop);

/* allocate a set of bytes from a user provided buffer */
static void *
buffer_alloc(void **buffer,int *size,int req)
{
void *result;

	if(!buffer || !*buffer)
		return NULL;
	if(!size || !*size)
		return NULL;

	/* Make sure "buffer" is long aligned */
	if (((long)(*buffer)) & (sizeof(long)-1)) {
		*buffer += sizeof(long) - ((long)(*buffer)&(sizeof(long)-1));
		*size   -= sizeof(long) - ((long)(*buffer)&(sizeof(long)-1));
	}

	if(req>*size || req<0)
		result=NULL;
	else {
		result=*buffer;
		*buffer+=req;
		*size-=req;
		return result;
	}

	return result;
}

/* Helper routine that turns a node structure into a hostent. Should this
 * routine migrate into the bproc library?
 */
static enum nss_status
bproc_gethostbynode_r(int node, struct hostent *host, char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
struct sockaddr_in sin;
int local_buflen=buflen,size;
void *local_buffer=buffer;
char node_name[16];
void *name_buffer,*addr_buffer,*addr_list_buffer,*alias_list_buffer;
int retval;

	sprintf(node_name,"n%d",node);
	if(!(name_buffer=buffer_alloc(&local_buffer,&local_buflen,strlen(node_name)+1)))
	{
		*errnop=ENOMEM;
		return NSS_STATUS_UNAVAIL;
	}
	if(!(addr_buffer=buffer_alloc(&local_buffer,&local_buflen,sizeof(sin))))
	{
		*errnop=ENOMEM;
		return NSS_STATUS_UNAVAIL;
	}
	if(!(addr_list_buffer=buffer_alloc(&local_buffer,&local_buflen,2*sizeof(char *))))
	{
		*errnop=ENOMEM;
		return NSS_STATUS_UNAVAIL;
	}
	if (!(alias_list_buffer=buffer_alloc(&local_buffer, &local_buflen,sizeof(void*))))
	{
		*errnop=ENOMEM;
		return NSS_STATUS_UNAVAIL;
	}

	size=sizeof(struct sockaddr_in);
	retval=bproc_nodeaddr(node,(struct sockaddr *)&sin,&size);
	if(retval==-1)
	{
		/* This will allow us to support self and master while down */
		if(node==BPROC_NODE_MASTER || node==BPROC_NODE_SELF)
		{
			sin.sin_family=AF_INET;		
			inet_aton("127.0.0.1",&sin.sin_addr);
		} else {
			*errnop=EINVAL;	
			return NSS_STATUS_UNAVAIL;
		}
	}

	memcpy(name_buffer,node_name,strlen(node_name)+1);
	host->h_name=name_buffer;
	
	host->h_aliases=alias_list_buffer;
	host->h_aliases[0]=NULL;
	host->h_addrtype=AF_INET;
	host->h_length=4;

	host->h_addr_list=(char **)addr_list_buffer;
	host->h_addr_list[0]=addr_buffer;

	memcpy(host->h_addr_list[0],(char *)&(sin.sin_addr.s_addr),4);
	host->h_addr_list[1]=NULL;	

	*errnop=0;
	return NSS_STATUS_SUCCESS;
}

int
getnodenum(int *node, char *s)
{
	int sign = 1;
	int val = 0;

	if (*s++ != 'n')
		return -1;

	if (*s == '-') {
		sign = -1;
		s++;
	}

	while (isdigit(*s)) {
		val *= 10;
		val += *s - '0';
		s++;
	}

	if (*s != '\0')
		return -1;

	*node = sign * val;

	return 0;
}

/* per gethostbyname.
 * Accepts '.' prefixed names.
 * Accepts 'master' and 'self' as aliases for nodes -1,-2
 */
enum nss_status _nss_bproc_gethostbyname_r(const char *name, struct hostent *host, char *buffer, int buflen, int *errnop, int *h_errnop)
{
	int node;

	if(!host)
		return NSS_STATUS_UNAVAIL;

	if(!name)
		return NSS_STATUS_UNAVAIL;

	*errnop=0;

	if (strcmp(name, "master") == 0)
		node = BPROC_NODE_MASTER;
	else if (strcmp(name, "self") == 0)
		node = BPROC_NODE_SELF;
	else if (getnodenum(&node, (char *)name) < 0)
		return NSS_STATUS_NOTFOUND;

	return bproc_gethostbynode_r(node,host,buffer,buflen,errnop,h_errnop);
}

/*
 * For glibc2
 */
enum nss_status _nss_bproc_gethostbyname2_r(const char *name, int af, struct hostent *host, char *buffer, int buflen, int *errnop, int *h_errnop)
{
	if (af != AF_INET)
		return NSS_STATUS_UNAVAIL;

	return _nss_bproc_gethostbyname_r(name, host, buffer, buflen, errnop, h_errnop);
}

int
checkaddr(int node, struct sockaddr_in *sin)
{
	int size;
	int retval;
	struct sockaddr_in nsin;

	size = sizeof(nsin);
	retval=bproc_nodeaddr(node,(struct sockaddr *)&nsin,&size);
	if (retval != -1)
		return memcmp(&sin->sin_addr, &nsin.sin_addr, sizeof(struct in_addr)) == 0;

	return 0;
}

/* per gethostbyaddr */
enum nss_status
_nss_bproc_gethostbyaddr_r(const char *addr, int addrlen, int type, struct hostent *host, char *buffer, size_t buflen, int *errnop, int *h_errnop)
{
	int n;
	int i;
	int node;
	enum nss_status res;
	struct in_addr lb;
	struct sockaddr_in sin;
	struct bproc_node_set_t ns;

	*errnop=0;

	if(type!=AF_INET)
		return NSS_STATUS_UNAVAIL;

	if(addrlen < sizeof(sin.sin_addr.s_addr))
		return NSS_STATUS_UNAVAIL;

	sin.sin_family=type;
	memcpy(&(sin.sin_addr.s_addr),addr,sizeof(sin.sin_addr.s_addr));

	/* check self */
	node = bproc_currnode();

	/* check loopback */
	inet_aton("127.0.0.1", &lb);
	if (memcmp(&sin.sin_addr, &lb, sizeof(struct in_addr)) == 0)
		return bproc_gethostbynode_r(node,host,buffer,buflen,errnop,h_errnop);

	if (node >= 0 && checkaddr(node, &sin))
		return bproc_gethostbynode_r(node,host,buffer,buflen,errnop,h_errnop);

	/* check master */
	if (checkaddr(BPROC_NODE_MASTER, &sin))
		return bproc_gethostbynode_r(BPROC_NODE_MASTER,host,buffer,buflen,errnop,h_errnop);

	/* check loopback */

	if (node != BPROC_NODE_MASTER)
		return NSS_STATUS_NOTFOUND;

	/*
	 * we're on master, so check all nodes
	 */
	if ((n = bproc_nodelist(&ns)) < 0)
		return NSS_STATUS_NOTFOUND;

	for (i = 0; i < n; i++) {
		if (checkaddr(ns.node[i].node, &sin)) {
			res = bproc_gethostbynode_r(ns.node[i].node,host,buffer,buflen,errnop,h_errnop);
			bproc_nodeset_free(&ns);
			return res;
		}
	}

	bproc_nodeset_free(&ns);

	return NSS_STATUS_NOTFOUND;
}

/* per getpwuid.
 * Answers only for the current user.
 * Answers only on remote nodes.
 * Constructs a response based on environment variables.
 */
enum nss_status
_nss_bproc_getpwuid_r(uid_t uid, struct passwd *pwd, char *buffer, size_t buflen, int *errnop)
{
int local_buflen=buflen;
void *local_buffer=buffer;
char *pw_name;
char *pw_dir;
char *pw_shell;
char *gecos_buffer;

	/* This check probably isn't necessary */
	if(!errnop)
		return NSS_STATUS_UNAVAIL;

	/* This check probably is... */
	if(!buffer || !pwd)
	{
		*errnop=EINVAL;
		return NSS_STATUS_UNAVAIL;
	}

	/* only respond for myself */
	if(uid!=getuid())
	{
		*errnop=ENOSYS;
		return NSS_STATUS_NOTFOUND;
	}

#ifdef SOMETHING_TO_THINK_ABOUT
	/* only respond on remote nodes */
	if(bproc_currnode()==-1)
	{
		*errnop=ENOTSUP;
		return NSS_STATUS_UNAVAIL;
	}
#endif

	pw_name=getenv("USER");
	pw_dir=getenv("HOME");
	pw_shell=getenv("SHELL");
	if(!pw_dir)
	{
		*errnop=ENOENT;
		return NSS_STATUS_UNAVAIL;
	}

	if(!(gecos_buffer=buffer_alloc(&local_buffer,&local_buflen,1)))
	{
		*errnop=EMSGSIZE;
		return NSS_STATUS_UNAVAIL;
	}
	*gecos_buffer=0;

	memset(pwd,0,sizeof(struct passwd));
	
	pwd->pw_name=pw_name;
	pwd->pw_passwd=gecos_buffer;
	pwd->pw_uid=uid;
	pwd->pw_gid=getgid();
	pwd->pw_gecos=gecos_buffer;
	pwd->pw_dir=pw_dir;
	pwd->pw_shell=pw_shell;

	*errnop=0;
	return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_bproc_getpwnam_r(const char *name, struct passwd *pwd, char *buffer, size_t buflen, int *errnop)
{
int local_buflen=buflen;
void *local_buffer=buffer;
char *pw_name;
char *pw_dir;
char *pw_shell;
char *gecos_buffer;

	/* This check probably isn't necessary */
	if(!errnop)
		return NSS_STATUS_UNAVAIL;

	/* This check probably is... */
	if(!buffer || !pwd)
	{
		*errnop=EINVAL;
		return NSS_STATUS_UNAVAIL;
	}

	pw_name=getenv("USER");
	if(!pw_name)
	{
		*errnop=ENOSYS;
		return NSS_STATUS_NOTFOUND;
	}

	/* only respond for myself */
	if(strcmp(pw_name,name))
	{
		*errnop=ENOSYS;
		return NSS_STATUS_NOTFOUND;
	}

#ifdef SOMETHING_TO_THINK_ABOUT
	/* only respond on remote nodes */
	if(bproc_currnode()==-1)
	{
		*errnop=ENOTSUP;
		return NSS_STATUS_UNAVAIL;
	}
#endif

	pw_dir=getenv("HOME");
	pw_shell=getenv("SHELL");
	if(!pw_dir)
	{
		*errnop=ENOENT;
		return NSS_STATUS_UNAVAIL;
	}

	if(!(gecos_buffer=buffer_alloc(&local_buffer,&local_buflen,1)))
	{
		*errnop=EMSGSIZE;
		return NSS_STATUS_UNAVAIL;
	}
	*gecos_buffer=0;

	memset(pwd,0,sizeof(struct passwd));
	
	pwd->pw_name=pw_name;
	pwd->pw_passwd=gecos_buffer;
	pwd->pw_uid=getuid();
	pwd->pw_gid=getgid();
	pwd->pw_gecos=gecos_buffer;
	pwd->pw_dir=pw_dir;
	pwd->pw_shell=pw_shell;

	*errnop=0;
	return NSS_STATUS_SUCCESS;
}
