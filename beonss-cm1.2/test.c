#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <nss.h>
#include <netdb.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "nss_bproc.h"

int test_getpwuid(void);
int test_getpwnam(void);
int test_gethostbyname(void);

int
main(int argc, char **argv)
{
	test_getpwuid();
	test_getpwnam();
	test_gethostbyname();
		
	return 0;
}

int
test_getpwuid()
{
uid_t uid;
struct passwd *passwd;
struct passwd nss_passwd;
unsigned char nss_buffer[1024];
int nss_errno;
int retval;
	
	printf("beonss tester\n");
	fflush(stdout);

	uid=getuid();

	printf("My uid is %d\n",uid);
	passwd=getpwuid(uid);
	printf("My passwd uid is %d\n",passwd->pw_uid);
	printf("My passwd name is %s\n",passwd->pw_name);

	retval=_nss_bproc_getpwuid_r(uid,&nss_passwd,nss_buffer,1024,&nss_errno);
	if(retval!=NSS_STATUS_SUCCESS)
	{
		printf("bproc getpwuid failed: ");
		if(retval==NSS_STATUS_NOTFOUND)
			printf("not found\n");
		else if(retval==NSS_STATUS_UNAVAIL)
			printf("unavailable: %s\n",strerror(nss_errno));
		else
			printf("unknown\n");
		exit(1);
	} else { 
		printf("My passwd uid is %d\n",nss_passwd.pw_uid);
		printf("My passwd name is %s\n",nss_passwd.pw_name);	
	}

	if(passwd->pw_uid == nss_passwd.pw_uid)
		printf("getpwuid: uid test PASSED\n");
	else
		printf("getpwuid: uid test FAILED\n");

	if(!strcmp(passwd->pw_name,nss_passwd.pw_name))
		printf("getpwuid: name test PASSED\n");
	else
		printf("getpwuid: name test FAILED\n");

	return 0;
}

int
test_getpwnam()
{
uid_t uid;
struct passwd *passwd;
struct passwd nss_passwd;
unsigned char nss_buffer[1024];
int nss_errno;
int retval;
	
	printf("beonss tester\n");
	fflush(stdout);

	uid=getuid();

	printf("My uid is %d\n",uid);
	printf("My name is: %s\n",getenv("USER"));
	passwd=getpwnam(getenv("USER"));
	printf("My passwd uid is %d\n",passwd->pw_uid);
	printf("My passwd name is %s\n",passwd->pw_name);

	retval=_nss_bproc_getpwnam_r(getenv("USER"),&nss_passwd,nss_buffer,1024,&nss_errno);
	if(retval!=NSS_STATUS_SUCCESS)
	{
		printf("bproc getpwuid failed: ");
		if(retval==NSS_STATUS_NOTFOUND)
			printf("not found\n");
		else if(retval==NSS_STATUS_UNAVAIL)
			printf("unavailable: %s\n",strerror(nss_errno));
		else
			printf("unknown\n");
		exit(1);
	} else { 
		printf("My passwd uid is %d\n",nss_passwd.pw_uid);
		printf("My passwd name is %s\n",nss_passwd.pw_name);	
	}

	if(passwd->pw_uid == nss_passwd.pw_uid)
		printf("getpwuid: uid test PASSED\n");
	else
		printf("getpwuid: uid test FAILED\n");

	if(!strcmp(passwd->pw_name,nss_passwd.pw_name))
		printf("getpwuid: name test PASSED\n");
	else
		printf("getpwuid: name test FAILED\n");

	return 0;
}

int
test_gethostbyname(void)
{
struct hostent *hostent;
struct hostent nss_hostent;
unsigned char nss_buffer[1024];
int nss_errno,nss_herrno;
int retval;

	retval=_nss_bproc_gethostbyname_r("self",&nss_hostent,nss_buffer,1024,&nss_errno,&nss_herrno);
	if(retval!=NSS_STATUS_SUCCESS)
	{
		printf("bproc gethostbyname failed: ");
		if(retval==NSS_STATUS_NOTFOUND)
			printf("not found\n");
		else if(retval==NSS_STATUS_UNAVAIL)
			printf("unavailable: %s\n",strerror(nss_errno));
		else
			printf("unknown\n");
		exit(1);
	} else {
	struct sockaddr_in sin;

		sin.sin_family=AF_INET;
		sin.sin_addr.s_addr=*(int *)nss_hostent.h_addr;
		printf("My address is %s\n",inet_ntoa(sin.sin_addr));
	}

	return 0;
}
