#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "tclink.c"

MODULE = Net::TCLink		PACKAGE = Net::TCLink

int
TCLinkCreate()

void 
TCLinkPushParam(handle, name, value)
	int handle
	char * name
	char * value

int 
TCLinkSend(handle)
	int handle

char *
TCLinkGetEntireResponse(handle)
	int handle
	CODE:
		char * x = (char*)malloc(1024 * 1024);
		TCLinkGetEntireResponse(handle,x,1000);
		RETVAL = x;
	OUTPUT:
		RETVAL

