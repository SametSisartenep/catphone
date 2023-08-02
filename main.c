#include <u.h>
#include <libc.h>
#include <draw.h>
#include <thread.h>
#include "dat.h"
#include "fns.h"

int debug;

//Channel *ingress;
//Channel *egress;
//
//
//void
//threadnetrecv(void *arg)
//{
//	
//}
//
//void
//threadnetppu(void *)
//{
//	
//}
//
//void
//threadnetsend(void *arg)
//{
//	
//}

void
usage(void)
{
	fprint(2, "usage: %s [-d] addr username password\n", argv0);
	exits("usage");
}

void
threadmain(int argc, char *argv[])
{
	Sip *sip;
	char *addr;
	int fd;

	SIPfmtinstall();
	fmtinstall('H', encodefmt);
	ARGBEGIN{
	default: usage();
	case 'd':
		debug++;
		break;
	}ARGEND;
	if(argc != 3)
		usage();

	addr = netmkaddr(argv[0], "udp", "sip");
	if(debug)
		fprint(2, "connecting to %s\n", addr);

	fd = dial(addr, nil, nil, nil);
	if(fd < 0)
		sysfatal("couldn't establish the connection");
	else if(debug)
		fprint(2, "connection established\n");

//	ingress = chancreate(sizeof(Sipmsg*), 8);
//	egress = chancreate(sizeof(Sipmsg*), 8);
//	threadcreate(threadnetrecv, &fd, mainstacksize);
//	threadcreate(threadnetppu, nil, mainstacksize);
//	threadcreate(threadnetsend, &fd, mainstacksize);
//	yield();

	sip = mksip(fd);
	if(sip == nil)
		sysfatal("mksip: %r");
	sip->reg(sip, argv[1], argv[2]);
	rmsip(sip);

	threadexitsall(nil);
}
