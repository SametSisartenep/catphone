#include <u.h>
#include <libc.h>
#include <bio.h>
#include <draw.h>
#include "dat.h"
#include "fns.h"

static char sipversion[] = "SIP/2.0";
static char *methodstrtab[] = {
 [REGISTER]	"REGISTER",
 [INVITE]	"INVITE",
 [ACK]		"ACK",
 [BYE]		"BYE",
 [CANCEL]	"CANCEL",
 [OPTIONS]	"OPTIONS",
 [NOTIFY]	"NOTIFY",
 [SUBSCRIBE]	"SUBSCRIBE",
 [INFO]		"INFO",
 [MESSAGE]	"MESSAGE",
 [UPDATE]	"UPDATE",
 [REFER]	"REFER",
};

static char registerhdr0[] = "REGISTER sip:%s %s\r\n"
	"Via: %s/UDP %s:%s;branch=z9hG4bK703d971c0c737b8e;rport\r\n"
	"Contact: <sip:%s-0x82a66a010@%s:%s>;expires=3849\r\n"
	"Max-Forwards: 70\r\n"
	"To: <sip:%s@%s>\r\n"
	"From: <sip:%s@%s>;tag=4a5a693256d38cbc\r\n"
	"Call-ID: 2cee372fc4be4e45\r\n"
	"CSeq: 16021 REGISTER\r\n"
	"User-Agent: catphone (plan9front)\r\n"
	"Allow: INVITE,ACK,BYE,CANCEL,OPTIONS,NOTIFY,SUBSCRIBE,INFO,MESSAGE,UPDATE,REFER\r\n"
	"Content-Length: 0\r\n"
	"\r\n";
static char registerhdr[] = "REGISTER sip:10.0.0.104 SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 10.0.1.9:54022;branch=z9hG4bKdf800c31b9a88ffb;rport\r\n"
	"Contact: <sip:sam-0x82a66a010@10.0.1.9:54022>;expires=3849\r\n"
	"Max-Forwards: 70\r\n"
	"Authorization: Digest username=\"sam\", realm=\"asterisk\", nonce=\"0d39ab10\", uri=\"sip:10.0.0.104\", response=\"a12e05b52604b5226763ce577d5c240b\", algorithm=MD5\r\n"
	"To: <sip:sam@10.0.0.104>\r\n"
	"From: <sip:sam@10.0.0.104>;tag=4a5a693256d38cbc\r\n"
	"Call-ID: 2cee372fc4be4e45\r\n"
	"CSeq: 16022 REGISTER\r\n"
	"User-Agent: catphone (plan9front)\r\n"
	"Allow: INVITE,ACK,BYE,CANCEL,OPTIONS,NOTIFY,SUBSCRIBE,INFO,MESSAGE,UPDATE,REFER\r\n"
	"Content-Length: 0\r\n"
	"\r\n";

static char *
getmethodstr(SipMethod m)
{
	return methodstrtab[m];
}

static uint
hash(char *s)
{
	uint h;

	h = 0x811c9dc5;
	while(*s != 0)
		h = (h^(uchar)*s++) * 0x1000193;
	return h % 13;
}

void
addheader(Hdrtab *ht, char *name, char *value)
{
	Hdr *h, *newh;
	uint key;

	key = hash(name);
	newh = emalloc(sizeof(Hdr));
	newh->name = strdup(name);
	newh->value = strdup(value);
	newh->next = nil;

	h = ht->headers[key];
	if(h == nil){
		ht->headers[key] = newh;
		return;
	}
	while(h->next != nil)
		h = h->next;
	h->next = newh;
}

Hdr *
getheader(Hdrtab *ht, char *name)
{
	Hdr *h;
	uint key;

	key = hash(name);
	for(h = ht->headers[key]; h != nil; h = h->next)
		if(cistrcmp(h->name, name) == 0)
			return h;
	return nil;
}

void
delheader(Hdrtab *ht, char *name)
{
	Hdr **h, *nh;
	uint key;

	key = hash(name);
	h = &ht->headers[key];
	while(*h != nil){
		nh = (*h)->next;
		if(cistrcmp((*h)->name, name) == 0){
			free((*h)->name);
			free((*h)->value);
			free(*h);
		}
		*h = nh;
	}
}

void
delheaders(Hdrtab *ht)
{
	Hdr *h, *nh;
	int i;

	for(i = 0; i < nelem(ht->headers); i++)
		for(h = ht->headers[i]; h != nil; h = nh){
			nh = h->next;
			free(h->name);
			free(h->value);
			free(h);
		}
}

/* rfc3261 § 10 - Registrations */
static int
sip_register(Sip *s, char *user, char *pass)
{
	Biobuf *bin, *bout;
	char *line, *p, *kv[2];
	int n;

	if((bin = Bfdopen(s->fd, OREAD)) == nil)
		sysfatal("Bfdopen: %r");
	if((bout = Bfdopen(s->fd, OWRITE)) == nil)
		sysfatal("Bfdopen: %r");

	/* present yourself */
	Bprint(bout, registerhdr0, s->nci->rsys, sipversion,
		sipversion, s->nci->lsys, s->nci->lserv,
		user, s->nci->lsys, s->nci->lserv,
		user, s->nci->rsys,
		user, s->nci->rsys);
	Bflush(bout);

	/* wait for the challenge */
	while((line = Brdline(bin, '\n')) != nil){
		if(strncmp(line, "\r\n", 2) == 0)
			break;

		p = strchr(line, '\r');
		*p++ = 0, *p = 0;
		if(debug)
			fprint(2, "%s\n", line);

		if(strstr(line, ":") == nil)
			continue;

		gettokens(line, kv, nelem(kv), ": ");
		if(debug)
			fprint(2, "got key=%s value=%s\n", kv[0], kv[1]);
	}

	/* respond to the challenge */

	/* get the OK */

	Bterm(bin);
	Bterm(bout);

	return 0;
}

Sip *
mksip(int fd)
{
	Sip *s;

	s = emalloc(sizeof(Sip));
	memset(s, 0, sizeof *s);
	s->version = 2;
	s->nci = getnetconninfo(nil, fd);
	if(s->nci == nil){
		werrstr("couldn't getnetconninfo");
		free(s);
		return nil;
	}
	s->fd = fd;
	s->reg = sip_register;

	return s;
}

void
rmsip(Sip *s)
{
	close(s->fd);
	freenetconninfo(s->nci);
	free(s);
}
