#include <u.h>
#include <libc.h>
#include <bio.h>
#include <mp.h>
#include <libsec.h>
#include <draw.h>
#include "dat.h"
#include "fns.h"

static char sipversion[] = "SIP/2.0";
static char useragent[] = "catphone (plan9front)";
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


static char *
getmethodstr(SipMethod m)
{
	return methodstrtab[m];
}

static char *
md5authfn(char *user, char *pass, char *uri, Sipmsg* m)
{
	uchar h1d[MD5dlen], h2d[MD5dlen], rd[MD5dlen];
	char h1ds[2*MD5dlen+1], h2ds[2*MD5dlen+1];
	static char rds[2*MD5dlen+1];
	char buf[4096];

	snprint(buf, sizeof buf, "%s:%s:%s", user, m->auth.realm, pass);
	md5((uchar*)buf, strlen(buf), h1d, nil);
	snprint(buf, sizeof buf, "%s:%s", getmethodstr(m->method), uri);
	md5((uchar*)buf, strlen(buf), h2d, nil);

	snprint(h1ds, sizeof h1ds, "%.*lH", sizeof h1d, h1d);
	snprint(h2ds, sizeof h2ds, "%.*lH", sizeof h2d, h2d);

	snprint(buf, sizeof buf, "%s:%s:%s", h1ds, m->auth.nonce, h2ds);
	md5((uchar*)buf, strlen(buf), rd, nil);
	snprint(rds, sizeof rds, "%.*lH", sizeof rd, rd);

	return rds;
}

static struct {
	char *name;
	char *(*fn)(char*, char*, char*, Sipmsg*);
} algos[] = {
 [AMD5]	{ .name = "MD5", .fn = md5authfn },
};

static uint
hash(char *s)
{
	uint h;

	h = 0x811c9dc5;
	while(*s != 0)
		h = (h^(uchar)*s++) * 0x1000193;
	return h % 13;
}

/* rfc3261 § 10 - Registrations */
static int
sip_register(Sip *s, char *user, char *pass)
{
	Sipmsg *req, *res;
	Hdr *h;
	Biobuf *bin, *bout;
	char *line, *p, *kv[8], *kv2[2], buf[1024];
	int n;

	if((bin = Bfdopen(s->fd, OREAD)) == nil)
		sysfatal("Bfdopen: %r");
	if((bout = Bfdopen(s->fd, OWRITE)) == nil)
		sysfatal("Bfdopen: %r");

	/* present yourself */
	req = newsipmsg();
	req->method = REGISTER;
	req->uri = smprint("sip:%s", s->nci->rsys);
	req->version = sipversion;
	snprint(buf, sizeof buf, "%s/UDP %s:%s;branch=z9hG4bK703d971c0c737b8e;rport",
		sipversion, s->nci->lsys, s->nci->lserv);
	addheader(req, "Via", buf);
	snprint(buf, sizeof buf, "<sip:%s-0x82a66a010@%s:%s>;expires=3849",
		user, s->nci->lsys, s->nci->lserv);
	addheader(req, "Contact", buf);
	addheader(req, "Max-Forwards", "70");
	snprint(buf, sizeof buf, "<sip:%s@%s>",
		user, s->nci->rsys);
	addheader(req, "To", buf);
	snprint(buf, sizeof buf, "<sip:%s@%s>;tag=4a5a693256d38cbc",
		user, s->nci->rsys);
	addheader(req, "From", buf);
	addheader(req, "Call-ID", "2cee372fc4be4e45");
	addheader(req, "CSeq", "16021 REGISTER");
	addheader(req, "User-Agent", useragent);
	addheader(req, "Allow", "INVITE,ACK,BYE,CANCEL,OPTIONS,NOTIFY,SUBSCRIBE,INFO,MESSAGE,UPDATE,REFER");
	snprint(buf, sizeof buf, "%lud", req->len);
	addheader(req, "Content-Length", buf);

	Bprint(bout, "%S", req);
	Bflush(bout);

	if(debug)
		fprint(2, "sent:\n%S\n", req);

	delsipmsg(req);

	/* wait for the challenge */
	res = newsipmsg();
	while((line = Brdline(bin, '\n')) != nil){
		if(strncmp(line, "\r\n", 2) == 0)
			break;

		p = strchr(line, '\r');
		*p++ = 0, *p = 0;

		if(strstr(line, ":") == nil && req->code == 0){
			if(gettokens(line, kv, 3, " ") == 3){
				res->version = strdup(kv[0]);
				res->code = strtoul(kv[1], nil, 10);
				res->reason = strdup(kv[2]);
			}
			continue;
		}

		if(gettokens(line, kv, 2, ": ") == 2)
			addheader(res, kv[0], kv[1]);
	}

	if(debug)
		fprint(2, "rcvd:\n%S\n", res);

	/* respond to the challenge */
	if((h = getheader(res, "WWW-Authenticate")) == nil)
		return -1;

	if((n = gettokens(h->value, kv, nelem(kv), ", ")) == 0)
		return -1;

	while(n-- > 0){
		if(gettokens(kv[n], kv2, 2, "=\"") != 2)
			continue;

		/* XXX: this hack should be replaced by a better method */
		p = strchr(kv2[1], '"');
		if(p != nil)
			*p = 0;

		if(strcmp(kv2[0], "algorithm") == 0)
			req->auth.algo = strdup(kv2[1]);
		else if(strcmp(kv2[0], "realm") == 0)
			req->auth.realm = strdup(kv2[1]);
		else if(strcmp(kv2[0], "nonce") == 0)
			req->auth.nonce = strdup(kv2[1]);
	}
	if(strcmp(res->auth.algo, "MD5") == 0){
		snprint(buf, sizeof buf, "sip:%s", s->nci->rsys);
		res->auth.response = algos[AMD5].fn(user, pass, buf, res);
		if(res->auth.response == nil)
			return -1;
	}else
		return -1;

	req = newsipmsg();
	req->method = REGISTER;
	req->uri = strdup(buf);
	req->version = sipversion;
	snprint(buf, sizeof buf, "%s/UDP %s:%s;branch=z9hG4bK703d971c0c737b8e;rport",
		sipversion, s->nci->lsys, s->nci->lserv);
	addheader(req, "Via", buf);
	snprint(buf, sizeof buf, "<sip:%s-0x82a66a010@%s:%s>;expires=3849",
		user, s->nci->lsys, s->nci->lserv);
	addheader(req, "Contact", buf);
	snprint(buf, sizeof buf, "Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\", algorithm=\"%s\"",
		user, res->auth.realm, res->auth.nonce, req->uri, res->auth.response, res->auth.algo);
	addheader(req, "Authorization", buf);
	addheader(req, "Max-Forwards", "70");
	snprint(buf, sizeof buf, "<sip:%s@%s>",
		user, s->nci->rsys);
	addheader(req, "To", buf);
	snprint(buf, sizeof buf, "<sip:%s@%s>;tag=4a5a693256d38cbc",
		user, s->nci->rsys);
	addheader(req, "From", buf);
	addheader(req, "Call-ID", "2cee372fc4be4e45");
	addheader(req, "CSeq", "16022 REGISTER");
	addheader(req, "User-Agent", useragent);
	addheader(req, "Allow", "INVITE,ACK,BYE,CANCEL,OPTIONS,NOTIFY,SUBSCRIBE,INFO,MESSAGE,UPDATE,REFER");
	snprint(buf, sizeof buf, "%lud", req->len);
	addheader(req, "Content-Length", buf);

	Bprint(bout, "%S", req);
	Bflush(bout);

	if(debug)
		fprint(2, "sent:\n%S\n", req);

	delsipmsg(res);
	delsipmsg(req);

	/* get the OK */
	res = newsipmsg();
	while((line = Brdline(bin, '\n')) != nil){
		if(strncmp(line, "\r\n", 2) == 0)
			break;

		p = strchr(line, '\r');
		*p++ = 0, *p = 0;

		if(strstr(line, ":") == nil && req->code == 0){
			if(gettokens(line, kv, 3, " ") == 3){
				res->version = strdup(kv[0]);
				res->code = strtoul(kv[1], nil, 10);
				res->reason = strdup(kv[2]);
			}
			continue;
		}

		if(gettokens(line, kv, 2, ": ") == 2)
			addheader(res, kv[0], kv[1]);
	}

	if(debug)
		fprint(2, "rcvd:\n%S\n", res);

	Bterm(bin);
	Bterm(bout);

	return 0;
}

int
Sfmt(Fmt *f)
{
	Sipmsg *m;
	Hdr *h;
	int i, n;

	m = va_arg(f->args, Sipmsg*);
	n = 0;

	if(m->code == 0){ /* request */
		n += fmtprint(f, "%s %s %s\r\n",
			getmethodstr(m->method), m->uri, m->version);
	}else{ /* response */
		n += fmtprint(f, "%s %d %s\r\n",
			m->version, m->code, m->reason);
	}

	for(i = 0; i < nelem(m->headers); i++)
		for(h = m->headers[i]; h != nil; h = h->next)
			n += fmtprint(f, "%s: %s\r\n", h->name, h->value);
	n += fmtprint(f, "\r\n");

	if(m->len > 0){
		fmtprint(f, "%.*s", (int)m->len, m->body);
		n += m->len;
	}

	return n;
}

void
SIPfmtinstall(void)
{
	fmtinstall('S', Sfmt);
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

Sipmsg *
newsipmsg(void)
{
	Sipmsg *m;

	m = emalloc(sizeof(Sipmsg));
	memset(m, 0, sizeof *m);

	return m;
}

void
delsipmsg(Sipmsg *m)
{
	if(m->uri != nil)
		free(m->uri);
	if(m->reason != nil)
		free(m->reason);
	delheaders(m);
	free(m);
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
