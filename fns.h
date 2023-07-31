void *emalloc(ulong);
void *erealloc(void*, ulong);
Image *eallocimage(Display*, Rectangle, ulong, int, ulong);

int Sfmt(Fmt*);
void SIPfmtinstall(void);

void addheader(Hdrtab*, char*, char*);
Hdr *getheader(Hdrtab*, char*);
void delheader(Hdrtab*, char*);
void delheaders(Hdrtab*);

Sipmsg *newsipmsg(void);
void delsipmsg(Sipmsg*);

Sip *mksip(int);
void rmsip(Sip*);
