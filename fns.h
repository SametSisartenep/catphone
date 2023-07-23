void *emalloc(ulong);
void *erealloc(void*, ulong);
Image *eallocimage(Display*, Rectangle, ulong, int, ulong);

void addheader(Hdrtab*, char*, char*);
Hdr *getheader(Hdrtab*, char*);
void delheader(Hdrtab*, char*);

Sip *mksip(int);
void rmsip(Sip*);
