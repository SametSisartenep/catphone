typedef enum {
	REGISTER,
	INVITE,
	ACK,
	BYE,
	CANCEL,
	OPTIONS,
	NOTIFY,
	SUBSCRIBE,
	INFO,
	MESSAGE,
	UPDATE,
	REFER
} SipMethod;

/* rfc3261 § 21 - Response Codes */
typedef enum {
	/* 1xx Provisional */
	Trying		= 100,
	Ringing		= 180,
	CallForwarded	= 181,
	Queued		= 182,
	SessionProgress	= 183,

	/* 2xx Successful */
	OK		= 200,

	/* 3xx Redirection */
	MultiChoice		= 300,
	MovedPerm		= 301,
	MovedTemp		= 302,
	UseProxy		= 305,
	AltService		= 380,

	/* 4xx Request Failure */
	BadRequest		= 400,
	Unauthorized		= 401,
	PaymentRequired		= 402,
	Forbidden		= 403,
	NotFound		= 404,
	MethodNotAllowed	= 405,
	RequestNotAcceptable	= 406,
	ProxyAuthRequired	= 407,
	RequestTimeout		= 408,
	Gone			= 410,
	EntityTooLarge		= 413,
	URITooLong		= 414,
	UnsupportedMedia	= 415,
	UnsupportedURIScheme	= 416,
	BadExtension		= 420,
	ExtensionRequired	= 421,
	IntervalTooBrief	= 423,
	TempUnavailable		= 480,
	CallDoesNotExist	= 481,
	LoopDetected		= 482,
	TooManyHops		= 483,
	AddressIncomplete	= 484,
	Ambiguous		= 485,
	BusyHere		= 486,
	RequestTerminated	= 487,
	NotAcceptableHere	= 488,
	RequestPending		= 491,
	Undecipherable		= 493,

	/* 5xx Server Failure */
	InternalError		= 500,
	NotImplemented		= 501,
	BadGateway		= 502,
	ServiceUnavailable	= 503,
	ServerTimeout		= 504,
	VersionNotSupported	= 505,
	MessageTooLarge		= 513,

	/* 6xx Global Failures */
	BusyEverywhere		= 600,
	Decline			= 603,
	DoesNotExistAnywhere	= 604,
	NotAcceptable		= 606,
	
} SipStatus;

typedef struct Hdr Hdr;
typedef struct Hdrtab Hdrtab;
typedef struct Sipmsg Sipmsg;
typedef struct Sip Sip;

struct Hdr
{
	char *name;
	char *value;
	Hdr *next;
};

struct Hdrtab
{
	Hdr *headers[13];
};

struct Sipmsg
{
	Hdrtab;
	char *version;
	SipMethod method;
};

/* SIP UAC (see rfc3261 § 8.1, 12.1.2) */
struct Sip
{
	int version;

	NetConnInfo *nci;
	int fd;

	int (*reg)(Sip*, char*, char*);
};

extern int debug;
