package clamavengin

import "C"

// Virus signature database options
const (
	DbPhishing         = 0x2
	DbPhishingUrls     = 0x8
	DbPua              = 0x10
	DbCvdnotmp         = 0x20 // obsolete
	DbOfficial         = 0x40 // internal
	DbPuaMode          = 0x80
	DbPuaInclude       = 0x100
	DbPuaExclude       = 0x200
	DbCompiled         = 0x400 // internal
	DbDirectory        = 0x800 // internal
	DbOfficialOnly     = 0x1000
	DbBytecode         = 0x2000
	DbSigned           = 0x4000 // internal
	DbBytecodeUnsigned = 0x8000

	// recommended db settings
	DbStdOpt = DbPhishing | DbPhishingUrls | DbBytecode
)

// Scanner options
const (
	// scan options
	ScanRaw                   = 0x0
	ScanArchive               = 0x1
	ScanMail                  = 0x2
	ScanOle2                  = 0x4
	ScanBlockencrypted        = 0x8
	ScanHTML                  = 0x10
	ScanPe                    = 0x20
	ScanBlockbroken           = 0x40
	ScanMailurl               = 0x80  // ignored
	ScanBlockmax              = 0x100 // ignored
	ScanAlgorithmic           = 0x200
	ScanPhishingBlockSSL      = 0x800 // ssl mismatches, not ssl by itself
	ScanPhishingBlockCloak    = 0x1000
	ScanElf                   = 0x2000
	ScanPdf                   = 0x4000
	ScanStructured            = 0x8000
	ScanStructuredSSNNormal   = 0x10000
	ScanStructuredSSNStripped = 0x20000
	ScanPartialMessage        = 0x40000
	ScanHeuristicPrecedence   = 0x80000
	ScanBlockmacros           = 0x100000
	ScanAllmatches            = 0x200000
	ScanSwf                   = 0x400000
	ScanPartitionIntxn        = 0x800000

	ScanCollectPerformanceInfo = 0x40000000

	// recommended scan settings
	ScanStdopt = ScanArchive | ScanMail | ScanOle2 | ScanPdf | ScanHTML | ScanPe | ScanAlgorithmic | ScanElf | ScanSwf
)

/*** scan options ***/
// struct cl_scan_options {
// uint32_t general;
// uint32_t parse;
// uint32_t heuristic;
// uint32_t mail;
// uint32_t dev;
// };

/* general */
const (
	SCAN_GENERAL_ALLMATCHES           = 0x1  /* scan in all-match mode */
	SCAN_GENERAL_COLLECT_METADATA     = 0x2  /* collect metadata (--gen-json) */
	SCAN_GENERAL_HEURISTICS           = 0x4  /* option to enable heuristic alerts */
	SCAN_GENERAL_HEURISTIC_PRECEDENCE = 0x8  /* allow heuristic match to take precedence. */
	SCAN_GENERAL_UNPRIVILEGED         = 0x10 /* scanner will not have read access to files. */

	/* parsing capabilities options */
	SCAN_PARSE_ARCHIVE = 0x1
	SCAN_PARSE_ELF     = 0x2
	SCAN_PARSE_PDF     = 0x4
	SCAN_PARSE_SWF     = 0x8
	SCAN_PARSE_HWP3    = 0x10
	SCAN_PARSE_XMLDOCS = 0x20
	SCAN_PARSE_MAIL    = 0x40
	SCAN_PARSE_OLE2    = 0x80
	SCAN_PARSE_HTML    = 0x100
	SCAN_PARSE_PE      = 0x200

	/* heuristic alerting options */
	SCAN_HEURISTIC_BROKEN                  = 0x2    /* alert on broken PE and broken ELF files */
	SCAN_HEURISTIC_EXCEEDS_MAX             = 0x4    /* alert when files exceed scan limits (filesize, max scansize, or max recursion depth) */
	SCAN_HEURISTIC_PHISHING_SSL_MISMATCH   = 0x8    /* alert on SSL mismatches */
	SCAN_HEURISTIC_PHISHING_CLOAK          = 0x10   /* alert on cloaked URLs in emails */
	SCAN_HEURISTIC_MACROS                  = 0x20   /* alert on OLE2 files containing macros */
	SCAN_HEURISTIC_ENCRYPTED_ARCHIVE       = 0x40   /* alert if archive is encrypted (rar, zip, etc) */
	SCAN_HEURISTIC_ENCRYPTED_DOC           = 0x80   /* alert if a document is encrypted (pdf, docx, etc) */
	SCAN_HEURISTIC_PARTITION_INTXN         = 0x100  /* alert if partition table size doesn't make sense */
	SCAN_HEURISTIC_STRUCTURED              = 0x200  /* data loss prevention options, i.e. alert when detecting personal information */
	SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL   = 0x400  /* alert when detecting social security numbers */
	SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED = 0x800  /* alert when detecting stripped social security numbers */
	SCAN_HEURISTIC_STRUCTURED_CC           = 0x1000 /* alert when detecting credit card numbers */
	SCAN_HEURISTIC_BROKEN_MEDIA            = 0x2000 /* alert if a file does not match the identified file format, works with JPEG, TIFF, GIF, PNG */

	/* mail scanning options */
	SCAN_MAIL_PARTIAL_MESSAGE = 0x1

	/* dev options */
	SCAN_DEV_COLLECT_SHA              = 0x1 /* Enables hash output in sha-collect builds - for internal use only */
	SCAN_DEV_COLLECT_PERFORMANCE_INFO = 0x2 /* collect performance timings */
)

const (
	DefaultCVDPath = "/var/lib/clamav"
)
