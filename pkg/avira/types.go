package avira

// ResponseCode
const (
	SavApiRspCode100 = 100 // information,Typically as a response to a request
	SavApiRspCode199 = 199 // "Pong" response with optional ping-text,Terminal
	SavApiRspCode200 = 200 // File was not an archive, no alert found,Terminal
	SavApiRspCode210 = 210 // File was an archive, no alert found,Terminal
	SavApiRspCode220 = 220 // A connection timeout occurred,Terminal
	SavApiRspCode310 = 310 // Alert found,Non-terminal
	SavApiRspCode319 = 319 // Scan finished, alert found,Terminal
	SavApiRspCode350 = 350 // Error occurred,Terminal
	SavApiRspCode401 = 401 // Low-level alert information,Non-terminal
	SavApiRspCode404 = 404 // Too many clients connected,Terminal
	SavApiRspCode420 = 420 // Repairable alert found (the alert itself will follow),Non-terminal
	SavApiRspCode421 = 421 // Microsoft Office OLE document found,Non-terminal
	SavApiRspCode422 = 422 // Microsoft Office OLE document with macros found,Non-terminal
	SavApiRspCode423 = 423 // Microsoft Office OLE document with macros having auto-start enabled found,Non-terminal
	SavApiRspCode430 = 430 // Alert URL,Non-terminal
	SavApiRspCode450 = 450 // Plugin response,Non-terminal
	SavApiRspCode499 = 499 // Information,Non-terminal
)

const (
	messageDelimiter      = " " // response line form:<status-code> <data>\n (for UNIX)
	alertMessageDelimiter = ";" // response with malware. alter-name ; type ; message
	innerPathDelimiter    = " <<< "
)

type Malware struct {
	Name              string // malware name
	Type              string
	Desc              string
	FilePathInArchive string // a recursive path in archive when scan target is an archive.e.g.fileA-in-archive[ --> fileB-in-fileA]
}
