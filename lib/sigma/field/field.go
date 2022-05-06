package field

type Field string

const (
	CommandLine         Field = "CommandLine"
	CSHost              Field = "cs-host"
	CSMethod            Field = "cs-method"
	CSReferrer          Field = "cs-referrer"
	Computer            Field = "Computer"
	ComputerName        Field = "ComputerName"
	CURI                Field = "c-uri"
	Description         Field = "Description"
	DestinationHostname Field = "DestinationHostname"
	DestinationIP       Field = "DestinationIp"
	DestinationPort     Field = "DestinationPort"
	DstIP               Field = "dst_ip"
	DstPort             Field = "dst_port"
	Hashes              Field = "Hashes"
	Image               Field = "Image"
	MachineName         Field = "MachineName"
	ParentCommandLine   Field = "ParentCommandLine"
	ParentProcessName   Field = "ParentProcessName"
	ParentImage         Field = "ParentImage"
	ProcessName         Field = "ProcessName"
	RDNS                Field = "r-dns"
	SourceHostname      Field = "SourceHostname"
	SourceIP            Field = "SourceIp"
	SourcePort          Field = "SourcePort"
	SrcIP               Field = "src_ip"
	SrcPort             Field = "src_port"
	TargetObject        Field = "TargetObject"
	Workstation         Field = "Workstation"
	WorkstationName     Field = "WorkstationName"
)

func (f Field) Contains() Field {
	return f + "|contains"
}

func (f Field) All() Field {
	return f + "|all"
}

func (f Field) Base64() Field {
	return f + "base64"
}

func (f Field) Base64Offset() Field {
	return f + "base64offset"
}

func (f Field) EndsWith() Field {
	return f + "|endswith"
}

func (f Field) StartsWith() Field {
	return f + "|startswith"
}

func (f Field) UTF16LE() Field {
	return f + "|utf16le"
}

func (f Field) UTF16BE() Field {
	return f + "|utf16be"
}

func (f Field) Wide() Field {
	return f + "|wide"
}

func (f Field) UTF16() Field {
	return f + "|utf16"
}

func (f Field) RE() Field {
	return f + "re"
}
