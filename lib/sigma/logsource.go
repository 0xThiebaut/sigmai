package sigma

type LogSource struct {
	Category   Category `yaml:",omitempty"`
	Product    Product  `yaml:",omitempty"`
	Service    Service  `yaml:",omitempty"`
	Definition string   `yaml:",omitempty"`
}

type Category string

const (
	CategoryProcessCreation Category = "process_creation"
	CategoryProxy           Category = "proxy"
	CategoryFirewall        Category = "firewall"
	CategoryDNS             Category = "dns"
	CategoryWebServer       Category = "webserver"
)

type Product string

const (
	ProductWindows Product = "windows"
	ProductLinux   Product = "linux"
	ProductApache  Product = "apache"
)

type Service string

const (
	ServiceSecurity          Service = "security"
	ServiceSystem            Service = "system"
	ServiceSysmon            Service = "sysmon"
	ServiceTaskScheduler     Service = "taskscheduler"
	ServiceWMI               Service = "wmi"
	ServiceApplication       Service = "application"
	ServiceDNSServer         Service = "dns-server"
	ServiceDriverFramework   Service = "driver-framework"
	ServicePowerShell        Service = "powershell"
	ServicePowerShellClassic Service = "powershell-classic"
	ServiceAuth              Service = "auth"
	ServiceAuditd            Service = "auditd"
	ServiceClamAV            Service = "clamav"
	ServiceAccess            Service = "access"
	ServiceError             Service = "error"
)
