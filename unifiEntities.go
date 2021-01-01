package gounifi

import (
	"bytes"
	"encoding/json"
	"time"
)

//AuthResponse - Response back from an auth request. The data field is always empty.
type AuthResponse struct {
	Meta struct {
		Rc string `json:"rc"`
	} `json:"meta"`
	Data []interface{}
}

//SiteHealth - Contains data from all configured subsystems. Requires parsing to determine if subsytem data is returned
//			   in the API data.
type SiteHealth struct {
	Meta struct {
		Rc string `json:"rc"`
	} `json:"meta"`
	Data []struct {
		Subsystem       string   `json:"subsystem"`
		NumUser         int      `json:"num_user,omitempty"`
		NumGuest        int      `json:"num_guest,omitempty"`
		NumIot          int      `json:"num_iot,omitempty"`
		TxBytesR        int      `json:"tx_bytes-r,omitempty"`
		RxBytesR        int      `json:"rx_bytes-r,omitempty"`
		Status          string   `json:"status"`
		NumAp           int      `json:"num_ap,omitempty"`
		NumAdopted      int      `json:"num_adopted,omitempty"`
		NumDisabled     int      `json:"num_disabled,omitempty"`
		NumDisconnected int      `json:"num_disconnected,omitempty"`
		NumPending      int      `json:"num_pending,omitempty"`
		NumGw           int      `json:"num_gw,omitempty"`
		WanIP           string   `json:"wan_ip,omitempty"`
		Gateways        []string `json:"gateways,omitempty"`
		Netmask         string   `json:"netmask,omitempty"`
		Nameservers     []string `json:"nameservers,omitempty"`
		NumSta          int      `json:"num_sta,omitempty"`
		GwMac           string   `json:"gw_mac,omitempty"`
		GwName          string   `json:"gw_name,omitempty"`
		GwSystemStats   struct {
			CPU    string `json:"cpu"`
			Mem    string `json:"mem"`
			Uptime string `json:"uptime"`
		} `json:"gw_system-stats,omitempty"`
		GwVersion             string  `json:"gw_version,omitempty"`
		Latency               int     `json:"latency,omitempty"`
		Uptime                int     `json:"uptime,omitempty"`
		Drops                 int     `json:"drops,omitempty"`
		XputUp                float64 `json:"xput_up,omitempty"`
		XputDown              float64 `json:"xput_down,omitempty"`
		SpeedtestStatus       string  `json:"speedtest_status,omitempty"`
		SpeedtestLastrun      int     `json:"speedtest_lastrun,omitempty"`
		SpeedtestPing         int     `json:"speedtest_ping,omitempty"`
		LanIP                 string  `json:"lan_ip,omitempty"`
		NumSw                 int     `json:"num_sw,omitempty"`
		RemoteUserEnabled     bool    `json:"remote_user_enabled,omitempty"`
		RemoteUserNumActive   int     `json:"remote_user_num_active,omitempty"`
		RemoteUserNumInactive int     `json:"remote_user_num_inactive,omitempty"`
		RemoteUserRxBytes     int     `json:"remote_user_rx_bytes,omitempty"`
		RemoteUserTxBytes     int     `json:"remote_user_tx_bytes,omitempty"`
		RemoteUserRxPackets   int     `json:"remote_user_rx_packets,omitempty"`
		RemoteUserTxPackets   int     `json:"remote_user_tx_packets,omitempty"`
		SiteToSiteEnabled     bool    `json:"site_to_site_enabled,omitempty"`
	} `json:"data"`
}

//SysInfo - Information about the controller
type SysInfo struct {
	Meta struct {
		Rc string `json:"rc"`
	} `json:"meta"`
	Data []struct {
		Timezone                                 string   `json:"timezone"`
		Autobackup                               bool     `json:"autobackup"`
		Build                                    string   `json:"build"`
		Version                                  string   `json:"version"`
		PreviousVersion                          string   `json:"previous_version"`
		DebugMgmt                                string   `json:"debug_mgmt"`
		DebugSystem                              string   `json:"debug_system"`
		DebugDevice                              string   `json:"debug_device"`
		DebugSdn                                 string   `json:"debug_sdn"`
		DataRetentionDays                        int      `json:"data_retention_days"`
		DataRetentionTimeInHoursFor5MinutesScale int      `json:"data_retention_time_in_hours_for_5minutes_scale"`
		DataRetentionTimeInHoursForHourlyScale   int      `json:"data_retention_time_in_hours_for_hourly_scale"`
		DataRetentionTimeInHoursForDailyScale    int      `json:"data_retention_time_in_hours_for_daily_scale"`
		DataRetentionTimeInHoursForMonthlyScale  int      `json:"data_retention_time_in_hours_for_monthly_scale"`
		DataRetentionTimeInHoursForOthers        int      `json:"data_retention_time_in_hours_for_others"`
		UpdateAvailable                          bool     `json:"update_available"`
		UpdateDownloaded                         bool     `json:"update_downloaded"`
		LiveChat                                 string   `json:"live_chat"`
		StoreEnabled                             string   `json:"store_enabled"`
		Hostname                                 string   `json:"hostname"`
		Name                                     string   `json:"name"`
		IPAddrs                                  []string `json:"ip_addrs"`
		InformPort                               int      `json:"inform_port"`
		HTTPSPort                                int      `json:"https_port"`
		OverrideInformHost                       bool     `json:"override_inform_host"`
		ImageMapsUseGoogleEngine                 bool     `json:"image_maps_use_google_engine"`
		RadiusDisconnectRunning                  bool     `json:"radius_disconnect_running"`
		FacebookWifiRegistered                   bool     `json:"facebook_wifi_registered"`
		SsoAppID                                 string   `json:"sso_app_id"`
		SsoAppSec                                string   `json:"sso_app_sec"`
		UnsupportedDeviceCount                   int      `json:"unsupported_device_count"`
		UnifiGoEnabled                           bool     `json:"unifi_go_enabled"`
		DefaultSiteDeviceAuthPasswordAlert       bool     `json:"default_site_device_auth_password_alert"`
	} `json:"data"`
}

//ActiveClients - List of all active clients on the site
type ActiveClients struct {
	Meta struct {
		Rc string `json:"rc"`
	} `json:"meta"`
	Data []struct {
		SiteID              string `json:"site_id"`
		AssocTime           int    `json:"assoc_time"`
		LatestAssocTime     int    `json:"latest_assoc_time"`
		Oui                 string `json:"oui"`
		UserID              string `json:"user_id"`
		ID                  string `json:"_id"`
		Mac                 string `json:"mac"`
		IsGuest             bool   `json:"is_guest"`
		FirstSeen           int    `json:"first_seen"`
		LastSeen            int    `json:"last_seen"`
		IsWired             bool   `json:"is_wired"`
		Hostname            string `json:"hostname,omitempty"`
		UsergroupID         string `json:"usergroup_id,omitempty"`
		Name                string `json:"name,omitempty"`
		Noted               bool   `json:"noted,omitempty"`
		FingerprintOverride bool   `json:"fingerprint_override,omitempty"`
		DevIDOverride       int    `json:"dev_id_override,omitempty"`
		Blocked             bool   `json:"blocked,omitempty"`
		UptimeByUap         int    `json:"_uptime_by_uap,omitempty"`
		LastSeenByUap       int    `json:"_last_seen_by_uap,omitempty"`
		IsGuestByUap        bool   `json:"_is_guest_by_uap,omitempty"`
		ApMac               string `json:"ap_mac,omitempty"`
		Channel             int    `json:"channel,omitempty"`
		Radio               string `json:"radio,omitempty"`
		RadioName           string `json:"radio_name,omitempty"`
		Essid               string `json:"essid,omitempty"`
		Bssid               string `json:"bssid,omitempty"`
		PowersaveEnabled    bool   `json:"powersave_enabled,omitempty"`
		Is11R               bool   `json:"is_11r,omitempty"`
		Ccq                 int    `json:"ccq,omitempty"`
		Rssi                int    `json:"rssi,omitempty"`
		Noise               int    `json:"noise,omitempty"`
		Signal              int    `json:"signal,omitempty"`
		TxRate              int    `json:"tx_rate,omitempty"`
		RxRate              int    `json:"rx_rate,omitempty"`
		TxPower             int    `json:"tx_power,omitempty"`
		Idletime            int    `json:"idletime,omitempty"`
		IP                  string `json:"ip"`
		DhcpendTime         int    `json:"dhcpend_time,omitempty"`
		Satisfaction        int    `json:"satisfaction"`
		Anomalies           int    `json:"anomalies,omitempty"`
		Vlan                int    `json:"vlan,omitempty"`
		RadioProto          string `json:"radio_proto,omitempty"`
		Uptime              int    `json:"uptime"`
		TxBytes             int    `json:"tx_bytes"`
		RxBytes             int    `json:"rx_bytes"`
		TxPackets           int    `json:"tx_packets"`
		TxRetries           int    `json:"tx_retries"`
		WifiTxAttempts      int    `json:"wifi_tx_attempts"`
		RxPackets           int    `json:"rx_packets"`
		BytesR              int    `json:"bytes-r"`
		TxBytesR            int    `json:"tx_bytes-r"`
		RxBytesR            int    `json:"rx_bytes-r"`
		Authorized          bool   `json:"authorized"`
		QosPolicyApplied    bool   `json:"qos_policy_applied"`
		UptimeByUsw         int    `json:"_uptime_by_usw"`
		LastSeenByUsw       int    `json:"_last_seen_by_usw"`
		IsGuestByUsw        bool   `json:"_is_guest_by_usw"`
		SwMac               string `json:"sw_mac"`
		SwDepth             int    `json:"sw_depth"`
		SwPort              int    `json:"sw_port"`
		Network             string `json:"network"`
		NetworkID           string `json:"network_id"`
		UptimeByUgw         int    `json:"_uptime_by_ugw"`
		LastSeenByUgw       int    `json:"_last_seen_by_ugw"`
		IsGuestByUgw        bool   `json:"_is_guest_by_ugw"`
		GwMac               string `json:"gw_mac"`
		WiredTxBytes        int    `json:"wired-tx_bytes,omitempty"`
		WiredRxBytes        int    `json:"wired-rx_bytes,omitempty"`
		WiredTxPackets      int    `json:"wired-tx_packets,omitempty"`
		WiredRxPackets      int    `json:"wired-rx_packets,omitempty"`
		WiredTxBytesR       int    `json:"wired-tx_bytes-r,omitempty"`
		WiredRxBytesR       int    `json:"wired-rx_bytes-r,omitempty"`
		UseFixedip          bool   `json:"use_fixedip,omitempty"`
		FixedIP             string `json:"fixed_ip,omitempty"`
		DevCat              int    `json:"dev_cat,omitempty"`
		DevFamily           int    `json:"dev_family,omitempty"`
		DevID               int    `json:"dev_id,omitempty"`
		OsClass             int    `json:"os_class,omitempty"`
		OsName              int    `json:"os_name,omitempty"`
		DevVendor           int    `json:"dev_vendor,omitempty"`
		Note                string `json:"note,omitempty"`
	} `json:"data"`
}

// User - List of all configured/known clients on the site
type User struct {
	Meta struct {
		Rc string `json:"rc"`
	} `json:"meta"`
	Data []struct {
		ID                  string `json:"_id"`
		Mac                 string `json:"mac"`
		SiteID              string `json:"site_id"`
		Oui                 string `json:"oui,omitempty"`
		IsGuest             bool   `json:"is_guest,omitempty"`
		FirstSeen           int    `json:"first_seen,omitempty"`
		LastSeen            int    `json:"last_seen,omitempty"`
		IsWired             bool   `json:"is_wired,omitempty"`
		Hostname            string `json:"hostname,omitempty"`
		Blocked             bool   `json:"blocked,omitempty"`
		FingerprintOverride bool   `json:"fingerprint_override,omitempty"`
		DevIDOverride       int    `json:"dev_id_override,omitempty"`
		UsergroupID         string `json:"usergroup_id,omitempty"`
		Name                string `json:"name,omitempty"`
		Noted               bool   `json:"noted,omitempty"`
		UseFixedip          bool   `json:"use_fixedip,omitempty"`
		NetworkID           string `json:"network_id,omitempty"`
		FixedIP             string `json:"fixed_ip,omitempty"`
		Note                string `json:"note,omitempty"`
	} `json:"data"`
}

// Below are the types that represent the various Ubiquiti components. There is are a lot of redundant fields here. A later task is to
// make them more generic where possible.

// TODO: Break out the common blocks into separate types to avoid repition
// TODO: Work out how to make these more generic while still retaining the rich structures for each device type

//DeviceBasic - Basic information about a network device
type DeviceBasic struct {
	Meta struct {
		Rc string `json:"rc"`
	} `json:"meta"`
	Data []struct {
		Mac      string `json:"mac"`
		State    int    `json:"state"`
		Adopted  bool   `json:"adopted"`
		Disabled bool   `json:"disabled"`
		Type     string `json:"type"`
		Model    string `json:"model"`
		Name     string `json:"name"`
	} `json:"data"`
}

//Devices - Contains the details for all the devices in the system. Because we dont know what we will get back in terms of combinations of devices
//			an empty interface is used which can then be parsed out to the concrete types at runtime. At least that is the plan!
type Devices struct {
	Meta struct {
		Rc string `json:"rc"`
	} `json:"meta"`
	//Data []interface{} `json:"data"`
	Data []json.RawMessage `json:"data"`
}

// TODO: Try and Find a more elegant way to do this

//UbiquitiDevices - A static catalog of Ubquiti Devices that are known to this client
var UbiquitiDevices = []string{"USG", "US8P60Switch", "U7LRWifiAP", "USC8Switch"}

//SiteDevices is a container for all devices in a site. The key should alsays be one of the devices listed in the catalog above
type SiteDevices map[string][]interface{}

//USG - Security Gateway
type USG struct {
	ID            string `json:"_id"`
	IP            string `json:"ip"`
	Mac           string `json:"mac"`
	Model         string `json:"model"`
	Type          string `json:"type"`
	Version       string `json:"version"`
	Adopted       bool   `json:"adopted"`
	SiteID        string `json:"site_id"`
	XAuthkey      string `json:"x_authkey"`
	Cfgversion    string `json:"cfgversion"`
	ConfigNetwork struct {
		Type string `json:"type"`
		IP   string `json:"ip"`
	} `json:"config_network"`
	LicenseState           string `json:"license_state"`
	XSSHHostkeyFingerprint string `json:"x_ssh_hostkey_fingerprint"`
	XFingerprint           string `json:"x_fingerprint"`
	InformURL              string `json:"inform_url"`
	InformIP               string `json:"inform_ip"`
	RequiredVersion        string `json:"required_version"`
	BoardRev               int    `json:"board_rev"`
	XAesGcm                bool   `json:"x_aes_gcm"`
	EthernetTable          []struct {
		Mac     string `json:"mac"`
		NumPort int    `json:"num_port"`
		Name    string `json:"name"`
	} `json:"ethernet_table"`
	EthernetOverrides []struct {
		Ifname       string `json:"ifname"`
		Networkgroup string `json:"networkgroup"`
	} `json:"ethernet_overrides"`
	FwCaps                     int    `json:"fw_caps"`
	HwCaps                     int    `json:"hw_caps"`
	UsgCaps                    int    `json:"usg_caps"`
	LedOverride                string `json:"led_override"`
	LedOverrideColor           string `json:"led_override_color"`
	LedOverrideColorBrightness int    `json:"led_override_color_brightness"`
	OutdoorModeOverride        string `json:"outdoor_mode_override"`
	Name                       string `json:"name"`
	Unsupported                bool   `json:"unsupported"`
	UnsupportedReason          int    `json:"unsupported_reason"`
	Serial                     string `json:"serial"`
	TwoPhaseAdopt              bool   `json:"two_phase_adopt"`
	SyslogKey                  string `json:"syslog_key"`
	KernelVersion              string `json:"kernel_version"`
	Architecture               string `json:"architecture"`
	LcmTrackerEnabled          bool   `json:"lcm_tracker_enabled"`
	LcmTrackerSeed             string `json:"lcm_tracker_seed"`
	DeviceID                   string `json:"device_id"`
	State                      int    `json:"state"`
	StartDisconnectedMillis    int64  `json:"start_disconnected_millis"`
	StartConnectedMillis       int64  `json:"start_connected_millis"`
	LastSeen                   int    `json:"last_seen"`
	Uptime                     int    `json:"uptime"`
	XUptime                    int    `json:"_uptime"`
	Locating                   bool   `json:"locating"`
	SysStats                   struct {
		Loadavg1  string `json:"loadavg_1"`
		Loadavg15 string `json:"loadavg_15"`
		Loadavg5  string `json:"loadavg_5"`
		MemBuffer int    `json:"mem_buffer"`
		MemTotal  int    `json:"mem_total"`
		MemUsed   int    `json:"mem_used"`
	} `json:"sys_stats"`
	SystemStats struct {
		CPU    string `json:"cpu"`
		Mem    string `json:"mem"`
		Uptime string `json:"uptime"`
	} `json:"system-stats"`
	GuestToken      string `json:"guest_token"`
	SpeedtestStatus struct {
		Latency int `json:"latency"`
		Rundate int `json:"rundate"`
		Runtime int `json:"runtime"`
		Server  struct {
			Cc          string  `json:"cc"`
			City        string  `json:"city"`
			Country     string  `json:"country"`
			Lat         float64 `json:"lat"`
			Lon         float64 `json:"lon"`
			Provider    string  `json:"provider"`
			ProviderURL string  `json:"provider_url"`
		} `json:"server"`
		StatusDownload int     `json:"status_download"`
		StatusPing     int     `json:"status_ping"`
		StatusSummary  int     `json:"status_summary"`
		StatusUpload   int     `json:"status_upload"`
		XputDownload   float64 `json:"xput_download"`
		XputUpload     float64 `json:"xput_upload"`
	} `json:"speedtest-status"`
	SpeedtestStatusSaved bool `json:"speedtest-status-saved"`
	Wan1                 struct {
		TxBytesR    int      `json:"tx_bytes-r"`
		RxBytesR    int      `json:"rx_bytes-r"`
		BytesR      int      `json:"bytes-r"`
		MaxSpeed    int      `json:"max_speed"`
		Type        string   `json:"type"`
		Name        string   `json:"name"`
		Ifname      string   `json:"ifname"`
		IP          string   `json:"ip"`
		Netmask     string   `json:"netmask"`
		Mac         string   `json:"mac"`
		Up          bool     `json:"up"`
		Speed       int      `json:"speed"`
		FullDuplex  bool     `json:"full_duplex"`
		RxBytes     int64    `json:"rx_bytes"`
		RxDropped   int      `json:"rx_dropped"`
		RxErrors    int      `json:"rx_errors"`
		RxPackets   int      `json:"rx_packets"`
		TxBytes     int64    `json:"tx_bytes"`
		TxDropped   int      `json:"tx_dropped"`
		TxErrors    int      `json:"tx_errors"`
		TxPackets   int      `json:"tx_packets"`
		RxMulticast int      `json:"rx_multicast"`
		Enable      bool     `json:"enable"`
		DNS         []string `json:"dns"`
		Gateway     string   `json:"gateway"`
	} `json:"wan1"`
	PortTable []struct {
		Name        string   `json:"name"`
		Ifname      string   `json:"ifname"`
		IP          string   `json:"ip"`
		Netmask     string   `json:"netmask"`
		Mac         string   `json:"mac"`
		Up          bool     `json:"up"`
		Speed       int      `json:"speed"`
		FullDuplex  bool     `json:"full_duplex"`
		RxBytes     int64    `json:"rx_bytes"`
		RxDropped   int      `json:"rx_dropped"`
		RxErrors    int      `json:"rx_errors"`
		RxPackets   int      `json:"rx_packets"`
		TxBytes     int64    `json:"tx_bytes"`
		TxDropped   int      `json:"tx_dropped"`
		TxErrors    int      `json:"tx_errors"`
		TxPackets   int      `json:"tx_packets"`
		RxMulticast int      `json:"rx_multicast"`
		Enable      bool     `json:"enable"`
		DNS         []string `json:"dns,omitempty"`
		Gateway     string   `json:"gateway,omitempty"`
	} `json:"port_table"`
	NetworkTable []struct {
		ID                     string `json:"_id"`
		Purpose                string `json:"purpose"`
		Networkgroup           string `json:"networkgroup"`
		DhcpdEnabled           bool   `json:"dhcpd_enabled"`
		DhcpdLeasetime         int    `json:"dhcpd_leasetime"`
		DhcpdDNSEnabled        bool   `json:"dhcpd_dns_enabled"`
		DhcpdGatewayEnabled    bool   `json:"dhcpd_gateway_enabled"`
		DhcpdTimeOffsetEnabled bool   `json:"dhcpd_time_offset_enabled"`
		Ipv6InterfaceType      string `json:"ipv6_interface_type"`
		Name                   string `json:"name"`
		Vlan                   string `json:"vlan"`
		IPSubnet               string `json:"ip_subnet"`
		DhcpdStart             string `json:"dhcpd_start"`
		DhcpdStop              string `json:"dhcpd_stop"`
		DomainName             string `json:"domain_name"`
		DhcpdDNS1              string `json:"dhcpd_dns_1,omitempty"`
		DhcpdDNS2              string `json:"dhcpd_dns_2,omitempty"`
		Enabled                bool   `json:"enabled"`
		IsNat                  bool   `json:"is_nat"`
		DhcpRelayEnabled       bool   `json:"dhcp_relay_enabled"`
		VlanEnabled            bool   `json:"vlan_enabled"`
		SiteID                 string `json:"site_id"`
		UpnpLanEnabled         bool   `json:"upnp_lan_enabled"`
		Mac                    string `json:"mac"`
		IsGuest                bool   `json:"is_guest"`
		IP                     string `json:"ip"`
		Up                     string `json:"up"`
		NumSta                 int    `json:"num_sta"`
		RxBytes                int    `json:"rx_bytes"`
		RxPackets              int    `json:"rx_packets"`
		TxBytes                int    `json:"tx_bytes"`
		TxPackets              int    `json:"tx_packets"`
		Ipv6PdStart            string `json:"ipv6_pd_start,omitempty"`
		Ipv6PdStop             string `json:"ipv6_pd_stop,omitempty"`
		IgmpSnooping           bool   `json:"igmp_snooping,omitempty"`
		DhcpdWpadURL           string `json:"dhcpd_wpad_url,omitempty"`
		DhcpdBootEnabled       bool   `json:"dhcpd_boot_enabled,omitempty"`
		DhcpdNtpEnabled        bool   `json:"dhcpd_ntp_enabled,omitempty"`
		DhcpdTftpServer        string `json:"dhcpd_tftp_server,omitempty"`
		DhcpdUnifiController   string `json:"dhcpd_unifi_controller,omitempty"`
		DhcpguardEnabled       bool   `json:"dhcpguard_enabled,omitempty"`
		DhcpdWinsEnabled       bool   `json:"dhcpd_wins_enabled,omitempty"`
		Ipv6RaEnabled          bool   `json:"ipv6_ra_enabled,omitempty"`
		LteLanEnabled          bool   `json:"lte_lan_enabled,omitempty"`
		DhcpdDNS3              string `json:"dhcpd_dns_3,omitempty"`
		AttrNoDelete           bool   `json:"attr_no_delete,omitempty"`
		AttrHiddenID           string `json:"attr_hidden_id,omitempty"`
	} `json:"network_table"`
	Upgradable            bool   `json:"upgradable"`
	AdoptableWhenUpgraded bool   `json:"adoptable_when_upgraded"`
	Rollupgrade           bool   `json:"rollupgrade"`
	XInformAuthkey        string `json:"x_inform_authkey"`
	KnownCfgversion       string `json:"known_cfgversion"`
	ConnectRequestIP      string `json:"connect_request_ip"`
	ConnectRequestPort    string `json:"connect_request_port"`
	UseCustomConfig       bool   `json:"use_custom_config"`
	PrevNonBusyState      int    `json:"prev_non_busy_state"`
	Uplink                struct {
		Drops            int      `json:"drops"`
		Enable           bool     `json:"enable"`
		FullDuplex       bool     `json:"full_duplex"`
		Gateways         []string `json:"gateways"`
		IP               string   `json:"ip"`
		Latency          int      `json:"latency"`
		Mac              string   `json:"mac"`
		Name             string   `json:"name"`
		Nameservers      []string `json:"nameservers"`
		Netmask          string   `json:"netmask"`
		NumPort          int      `json:"num_port"`
		RxBytes          int64    `json:"rx_bytes"`
		RxDropped        int      `json:"rx_dropped"`
		RxErrors         int      `json:"rx_errors"`
		RxMulticast      int      `json:"rx_multicast"`
		RxPackets        int      `json:"rx_packets"`
		Speed            int      `json:"speed"`
		SpeedtestLastrun int      `json:"speedtest_lastrun"`
		SpeedtestPing    int      `json:"speedtest_ping"`
		SpeedtestStatus  string   `json:"speedtest_status"`
		TxBytes          int64    `json:"tx_bytes"`
		TxDropped        int      `json:"tx_dropped"`
		TxErrors         int      `json:"tx_errors"`
		TxPackets        int      `json:"tx_packets"`
		Up               bool     `json:"up"`
		Uptime           int      `json:"uptime"`
		XputDown         float64  `json:"xput_down"`
		XputUp           float64  `json:"xput_up"`
		TxBytesR         int      `json:"tx_bytes-r"`
		RxBytesR         int      `json:"rx_bytes-r"`
		BytesR           int      `json:"bytes-r"`
		MaxSpeed         int      `json:"max_speed"`
		Type             string   `json:"type"`
	} `json:"uplink"`
	NextInterval     int `json:"next_interval"`
	NextHeartbeatAt  int `json:"next_heartbeat_at"`
	ConsideredLostAt int `json:"considered_lost_at"`
	Stat             struct {
		Gw struct {
			SiteID        string    `json:"site_id"`
			O             string    `json:"o"`
			Oid           string    `json:"oid"`
			Gw            string    `json:"gw"`
			Time          int64     `json:"time"`
			Datetime      time.Time `json:"datetime"`
			Duration      float64   `json:"duration"`
			WanRxPackets  float64   `json:"wan-rx_packets"`
			WanRxBytes    float64   `json:"wan-rx_bytes"`
			WanTxPackets  float64   `json:"wan-tx_packets"`
			WanTxBytes    float64   `json:"wan-tx_bytes"`
			LanRxPackets  float64   `json:"lan-rx_packets"`
			LanRxBytes    float64   `json:"lan-rx_bytes"`
			LanTxPackets  float64   `json:"lan-tx_packets"`
			LanTxBytes    float64   `json:"lan-tx_bytes"`
			Lan2TxPackets float64   `json:"lan2-tx_packets"`
			Lan2TxBytes   float64   `json:"lan2-tx_bytes"`
			Lan2RxPackets float64   `json:"lan2-rx_packets"`
			Lan2RxBytes   float64   `json:"lan2-rx_bytes"`
			Lan2RxDropped float64   `json:"lan2-rx_dropped"`
			WanRxDropped  float64   `json:"wan-rx_dropped"`
			LanRxDropped  float64   `json:"lan-rx_dropped"`
		} `json:"gw"`
	} `json:"stat"`
	TxBytes        int64 `json:"tx_bytes"`
	RxBytes        int64 `json:"rx_bytes"`
	Bytes          int64 `json:"bytes"`
	NumSta         int   `json:"num_sta"`
	UserNumSta     int   `json:"user-num_sta"`
	GuestNumSta    int   `json:"guest-num_sta"`
	NumDesktop     int   `json:"num_desktop"`
	NumMobile      int   `json:"num_mobile"`
	NumHandheld    int   `json:"num_handheld"`
	XHasSSHHostkey bool  `json:"x_has_ssh_hostkey"`
}

func (u *USG) unmarshal(raw json.RawMessage) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))

	// This could cause issues down the road if new fields are added.
	dec.DisallowUnknownFields()

	if err := dec.Decode(u); err != nil {
		return false
	}

	return true
}

//US8P60Switch - 60W PoE 8 port switch
type US8P60Switch struct {
	ID            string `json:"_id"`
	IP            string `json:"ip"`
	Mac           string `json:"mac"`
	Model         string `json:"model"`
	Type          string `json:"type"`
	Version       string `json:"version"`
	Adopted       bool   `json:"adopted"`
	SiteID        string `json:"site_id"`
	XAuthkey      string `json:"x_authkey"`
	Cfgversion    string `json:"cfgversion"`
	SyslogKey     string `json:"syslog_key"`
	ConfigNetwork struct {
		Type string `json:"type"`
		IP   string `json:"ip"`
	} `json:"config_network"`
	JumboframeEnabled      bool   `json:"jumboframe_enabled"`
	FlowctrlEnabled        bool   `json:"flowctrl_enabled"`
	StpVersion             string `json:"stp_version"`
	StpPriority            string `json:"stp_priority"`
	Dot1XPortctrlEnabled   bool   `json:"dot1x_portctrl_enabled"`
	PowerSourceCtrlEnabled bool   `json:"power_source_ctrl_enabled"`
	LicenseState           string `json:"license_state"`
	XSSHHostkeyFingerprint string `json:"x_ssh_hostkey_fingerprint"`
	XAesGcm                bool   `json:"x_aes_gcm"`
	XFingerprint           string `json:"x_fingerprint"`
	InformURL              string `json:"inform_url"`
	InformIP               string `json:"inform_ip"`
	RequiredVersion        string `json:"required_version"`
	KernelVersion          string `json:"kernel_version"`
	Architecture           string `json:"architecture"`
	HashID                 string `json:"hash_id"`
	GatewayMac             string `json:"gateway_mac"`
	BoardRev               int    `json:"board_rev"`
	ManufacturerID         int    `json:"manufacturer_id"`
	EthernetTable          []struct {
		Mac     string `json:"mac"`
		NumPort int    `json:"num_port,omitempty"`
		Name    string `json:"name"`
	} `json:"ethernet_table"`
	PortTable []struct {
		PortIdx                int           `json:"port_idx"`
		Media                  string        `json:"media"`
		PortPoe                bool          `json:"port_poe"`
		PoeCaps                int           `json:"poe_caps"`
		SpeedCaps              int           `json:"speed_caps"`
		OpMode                 string        `json:"op_mode"`
		PortconfID             string        `json:"portconf_id"`
		Anomalies              int           `json:"anomalies"`
		Autoneg                bool          `json:"autoneg"`
		Dot1XMode              string        `json:"dot1x_mode"`
		Dot1XStatus            string        `json:"dot1x_status"`
		Enable                 bool          `json:"enable"`
		FlowctrlRx             bool          `json:"flowctrl_rx"`
		FlowctrlTx             bool          `json:"flowctrl_tx"`
		FullDuplex             bool          `json:"full_duplex"`
		IsUplink               bool          `json:"is_uplink"`
		Jumbo                  bool          `json:"jumbo"`
		RxBroadcast            int           `json:"rx_broadcast"`
		RxBytes                int64         `json:"rx_bytes"`
		RxDropped              int           `json:"rx_dropped"`
		RxErrors               int           `json:"rx_errors"`
		RxMulticast            int           `json:"rx_multicast"`
		RxPackets              int           `json:"rx_packets"`
		Satisfaction           int           `json:"satisfaction"`
		SatisfactionReason     int           `json:"satisfaction_reason"`
		Speed                  int           `json:"speed"`
		StpPathcost            int           `json:"stp_pathcost"`
		StpState               string        `json:"stp_state"`
		TxBroadcast            int           `json:"tx_broadcast"`
		TxBytes                int64         `json:"tx_bytes"`
		TxDropped              int           `json:"tx_dropped"`
		TxErrors               int           `json:"tx_errors"`
		TxMulticast            int           `json:"tx_multicast"`
		TxPackets              int           `json:"tx_packets"`
		Up                     bool          `json:"up"`
		TxBytesR               int           `json:"tx_bytes-r"`
		RxBytesR               int           `json:"rx_bytes-r"`
		BytesR                 int           `json:"bytes-r"`
		PortSecurityMacAddress []interface{} `json:"port_security_mac_address,omitempty"`
		Name                   string        `json:"name"`
		Masked                 bool          `json:"masked"`
		AggregatedBy           bool          `json:"aggregated_by"`
		PoeMode                string        `json:"poe_mode,omitempty"`
		PoeClass               string        `json:"poe_class,omitempty"`
		PoeCurrent             string        `json:"poe_current,omitempty"`
		PoeEnable              bool          `json:"poe_enable,omitempty"`
		PoeGood                bool          `json:"poe_good,omitempty"`
		PoePower               string        `json:"poe_power,omitempty"`
		PoeVoltage             string        `json:"poe_voltage,omitempty"`
	} `json:"port_table"`
	SwitchCaps struct {
		FeatureCaps          int `json:"feature_caps"`
		MaxMirrorSessions    int `json:"max_mirror_sessions"`
		MaxAggregateSessions int `json:"max_aggregate_sessions"`
	} `json:"switch_caps"`
	HasFan                     bool   `json:"has_fan"`
	HasTemperature             bool   `json:"has_temperature"`
	HwCaps                     int    `json:"hw_caps"`
	FwCaps                     int    `json:"fw_caps"`
	Satisfaction               int    `json:"satisfaction"`
	SysErrorCaps               int    `json:"sys_error_caps"`
	LedOverride                string `json:"led_override"`
	LedOverrideColor           string `json:"led_override_color"`
	LedOverrideColorBrightness int    `json:"led_override_color_brightness"`
	OutdoorModeOverride        string `json:"outdoor_mode_override"`
	LcmBrightnessOverride      bool   `json:"lcm_brightness_override"`
	LcmIdleTimeoutOverride     bool   `json:"lcm_idle_timeout_override"`
	Name                       string `json:"name"`
	PortOverrides              []struct {
		PortIdx                int           `json:"port_idx"`
		PortconfID             string        `json:"portconf_id"`
		PortSecurityMacAddress []interface{} `json:"port_security_mac_address"`
		Name                   string        `json:"name"`
		PoeMode                string        `json:"poe_mode,omitempty"`
	} `json:"port_overrides"`
	Unsupported             bool   `json:"unsupported"`
	UnsupportedReason       int    `json:"unsupported_reason"`
	Serial                  string `json:"serial"`
	DeviceID                string `json:"device_id"`
	State                   int    `json:"state"`
	StartDisconnectedMillis int64  `json:"start_disconnected_millis"`
	XInformAuthkey          string `json:"x_inform_authkey"`
	LastSeen                int    `json:"last_seen"`
	Upgradable              bool   `json:"upgradable"`
	AdoptableWhenUpgraded   bool   `json:"adoptable_when_upgraded"`
	Rollupgrade             bool   `json:"rollupgrade"`
	KnownCfgversion         string `json:"known_cfgversion"`
	Uptime                  int    `json:"uptime"`
	XUptime                 int    `json:"_uptime"`
	Locating                bool   `json:"locating"`
	StartConnectedMillis    int64  `json:"start_connected_millis"`
	PrevNonBusyState        int    `json:"prev_non_busy_state"`
	ConnectRequestIP        string `json:"connect_request_ip"`
	ConnectRequestPort      string `json:"connect_request_port"`
	SysStats                struct {
		Loadavg1  string `json:"loadavg_1"`
		Loadavg15 string `json:"loadavg_15"`
		Loadavg5  string `json:"loadavg_5"`
		MemBuffer int    `json:"mem_buffer"`
		MemTotal  int    `json:"mem_total"`
		MemUsed   int    `json:"mem_used"`
	} `json:"sys_stats"`
	SystemStats struct {
		CPU    string `json:"cpu"`
		Mem    string `json:"mem"`
		Uptime string `json:"uptime"`
	} `json:"system-stats"`
	SSHSessionTable []interface{} `json:"ssh_session_table"`
	Overheating     bool          `json:"overheating"`
	TotalMaxPower   int           `json:"total_max_power"`
	DownlinkTable   []struct {
		PortIdx    int    `json:"port_idx"`
		Speed      int    `json:"speed"`
		FullDuplex bool   `json:"full_duplex"`
		Mac        string `json:"mac"`
	} `json:"downlink_table"`
	Uplink struct {
		FullDuplex  bool   `json:"full_duplex"`
		IP          string `json:"ip"`
		Mac         string `json:"mac"`
		Name        string `json:"name"`
		Netmask     string `json:"netmask"`
		NumPort     int    `json:"num_port"`
		RxBytes     int64  `json:"rx_bytes"`
		RxDropped   int    `json:"rx_dropped"`
		RxErrors    int    `json:"rx_errors"`
		RxMulticast int    `json:"rx_multicast"`
		RxPackets   int    `json:"rx_packets"`
		Speed       int    `json:"speed"`
		TxBytes     int64  `json:"tx_bytes"`
		TxDropped   int    `json:"tx_dropped"`
		TxErrors    int    `json:"tx_errors"`
		TxPackets   int    `json:"tx_packets"`
		Up          bool   `json:"up"`
		PortIdx     int    `json:"port_idx"`
		Media       string `json:"media"`
		MaxSpeed    int    `json:"max_speed"`
		UplinkMac   string `json:"uplink_mac"`
		Type        string `json:"type"`
		TxBytesR    int    `json:"tx_bytes-r"`
		RxBytesR    int    `json:"rx_bytes-r"`
	} `json:"uplink"`
	LastUplink struct {
		UplinkMac string `json:"uplink_mac"`
	} `json:"last_uplink"`
	UplinkDepth      int           `json:"uplink_depth"`
	DhcpServerTable  []interface{} `json:"dhcp_server_table"`
	NextInterval     int           `json:"next_interval"`
	NextHeartbeatAt  int           `json:"next_heartbeat_at"`
	ConsideredLostAt int           `json:"considered_lost_at"`
	Stat             SwitchStats   `json:"stat"`
	TxBytes          int64         `json:"tx_bytes"`
	RxBytes          int64         `json:"rx_bytes"`
	Bytes            int64         `json:"bytes"`
	NumSta           int           `json:"num_sta"`
	UserNumSta       int           `json:"user-num_sta"`
	GuestNumSta      int           `json:"guest-num_sta"`
	XHasSSHHostkey   bool          `json:"x_has_ssh_hostkey"`
}

func (u *US8P60Switch) unmarshal(raw json.RawMessage) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))

	// This could cause issues down the road if new fields are added.
	dec.DisallowUnknownFields()

	if err := dec.Decode(u); err != nil {
		return false
	}

	return true
}

//U7LRWifiAP - U7 Long Range Wifi AP
type U7LRWifiAP struct {
	ID         string        `json:"_id"`
	PortTable  []interface{} `json:"port_table"`
	HasSpeaker bool          `json:"has_speaker"`
	RadioTable []struct {
		Radio                 string `json:"radio"`
		Name                  string `json:"name"`
		Ht                    string `json:"ht"`
		Channel               int    `json:"channel"`
		TxPowerMode           string `json:"tx_power_mode"`
		AntennaGain           int    `json:"antenna_gain"`
		MinRssiEnabled        bool   `json:"min_rssi_enabled"`
		SensLevelEnabled      bool   `json:"sens_level_enabled"`
		VwireEnabled          bool   `json:"vwire_enabled"`
		MinTxpower            int    `json:"min_txpower"`
		MaxTxpower            int    `json:"max_txpower"`
		BuiltinAntenna        bool   `json:"builtin_antenna"`
		BuiltinAntGain        int    `json:"builtin_ant_gain"`
		CurrentAntennaGain    int    `json:"current_antenna_gain"`
		Nss                   int    `json:"nss"`
		RadioCaps             int    `json:"radio_caps"`
		WlangroupID           string `json:"wlangroup_id"`
		BackupChannel         int    `json:"backup_channel"`
		HardNoiseFloorEnabled bool   `json:"hard_noise_floor_enabled,omitempty"`
		Is11Ac                bool   `json:"is_11ac,omitempty"`
		HasDfs                bool   `json:"has_dfs,omitempty"`
		HasFccdfs             bool   `json:"has_fccdfs,omitempty"`
	} `json:"radio_table"`
	XFingerprint  string `json:"x_fingerprint"`
	LicenseState  string `json:"license_state"`
	InformIP      string `json:"inform_ip"`
	Type          string `json:"type"`
	BoardRev      int    `json:"board_rev"`
	Cfgversion    string `json:"cfgversion"`
	Mac           string `json:"mac"`
	EthernetTable []struct {
		Mac     string `json:"mac"`
		NumPort int    `json:"num_port"`
		Name    string `json:"name"`
	} `json:"ethernet_table"`
	InformURL     string `json:"inform_url"`
	ConfigNetwork struct {
		Type      string `json:"type"`
		IP        string `json:"ip"`
		DNS1      string `json:"dns1"`
		Netmask   string `json:"netmask"`
		DNS2      string `json:"dns2"`
		Gateway   string `json:"gateway"`
		Dnssuffix string `json:"dnssuffix"`
	} `json:"config_network"`
	LedOverride            string        `json:"led_override"`
	Model                  string        `json:"model"`
	OutdoorModeOverride    string        `json:"outdoor_mode_override"`
	HasEth1                bool          `json:"has_eth1"`
	IP                     string        `json:"ip"`
	XAuthkey               string        `json:"x_authkey"`
	XSSHHostkeyFingerprint string        `json:"x_ssh_hostkey_fingerprint"`
	ScanRadioTable         []interface{} `json:"scan_radio_table"`
	Version                string        `json:"version"`
	VwireTable             []interface{} `json:"vwire_table"`
	XVwirekey              string        `json:"x_vwirekey"`
	CountrycodeTable       []interface{} `json:"countrycode_table"`
	AntennaTable           []struct {
		Default   bool   `json:"default"`
		ID        int    `json:"id"`
		Name      string `json:"name"`
		Wifi0Gain int    `json:"wifi0_gain"`
		Wifi1Gain int    `json:"wifi1_gain"`
	} `json:"antenna_table"`
	Serial        string `json:"serial"`
	WifiCaps      int    `json:"wifi_caps"`
	Name          string `json:"name"`
	SiteID        string `json:"site_id"`
	FwCaps        int    `json:"fw_caps"`
	Adopted       bool   `json:"adopted"`
	WlanOverrides []struct {
		WlanID    string `json:"wlan_id"`
		Radio     string `json:"radio"`
		Name      string `json:"name"`
		RadioName string `json:"radio_name"`
	} `json:"wlan_overrides"`
	Unsupported                bool   `json:"unsupported"`
	UnsupportedReason          int    `json:"unsupported_reason"`
	RequiredVersion            string `json:"required_version"`
	HwCaps                     int    `json:"hw_caps"`
	SysErrorCaps               int    `json:"sys_error_caps"`
	HasFan                     bool   `json:"has_fan"`
	HasTemperature             bool   `json:"has_temperature"`
	TwoPhaseAdopt              bool   `json:"two_phase_adopt"`
	XAesGcm                    bool   `json:"x_aes_gcm"`
	LedOverrideColor           string `json:"led_override_color"`
	LedOverrideColorBrightness int    `json:"led_override_color_brightness"`
	WlangroupIDNa              string `json:"wlangroup_id_na"`
	WlangroupIDNg              string `json:"wlangroup_id_ng"`
	SyslogKey                  string `json:"syslog_key"`
	KernelVersion              string `json:"kernel_version"`
	Architecture               string `json:"architecture"`
	HashID                     string `json:"hash_id"`
	GatewayMac                 string `json:"gateway_mac"`
	ManufacturerID             int    `json:"manufacturer_id"`
	LcmTrackerEnabled          bool   `json:"lcm_tracker_enabled"`
	DeviceID                   string `json:"device_id"`
	State                      int    `json:"state"`
	StartDisconnectedMillis    int64  `json:"start_disconnected_millis"`
	LastSeen                   int    `json:"last_seen"`
	LastUplink                 struct {
		UplinkMac        string `json:"uplink_mac"`
		UplinkRemotePort int    `json:"uplink_remote_port"`
	} `json:"last_uplink"`
	Default               bool   `json:"default"`
	DiscoveredVia         string `json:"discovered_via"`
	AdoptIP               string `json:"adopt_ip"`
	AdoptURL              string `json:"adopt_url"`
	XInformAuthkey        string `json:"x_inform_authkey"`
	Upgradable            bool   `json:"upgradable"`
	AdoptableWhenUpgraded bool   `json:"adoptable_when_upgraded"`
	Rollupgrade           bool   `json:"rollupgrade"`
	KnownCfgversion       string `json:"known_cfgversion"`
	Uptime                int    `json:"uptime"`
	XUptime               int    `json:"_uptime"`
	Locating              bool   `json:"locating"`
	StartConnectedMillis  int64  `json:"start_connected_millis"`
	SysStats              struct {
		Loadavg1  string `json:"loadavg_1"`
		Loadavg15 string `json:"loadavg_15"`
		Loadavg5  string `json:"loadavg_5"`
		MemBuffer int    `json:"mem_buffer"`
		MemTotal  int    `json:"mem_total"`
		MemUsed   int    `json:"mem_used"`
	} `json:"sys_stats"`
	SystemStats struct {
		CPU    string `json:"cpu"`
		Mem    string `json:"mem"`
		Uptime string `json:"uptime"`
	} `json:"system-stats"`
	SSHSessionTable  []interface{} `json:"ssh_session_table"`
	Scanning         bool          `json:"scanning"`
	SpectrumScanning bool          `json:"spectrum_scanning"`
	GuestToken       string        `json:"guest_token"`
	Meshv3PeerMac    string        `json:"meshv3_peer_mac"`
	Satisfaction     int           `json:"satisfaction"`
	HideChWidth      string        `json:"hide_ch_width"`
	Isolated         bool          `json:"isolated"`
	RadioTableStats  []struct {
		Name               string      `json:"name"`
		Channel            int         `json:"channel"`
		LastInterferenceAt int         `json:"last_interference_at,omitempty"`
		Radio              string      `json:"radio"`
		AstTxto            interface{} `json:"ast_txto"`
		AstCst             interface{} `json:"ast_cst"`
		AstBeXmit          int         `json:"ast_be_xmit"`
		CuTotal            int         `json:"cu_total"`
		CuSelfRx           int         `json:"cu_self_rx"`
		CuSelfTx           int         `json:"cu_self_tx"`
		Gain               int         `json:"gain"`
		Satisfaction       int         `json:"satisfaction"`
		State              string      `json:"state"`
		Extchannel         int         `json:"extchannel"`
		TxPower            int         `json:"tx_power"`
		TxPackets          int         `json:"tx_packets"`
		TxRetries          int         `json:"tx_retries"`
		NumSta             int         `json:"num_sta"`
		GuestNumSta        int         `json:"guest-num_sta"`
		UserNumSta         int         `json:"user-num_sta"`
	} `json:"radio_table_stats"`
	Uplink struct {
		FullDuplex       bool   `json:"full_duplex"`
		IP               string `json:"ip"`
		Mac              string `json:"mac"`
		Name             string `json:"name"`
		Netmask          string `json:"netmask"`
		NumPort          int    `json:"num_port"`
		RxBytes          int    `json:"rx_bytes"`
		RxDropped        int    `json:"rx_dropped"`
		RxErrors         int    `json:"rx_errors"`
		RxMulticast      int    `json:"rx_multicast"`
		RxPackets        int    `json:"rx_packets"`
		Speed            int    `json:"speed"`
		TxBytes          int    `json:"tx_bytes"`
		TxDropped        int    `json:"tx_dropped"`
		TxErrors         int    `json:"tx_errors"`
		TxPackets        int    `json:"tx_packets"`
		Up               bool   `json:"up"`
		MaxSpeed         int    `json:"max_speed"`
		Type             string `json:"type"`
		TxBytesR         int    `json:"tx_bytes-r"`
		RxBytesR         int    `json:"rx_bytes-r"`
		UplinkMac        string `json:"uplink_mac"`
		UplinkRemotePort int    `json:"uplink_remote_port"`
	} `json:"uplink"`
	VapTable []struct {
		AnomaliesBarChart struct {
			HighDNSLatency    int `json:"high_dns_latency"`
			HighIcmpRtt       int `json:"high_icmp_rtt"`
			HighTCPLatency    int `json:"high_tcp_latency"`
			HighTCPPacketLoss int `json:"high_tcp_packet_loss"`
			HighWifiLatency   int `json:"high_wifi_latency"`
			HighWifiRetries   int `json:"high_wifi_retries"`
			LowPhyRate        int `json:"low_phy_rate"`
			PoorStreamEff     int `json:"poor_stream_eff"`
			SleepyClient      int `json:"sleepy_client"`
			StaArpTimeout     int `json:"sta_arp_timeout"`
			StaDNSTimeout     int `json:"sta_dns_timeout"`
			StaIPTimeout      int `json:"sta_ip_timeout"`
			WeakSignal        int `json:"weak_signal"`
		} `json:"anomalies_bar_chart"`
		AnomaliesBarChartNow struct {
			HighDNSLatency    int `json:"high_dns_latency"`
			HighIcmpRtt       int `json:"high_icmp_rtt"`
			HighTCPLatency    int `json:"high_tcp_latency"`
			HighTCPPacketLoss int `json:"high_tcp_packet_loss"`
			HighWifiLatency   int `json:"high_wifi_latency"`
			HighWifiRetries   int `json:"high_wifi_retries"`
			LowPhyRate        int `json:"low_phy_rate"`
			PoorStreamEff     int `json:"poor_stream_eff"`
			SleepyClient      int `json:"sleepy_client"`
			StaArpTimeout     int `json:"sta_arp_timeout"`
			StaDNSTimeout     int `json:"sta_dns_timeout"`
			StaIPTimeout      int `json:"sta_ip_timeout"`
			WeakSignal        int `json:"weak_signal"`
		} `json:"anomalies_bar_chart_now"`
		AvgClientSignal     int    `json:"avg_client_signal"`
		Bssid               string `json:"bssid"`
		Ccq                 int    `json:"ccq"`
		Channel             int    `json:"channel"`
		DNSAvgLatency       int    `json:"dns_avg_latency"`
		Essid               string `json:"essid"`
		Extchannel          int    `json:"extchannel,omitempty"`
		IcmpAvgRtt          int    `json:"icmp_avg_rtt"`
		ID                  string `json:"id"`
		MacFilterRejections int    `json:"mac_filter_rejections"`
		Name                string `json:"name"`
		NumSatisfactionSta  int    `json:"num_satisfaction_sta"`
		NumSta              int    `json:"num_sta"`
		Radio               string `json:"radio"`
		RadioName           string `json:"radio_name"`
		ReasonsBarChart     struct {
			PhyRate       int `json:"phy_rate"`
			Signal        int `json:"signal"`
			SleepyClient  int `json:"sleepy_client"`
			StaArpTimeout int `json:"sta_arp_timeout"`
			StaDNSLatency int `json:"sta_dns_latency"`
			StaDNSTimeout int `json:"sta_dns_timeout"`
			StaIcmpRtt    int `json:"sta_icmp_rtt"`
			StaIPTimeout  int `json:"sta_ip_timeout"`
			StreamEff     int `json:"stream_eff"`
			TCPLatency    int `json:"tcp_latency"`
			TCPPacketLoss int `json:"tcp_packet_loss"`
			WifiLatency   int `json:"wifi_latency"`
			WifiRetries   int `json:"wifi_retries"`
		} `json:"reasons_bar_chart"`
		ReasonsBarChartNow struct {
			PhyRate       int `json:"phy_rate"`
			Signal        int `json:"signal"`
			SleepyClient  int `json:"sleepy_client"`
			StaArpTimeout int `json:"sta_arp_timeout"`
			StaDNSLatency int `json:"sta_dns_latency"`
			StaDNSTimeout int `json:"sta_dns_timeout"`
			StaIcmpRtt    int `json:"sta_icmp_rtt"`
			StaIPTimeout  int `json:"sta_ip_timeout"`
			StreamEff     int `json:"stream_eff"`
			TCPLatency    int `json:"tcp_latency"`
			TCPPacketLoss int `json:"tcp_packet_loss"`
			WifiLatency   int `json:"wifi_latency"`
			WifiRetries   int `json:"wifi_retries"`
		} `json:"reasons_bar_chart_now"`
		RxBytes    int `json:"rx_bytes"`
		RxCrypts   int `json:"rx_crypts"`
		RxDropped  int `json:"rx_dropped"`
		RxErrors   int `json:"rx_errors"`
		RxFrags    int `json:"rx_frags"`
		RxNwids    int `json:"rx_nwids"`
		RxPackets  int `json:"rx_packets"`
		RxTCPStats struct {
			Goodbytes  int   `json:"goodbytes"`
			LatAvg     int   `json:"lat_avg"`
			LatMax     int   `json:"lat_max"`
			LatMin     int64 `json:"lat_min"`
			LatSamples int   `json:"lat_samples"`
			LatSum     int   `json:"lat_sum"`
			Stalls     int   `json:"stalls"`
		} `json:"rx_tcp_stats"`
		Satisfaction      int    `json:"satisfaction"`
		SatisfactionNow   int    `json:"satisfaction_now"`
		SatisfactionReal  int    `json:"satisfaction_real"`
		State             string `json:"state"`
		TxBytes           int64  `json:"tx_bytes"`
		TxCombinedRetries int    `json:"tx_combined_retries"`
		TxDataMpduBytes   int    `json:"tx_data_mpdu_bytes"`
		TxDropped         int    `json:"tx_dropped"`
		TxErrors          int    `json:"tx_errors"`
		TxPackets         int    `json:"tx_packets"`
		TxPower           int    `json:"tx_power"`
		TxRetries         int    `json:"tx_retries"`
		TxRtsRetries      int    `json:"tx_rts_retries"`
		TxSuccess         int    `json:"tx_success"`
		TxTCPStats        struct {
			Goodbytes  int   `json:"goodbytes"`
			LatAvg     int   `json:"lat_avg"`
			LatMax     int   `json:"lat_max"`
			LatMin     int64 `json:"lat_min"`
			LatSamples int   `json:"lat_samples"`
			LatSum     int   `json:"lat_sum"`
			Stalls     int   `json:"stalls"`
		} `json:"tx_tcp_stats"`
		TxTotal          int         `json:"tx_total"`
		Up               bool        `json:"up"`
		Usage            string      `json:"usage"`
		WifiTxAttempts   int         `json:"wifi_tx_attempts"`
		WifiTxDropped    int         `json:"wifi_tx_dropped"`
		T                string      `json:"t"`
		WlanconfID       string      `json:"wlanconf_id"`
		IsGuest          bool        `json:"is_guest"`
		IsWep            bool        `json:"is_wep"`
		ApMac            string      `json:"ap_mac"`
		MapID            interface{} `json:"map_id"`
		SiteID           string      `json:"site_id"`
		WifiTxLatencyMov struct {
			Avg        int `json:"avg"`
			Max        int `json:"max"`
			Min        int `json:"min"`
			Total      int `json:"total"`
			TotalCount int `json:"total_count"`
		} `json:"wifi_tx_latency_mov,omitempty"`
	} `json:"vap_table"`
	DownlinkTable      []interface{} `json:"downlink_table"`
	VwireVapTable      []interface{} `json:"vwire_vap_table"`
	BytesD             int           `json:"bytes-d"`
	TxBytesD           int           `json:"tx_bytes-d"`
	RxBytesD           int           `json:"rx_bytes-d"`
	BytesR             int           `json:"bytes-r"`
	PrevNonBusyState   int           `json:"prev_non_busy_state"`
	ConnectRequestIP   string        `json:"connect_request_ip"`
	ConnectRequestPort string        `json:"connect_request_port"`
	LastScan           int           `json:"last_scan"`
	NextInterval       int           `json:"next_interval"`
	NextHeartbeatAt    int           `json:"next_heartbeat_at"`
	ConsideredLostAt   int           `json:"considered_lost_at"`
	Stat               struct {
		Ap struct {
			SiteID                        string    `json:"site_id"`
			O                             string    `json:"o"`
			Oid                           string    `json:"oid"`
			Ap                            string    `json:"ap"`
			Time                          int64     `json:"time"`
			Datetime                      time.Time `json:"datetime"`
			GuestWifi0RxPackets           float64   `json:"guest-wifi0-rx_packets"`
			GuestWifi1RxPackets           float64   `json:"guest-wifi1-rx_packets"`
			UserWifi1RxPackets            int       `json:"user-wifi1-rx_packets"`
			UserWifi0RxPackets            int       `json:"user-wifi0-rx_packets"`
			UserRxPackets                 int       `json:"user-rx_packets"`
			GuestRxPackets                float64   `json:"guest-rx_packets"`
			Wifi0RxPackets                int       `json:"wifi0-rx_packets"`
			Wifi1RxPackets                int       `json:"wifi1-rx_packets"`
			RxPackets                     int       `json:"rx_packets"`
			GuestWifi0RxBytes             float64   `json:"guest-wifi0-rx_bytes"`
			GuestWifi1RxBytes             int       `json:"guest-wifi1-rx_bytes"`
			UserWifi1RxBytes              int64     `json:"user-wifi1-rx_bytes"`
			UserWifi0RxBytes              int64     `json:"user-wifi0-rx_bytes"`
			UserRxBytes                   int64     `json:"user-rx_bytes"`
			GuestRxBytes                  int       `json:"guest-rx_bytes"`
			Wifi0RxBytes                  int64     `json:"wifi0-rx_bytes"`
			Wifi1RxBytes                  int64     `json:"wifi1-rx_bytes"`
			RxBytes                       int64     `json:"rx_bytes"`
			GuestWifi0RxErrors            float64   `json:"guest-wifi0-rx_errors"`
			GuestWifi1RxErrors            float64   `json:"guest-wifi1-rx_errors"`
			UserWifi1RxErrors             float64   `json:"user-wifi1-rx_errors"`
			UserWifi0RxErrors             float64   `json:"user-wifi0-rx_errors"`
			UserRxErrors                  float64   `json:"user-rx_errors"`
			GuestRxErrors                 float64   `json:"guest-rx_errors"`
			Wifi0RxErrors                 float64   `json:"wifi0-rx_errors"`
			Wifi1RxErrors                 float64   `json:"wifi1-rx_errors"`
			RxErrors                      float64   `json:"rx_errors"`
			GuestWifi0RxDropped           float64   `json:"guest-wifi0-rx_dropped"`
			GuestWifi1RxDropped           float64   `json:"guest-wifi1-rx_dropped"`
			UserWifi1RxDropped            float64   `json:"user-wifi1-rx_dropped"`
			UserWifi0RxDropped            float64   `json:"user-wifi0-rx_dropped"`
			UserRxDropped                 float64   `json:"user-rx_dropped"`
			GuestRxDropped                float64   `json:"guest-rx_dropped"`
			Wifi0RxDropped                float64   `json:"wifi0-rx_dropped"`
			Wifi1RxDropped                float64   `json:"wifi1-rx_dropped"`
			RxDropped                     float64   `json:"rx_dropped"`
			GuestWifi0RxCrypts            float64   `json:"guest-wifi0-rx_crypts"`
			GuestWifi1RxCrypts            float64   `json:"guest-wifi1-rx_crypts"`
			UserWifi1RxCrypts             float64   `json:"user-wifi1-rx_crypts"`
			UserWifi0RxCrypts             float64   `json:"user-wifi0-rx_crypts"`
			UserRxCrypts                  float64   `json:"user-rx_crypts"`
			GuestRxCrypts                 float64   `json:"guest-rx_crypts"`
			Wifi0RxCrypts                 float64   `json:"wifi0-rx_crypts"`
			Wifi1RxCrypts                 float64   `json:"wifi1-rx_crypts"`
			RxCrypts                      float64   `json:"rx_crypts"`
			GuestWifi0RxFrags             float64   `json:"guest-wifi0-rx_frags"`
			GuestWifi1RxFrags             float64   `json:"guest-wifi1-rx_frags"`
			UserWifi1RxFrags              float64   `json:"user-wifi1-rx_frags"`
			UserWifi0RxFrags              float64   `json:"user-wifi0-rx_frags"`
			UserRxFrags                   float64   `json:"user-rx_frags"`
			GuestRxFrags                  float64   `json:"guest-rx_frags"`
			Wifi0RxFrags                  float64   `json:"wifi0-rx_frags"`
			Wifi1RxFrags                  float64   `json:"wifi1-rx_frags"`
			RxFrags                       float64   `json:"rx_frags"`
			GuestWifi0TxPackets           float64   `json:"guest-wifi0-tx_packets"`
			GuestWifi1TxPackets           float64   `json:"guest-wifi1-tx_packets"`
			UserWifi1TxPackets            int       `json:"user-wifi1-tx_packets"`
			UserWifi0TxPackets            int       `json:"user-wifi0-tx_packets"`
			UserTxPackets                 int       `json:"user-tx_packets"`
			GuestTxPackets                float64   `json:"guest-tx_packets"`
			Wifi0TxPackets                int       `json:"wifi0-tx_packets"`
			Wifi1TxPackets                int       `json:"wifi1-tx_packets"`
			TxPackets                     int       `json:"tx_packets"`
			GuestWifi0TxBytes             int       `json:"guest-wifi0-tx_bytes"`
			GuestWifi1TxBytes             int       `json:"guest-wifi1-tx_bytes"`
			UserWifi1TxBytes              int64     `json:"user-wifi1-tx_bytes"`
			UserWifi0TxBytes              int64     `json:"user-wifi0-tx_bytes"`
			UserTxBytes                   int64     `json:"user-tx_bytes"`
			GuestTxBytes                  int       `json:"guest-tx_bytes"`
			Wifi0TxBytes                  int64     `json:"wifi0-tx_bytes"`
			Wifi1TxBytes                  int64     `json:"wifi1-tx_bytes"`
			TxBytes                       int64     `json:"tx_bytes"`
			GuestWifi0TxErrors            float64   `json:"guest-wifi0-tx_errors"`
			GuestWifi1TxErrors            float64   `json:"guest-wifi1-tx_errors"`
			UserWifi1TxErrors             float64   `json:"user-wifi1-tx_errors"`
			UserWifi0TxErrors             float64   `json:"user-wifi0-tx_errors"`
			UserTxErrors                  float64   `json:"user-tx_errors"`
			GuestTxErrors                 float64   `json:"guest-tx_errors"`
			Wifi0TxErrors                 float64   `json:"wifi0-tx_errors"`
			Wifi1TxErrors                 float64   `json:"wifi1-tx_errors"`
			TxErrors                      float64   `json:"tx_errors"`
			GuestWifi0TxDropped           float64   `json:"guest-wifi0-tx_dropped"`
			GuestWifi1TxDropped           float64   `json:"guest-wifi1-tx_dropped"`
			UserWifi1TxDropped            float64   `json:"user-wifi1-tx_dropped"`
			UserWifi0TxDropped            float64   `json:"user-wifi0-tx_dropped"`
			UserTxDropped                 float64   `json:"user-tx_dropped"`
			GuestTxDropped                float64   `json:"guest-tx_dropped"`
			Wifi0TxDropped                float64   `json:"wifi0-tx_dropped"`
			Wifi1TxDropped                float64   `json:"wifi1-tx_dropped"`
			TxDropped                     float64   `json:"tx_dropped"`
			GuestWifi0TxRetries           float64   `json:"guest-wifi0-tx_retries"`
			GuestWifi1TxRetries           float64   `json:"guest-wifi1-tx_retries"`
			UserWifi1TxRetries            int64     `json:"user-wifi1-tx_retries"`
			UserWifi0TxRetries            int       `json:"user-wifi0-tx_retries"`
			UserTxRetries                 int64     `json:"user-tx_retries"`
			GuestTxRetries                float64   `json:"guest-tx_retries"`
			Wifi0TxRetries                int       `json:"wifi0-tx_retries"`
			Wifi1TxRetries                int64     `json:"wifi1-tx_retries"`
			TxRetries                     int64     `json:"tx_retries"`
			GuestWifi0MacFilterRejections float64   `json:"guest-wifi0-mac_filter_rejections"`
			GuestWifi1MacFilterRejections float64   `json:"guest-wifi1-mac_filter_rejections"`
			UserWifi1MacFilterRejections  float64   `json:"user-wifi1-mac_filter_rejections"`
			UserWifi0MacFilterRejections  float64   `json:"user-wifi0-mac_filter_rejections"`
			UserMacFilterRejections       float64   `json:"user-mac_filter_rejections"`
			GuestMacFilterRejections      float64   `json:"guest-mac_filter_rejections"`
			Wifi0MacFilterRejections      float64   `json:"wifi0-mac_filter_rejections"`
			Wifi1MacFilterRejections      float64   `json:"wifi1-mac_filter_rejections"`
			MacFilterRejections           float64   `json:"mac_filter_rejections"`
			GuestWifi0WifiTxAttempts      float64   `json:"guest-wifi0-wifi_tx_attempts"`
			GuestWifi1WifiTxAttempts      float64   `json:"guest-wifi1-wifi_tx_attempts"`
			UserWifi1WifiTxAttempts       int       `json:"user-wifi1-wifi_tx_attempts"`
			UserWifi0WifiTxAttempts       int       `json:"user-wifi0-wifi_tx_attempts"`
			UserWifiTxAttempts            int       `json:"user-wifi_tx_attempts"`
			GuestWifiTxAttempts           float64   `json:"guest-wifi_tx_attempts"`
			Wifi0WifiTxAttempts           int       `json:"wifi0-wifi_tx_attempts"`
			Wifi1WifiTxAttempts           int       `json:"wifi1-wifi_tx_attempts"`
			WifiTxAttempts                int       `json:"wifi_tx_attempts"`
			GuestWifi0WifiTxDropped       float64   `json:"guest-wifi0-wifi_tx_dropped"`
			GuestWifi1WifiTxDropped       float64   `json:"guest-wifi1-wifi_tx_dropped"`
			UserWifi1WifiTxDropped        float64   `json:"user-wifi1-wifi_tx_dropped"`
			UserWifi0WifiTxDropped        float64   `json:"user-wifi0-wifi_tx_dropped"`
			UserWifiTxDropped             float64   `json:"user-wifi_tx_dropped"`
			GuestWifiTxDropped            float64   `json:"guest-wifi_tx_dropped"`
			Wifi0WifiTxDropped            float64   `json:"wifi0-wifi_tx_dropped"`
			Wifi1WifiTxDropped            float64   `json:"wifi1-wifi_tx_dropped"`
			WifiTxDropped                 float64   `json:"wifi_tx_dropped"`
			Bytes                         int64     `json:"bytes"`
			Duration                      int       `json:"duration"`
		} `json:"ap"`
	} `json:"stat"`
	TxBytes         int64         `json:"tx_bytes"`
	RxBytes         int64         `json:"rx_bytes"`
	Bytes           int64         `json:"bytes"`
	VwireEnabled    bool          `json:"vwireEnabled"`
	UplinkTable     []interface{} `json:"uplink_table"`
	NumSta          int           `json:"num_sta"`
	UserNumSta      int           `json:"user-num_sta"`
	UserWlanNumSta  int           `json:"user-wlan-num_sta"`
	GuestNumSta     int           `json:"guest-num_sta"`
	GuestWlanNumSta int           `json:"guest-wlan-num_sta"`
	XHasSSHHostkey  bool          `json:"x_has_ssh_hostkey"`
}

func (u *U7LRWifiAP) unmarshal(raw json.RawMessage) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))

	// This could cause issues down the road if new fields are added.
	dec.DisallowUnknownFields()

	if err := dec.Decode(u); err != nil {
		return false
	}

	return true
}

//USC8Switch - 8 Port PoE passthrough switch
type USC8Switch struct {
	ID            string `json:"_id"`
	IP            string `json:"ip"`
	Mac           string `json:"mac"`
	Model         string `json:"model"`
	Type          string `json:"type"`
	Version       string `json:"version"`
	Adopted       bool   `json:"adopted"`
	SiteID        string `json:"site_id"`
	XAuthkey      string `json:"x_authkey"`
	Cfgversion    string `json:"cfgversion"`
	SyslogKey     string `json:"syslog_key"`
	ConfigNetwork struct {
		Type string `json:"type"`
		IP   string `json:"ip"`
	} `json:"config_network"`
	JumboframeEnabled      bool   `json:"jumboframe_enabled"`
	FlowctrlEnabled        bool   `json:"flowctrl_enabled"`
	StpVersion             string `json:"stp_version"`
	StpPriority            string `json:"stp_priority"`
	Dot1XPortctrlEnabled   bool   `json:"dot1x_portctrl_enabled"`
	PowerSourceCtrlEnabled bool   `json:"power_source_ctrl_enabled"`
	LicenseState           string `json:"license_state"`
	XAesGcm                bool   `json:"x_aes_gcm"`
	XFingerprint           string `json:"x_fingerprint"`
	InformURL              string `json:"inform_url"`
	InformIP               string `json:"inform_ip"`
	RequiredVersion        string `json:"required_version"`
	KernelVersion          string `json:"kernel_version"`
	Architecture           string `json:"architecture"`
	HashID                 string `json:"hash_id"`
	GatewayMac             string `json:"gateway_mac"`
	BoardRev               int    `json:"board_rev"`
	ManufacturerID         int    `json:"manufacturer_id"`
	EthernetTable          []struct {
		Mac     string `json:"mac"`
		NumPort int    `json:"num_port,omitempty"`
		Name    string `json:"name"`
	} `json:"ethernet_table"`
	PortTable []struct {
		PortIdx                int           `json:"port_idx"`
		Media                  string        `json:"media"`
		PortPoe                bool          `json:"port_poe"`
		PoeCaps                int           `json:"poe_caps"`
		SpeedCaps              int           `json:"speed_caps"`
		OpMode                 string        `json:"op_mode"`
		PortconfID             string        `json:"portconf_id"`
		Autoneg                bool          `json:"autoneg"`
		Dot1XMode              string        `json:"dot1x_mode"`
		Dot1XStatus            string        `json:"dot1x_status"`
		Enable                 bool          `json:"enable"`
		FlowctrlRx             bool          `json:"flowctrl_rx"`
		FlowctrlTx             bool          `json:"flowctrl_tx"`
		FullDuplex             bool          `json:"full_duplex"`
		IsUplink               bool          `json:"is_uplink"`
		Jumbo                  bool          `json:"jumbo"`
		RxBroadcast            int           `json:"rx_broadcast"`
		RxBytes                int64         `json:"rx_bytes"`
		RxDropped              int           `json:"rx_dropped"`
		RxErrors               int           `json:"rx_errors"`
		RxMulticast            int           `json:"rx_multicast"`
		RxPackets              int           `json:"rx_packets"`
		Satisfaction           int           `json:"satisfaction"`
		SatisfactionReason     int           `json:"satisfaction_reason"`
		Speed                  int           `json:"speed"`
		StpPathcost            int           `json:"stp_pathcost"`
		StpState               string        `json:"stp_state"`
		TxBroadcast            int           `json:"tx_broadcast"`
		TxBytes                int64         `json:"tx_bytes"`
		TxDropped              int           `json:"tx_dropped"`
		TxErrors               int           `json:"tx_errors"`
		TxMulticast            int           `json:"tx_multicast"`
		TxPackets              int           `json:"tx_packets"`
		Up                     bool          `json:"up"`
		TxBytesR               int           `json:"tx_bytes-r"`
		RxBytesR               int           `json:"rx_bytes-r"`
		BytesR                 int           `json:"bytes-r"`
		PortSecurityMacAddress []interface{} `json:"port_security_mac_address,omitempty"`
		Name                   string        `json:"name"`
		Masked                 bool          `json:"masked"`
		AggregatedBy           bool          `json:"aggregated_by"`
		PoeMode                string        `json:"poe_mode,omitempty"`
		PoeEnable              bool          `json:"poe_enable,omitempty"`
		PoeVoltage             string        `json:"poe_voltage,omitempty"`
	} `json:"port_table"`
	SwitchCaps struct {
		FeatureCaps          int `json:"feature_caps"`
		MaxMirrorSessions    int `json:"max_mirror_sessions"`
		MaxAggregateSessions int `json:"max_aggregate_sessions"`
	} `json:"switch_caps"`
	HasFan                     bool   `json:"has_fan"`
	HasTemperature             bool   `json:"has_temperature"`
	HwCaps                     int    `json:"hw_caps"`
	FwCaps                     int    `json:"fw_caps"`
	Satisfaction               int    `json:"satisfaction"`
	SysErrorCaps               int    `json:"sys_error_caps"`
	XSSHHostkeyFingerprint     string `json:"x_ssh_hostkey_fingerprint"`
	LedOverride                string `json:"led_override"`
	LedOverrideColor           string `json:"led_override_color"`
	LedOverrideColorBrightness int    `json:"led_override_color_brightness"`
	OutdoorModeOverride        string `json:"outdoor_mode_override"`
	LcmBrightnessOverride      bool   `json:"lcm_brightness_override"`
	LcmIdleTimeoutOverride     bool   `json:"lcm_idle_timeout_override"`
	Name                       string `json:"name"`
	PortOverrides              []struct {
		PortIdx                int           `json:"port_idx"`
		PortconfID             string        `json:"portconf_id"`
		PortSecurityMacAddress []interface{} `json:"port_security_mac_address"`
		Name                   string        `json:"name"`
	} `json:"port_overrides"`
	Unsupported             bool   `json:"unsupported"`
	UnsupportedReason       int    `json:"unsupported_reason"`
	Serial                  string `json:"serial"`
	DeviceID                string `json:"device_id"`
	State                   int    `json:"state"`
	StartDisconnectedMillis int64  `json:"start_disconnected_millis"`
	XInformAuthkey          string `json:"x_inform_authkey"`
	LastSeen                int    `json:"last_seen"`
	Upgradable              bool   `json:"upgradable"`
	AdoptableWhenUpgraded   bool   `json:"adoptable_when_upgraded"`
	Rollupgrade             bool   `json:"rollupgrade"`
	KnownCfgversion         string `json:"known_cfgversion"`
	Uptime                  int    `json:"uptime"`
	XUptime                 int    `json:"_uptime"`
	Locating                bool   `json:"locating"`
	StartConnectedMillis    int64  `json:"start_connected_millis"`
	PrevNonBusyState        int    `json:"prev_non_busy_state"`
	ConnectRequestIP        string `json:"connect_request_ip"`
	ConnectRequestPort      string `json:"connect_request_port"`
	SysStats                struct {
		Loadavg1  string `json:"loadavg_1"`
		Loadavg15 string `json:"loadavg_15"`
		Loadavg5  string `json:"loadavg_5"`
		MemBuffer int    `json:"mem_buffer"`
		MemTotal  int    `json:"mem_total"`
		MemUsed   int    `json:"mem_used"`
	} `json:"sys_stats"`
	SystemStats struct {
		CPU    string `json:"cpu"`
		Mem    string `json:"mem"`
		Uptime string `json:"uptime"`
	} `json:"system-stats"`
	SSHSessionTable    []interface{} `json:"ssh_session_table"`
	Overheating        bool          `json:"overheating"`
	PowerSource        string        `json:"power_source"`
	PowerSourceVoltage string        `json:"power_source_voltage"`
	TotalMaxPower      int           `json:"total_max_power"`
	DownlinkTable      []struct {
		PortIdx    int    `json:"port_idx"`
		Speed      int    `json:"speed"`
		FullDuplex bool   `json:"full_duplex"`
		Mac        string `json:"mac"`
	} `json:"downlink_table"`
	Uplink struct {
		IP               string `json:"ip"`
		Mac              string `json:"mac"`
		Name             string `json:"name"`
		Netmask          string `json:"netmask"`
		NumPort          int    `json:"num_port"`
		RxBytes          int64  `json:"rx_bytes"`
		RxDropped        int    `json:"rx_dropped"`
		RxErrors         int    `json:"rx_errors"`
		RxMulticast      int    `json:"rx_multicast"`
		RxPackets        int    `json:"rx_packets"`
		TxBytes          int64  `json:"tx_bytes"`
		TxDropped        int    `json:"tx_dropped"`
		TxErrors         int    `json:"tx_errors"`
		TxPackets        int    `json:"tx_packets"`
		PortIdx          int    `json:"port_idx"`
		Media            string `json:"media"`
		Speed            int    `json:"speed"`
		FullDuplex       bool   `json:"full_duplex"`
		MaxSpeed         int    `json:"max_speed"`
		UplinkMac        string `json:"uplink_mac"`
		UplinkRemotePort int    `json:"uplink_remote_port"`
		Type             string `json:"type"`
		TxBytesR         int    `json:"tx_bytes-r"`
		RxBytesR         int    `json:"rx_bytes-r"`
	} `json:"uplink"`
	UplinkDepth     int           `json:"uplink_depth"`
	DhcpServerTable []interface{} `json:"dhcp_server_table"`
	LastUplink      struct {
		UplinkMac string `json:"uplink_mac"`
	} `json:"last_uplink"`
	NextInterval     int         `json:"next_interval"`
	NextHeartbeatAt  int         `json:"next_heartbeat_at"`
	ConsideredLostAt int         `json:"considered_lost_at"`
	Stat             SwitchStats `json:"stat"`
	TxBytes          int64       `json:"tx_bytes"`
	RxBytes          int64       `json:"rx_bytes"`
	Bytes            int64       `json:"bytes"`
	NumSta           int         `json:"num_sta"`
	UserNumSta       int         `json:"user-num_sta"`
	GuestNumSta      int         `json:"guest-num_sta"`
	XHasSSHHostkey   bool        `json:"x_has_ssh_hostkey"`
}

func (u *USC8Switch) unmarshal(raw json.RawMessage) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))

	// This could cause issues down the road if new fields are added.
	dec.DisallowUnknownFields()

	if err := dec.Decode(u); err != nil {
		return false
	}

	return true
}

//SwitchStats -  Stats data for an 8 port switch. I will add more ports defitions when I see the same stats structure for a bigger switch. Can use 'omitempty' to remove fields
type SwitchStats struct {
	Sw struct {
		SiteID           string    `json:"site_id"`
		O                string    `json:"o"`
		Oid              string    `json:"oid"`
		Sw               string    `json:"sw"`
		Time             int64     `json:"time"`
		Datetime         time.Time `json:"datetime"`
		RxPackets        int       `json:"rx_packets"`
		RxBytes          int64     `json:"rx_bytes"`
		RxErrors         float64   `json:"rx_errors"`
		RxDropped        float64   `json:"rx_dropped"`
		RxCrypts         float64   `json:"rx_crypts"`
		RxFrags          float64   `json:"rx_frags"`
		TxPackets        int       `json:"tx_packets"`
		TxBytes          int64     `json:"tx_bytes"`
		TxErrors         float64   `json:"tx_errors"`
		TxDropped        float64   `json:"tx_dropped"`
		TxRetries        float64   `json:"tx_retries"`
		RxMulticast      int       `json:"rx_multicast"`
		RxBroadcast      float64   `json:"rx_broadcast"`
		TxMulticast      int       `json:"tx_multicast"`
		TxBroadcast      int       `json:"tx_broadcast"`
		Bytes            int64     `json:"bytes"`
		Duration         int       `json:"duration"`
		Port1RxPackets   int       `json:"port_1-rx_packets"`
		Port1RxBytes     int64     `json:"port_1-rx_bytes"`
		Port1RxDropped   float64   `json:"port_1-rx_dropped"`
		Port1TxPackets   int       `json:"port_1-tx_packets"`
		Port1TxBytes     int64     `json:"port_1-tx_bytes"`
		Port1RxMulticast int       `json:"port_1-rx_multicast"`
		Port1RxBroadcast float64   `json:"port_1-rx_broadcast"`
		Port1TxMulticast float64   `json:"port_1-tx_multicast"`
		Port1TxBroadcast float64   `json:"port_1-tx_broadcast"`
		Port1RxErrors    float64   `json:"port_1-rx_errors"`
		Port1TxErrors    float64   `json:"port_1-tx_errors"`
		Port2RxPackets   int       `json:"port_2-rx_packets"`
		Port2RxBytes     int64     `json:"port_2-rx_bytes"`
		Port2RxDropped   float64   `json:"port_2-rx_dropped"`
		Port2TxPackets   int       `json:"port_2-tx_packets"`
		Port2TxBytes     int64     `json:"port_2-tx_bytes"`
		Port2RxMulticast float64   `json:"port_2-rx_multicast"`
		Port2RxBroadcast float64   `json:"port_2-rx_broadcast"`
		Port2TxMulticast int       `json:"port_2-tx_multicast"`
		Port2TxBroadcast float64   `json:"port_2-tx_broadcast"`
		Port2RxErrors    float64   `json:"port_2-rx_errors"`
		Port2TxErrors    float64   `json:"port_2-tx_errors"`
		Port3RxPackets   int       `json:"port_3-rx_packets"`
		Port3RxBytes     int64     `json:"port_3-rx_bytes"`
		Port3RxDropped   float64   `json:"port_3-rx_dropped"`
		Port3TxPackets   int       `json:"port_3-tx_packets"`
		Port3TxBytes     int64     `json:"port_3-tx_bytes"`
		Port3RxMulticast float64   `json:"port_3-rx_multicast"`
		Port3RxBroadcast float64   `json:"port_3-rx_broadcast"`
		Port3TxMulticast int       `json:"port_3-tx_multicast"`
		Port3TxBroadcast float64   `json:"port_3-tx_broadcast"`
		Port3RxErrors    float64   `json:"port_3-rx_errors"`
		Port3TxErrors    float64   `json:"port_3-tx_errors"`
		Port5RxPackets   int       `json:"port_5-rx_packets"`
		Port5RxBytes     int64     `json:"port_5-rx_bytes"`
		Port5RxDropped   float64   `json:"port_5-rx_dropped"`
		Port5RxErrors    float64   `json:"port_5-rx_errors"`
		Port5TxPackets   int       `json:"port_5-tx_packets"`
		Port5TxBytes     int64     `json:"port_5tx_bytes"`
		Port5RxMulticast float64   `json:"port_5-rx_multicast"`
		Port5RxBroadcast float64   `json:"port_5-rx_broadcast"`
		Port5TxMulticast int       `json:"port_5-tx_multicast"`
		Port5TxBroadcast float64   `json:"port_5-tx_broadcast"`
		Port5TxErrors    float64   `json:"port_5-tx_errors"`
		Port6RxPackets   int       `json:"port_6-rx_packets"`
		Port6RxBytes     int64     `json:"port_6-rx_bytes"`
		Port6RxDropped   float64   `json:"port_6-rx_dropped"`
		Port6RxErrors    float64   `json:"port_6-rx_errors"`
		Port6TxPackets   int       `json:"port_6-tx_packets"`
		Port6TxBytes     int64     `json:"port_6tx_bytes"`
		Port6RxMulticast float64   `json:"port_6-rx_multicast"`
		Port6RxBroadcast float64   `json:"port_6-rx_broadcast"`
		Port6TxMulticast int       `json:"port_6-tx_multicast"`
		Port6TxBroadcast float64   `json:"port_6-tx_broadcast"`
		Port6TxErrors    float64   `json:"port_6-tx_errors"`
		Port4RxPackets   int       `json:"port_4-rx_packets"`
		Port4RxBytes     int64     `json:"port_4-rx_bytes"`
		Port4RxDropped   float64   `json:"port_4-rx_dropped"`
		Port4RxErrors    float64   `json:"port_4-rx_errors"`
		Port4TxPackets   int       `json:"port_4-tx_packets"`
		Port4TxBytes     int64     `json:"port_4-tx_bytes"`
		Port4RxMulticast float64   `json:"port_4-rx_multicast"`
		Port4RxBroadcast float64   `json:"port_4-rx_broadcast"`
		Port4TxMulticast int       `json:"port_4-tx_multicast"`
		Port4TxBroadcast float64   `json:"port_4-tx_broadcast"`
		Port4TxErrors    float64   `json:"port_4-tx_errors"`
		Port7RxPackets   int       `json:"port_7-rx_packets"`
		Port7RxBytes     int64     `json:"port_7-rx_bytes"`
		Port7RxDropped   float64   `json:"port_7-rx_dropped"`
		Port7TxPackets   int       `json:"port_7-tx_packets"`
		Port7TxBytes     int64     `json:"port_7-tx_bytes"`
		Port7RxMulticast float64   `json:"port_7-rx_multicast"`
		Port7RxBroadcast float64   `json:"port_7-rx_broadcast"`
		Port7TxMulticast int       `json:"port_7-tx_multicast"`
		Port7TxBroadcast float64   `json:"port_7-tx_broadcast"`
		Port7RxErrors    float64   `json:"port_7-rx_errors"`
		Port7TxErrors    float64   `json:"port_7-tx_errors"`
		Port8RxPackets   int       `json:"port_8-rx_packets"`
		Port8RxBytes     int64     `json:"port_8-rx_bytes"`
		Port8RxDropped   float64   `json:"port_8-rx_dropped"`
		Port8TxPackets   int       `json:"port_8-tx_packets"`
		Port8TxBytes     int64     `json:"port_8-tx_bytes"`
		Port8RxMulticast float64   `json:"port_8-rx_multicast"`
		Port8RxBroadcast float64   `json:"port_8-rx_broadcast"`
		Port8TxMulticast int       `json:"port_8-tx_multicast"`
		Port8TxBroadcast float64   `json:"port_8-tx_broadcast"`
		Port8RxErrors    float64   `json:"port_8-rx_errors"`
		Port8TxErrors    float64   `json:"port_8-tx_errors"`
		Port7TxDropped   float64   `json:"port_7-tx_dropped"`
		Port2TxDropped   float64   `json:"port_2-tx_dropped"`
		Port4TxDropped   float64   `json:"port_4-tx_dropped"`
		Port1TxDropped   float64   `json:"port_1-tx_dropped"`
		Port3TxDropped   float64   `json:"port_3-tx_dropped"`
		Port5TxDropped   float64   `json:"port_5-tx_dropped"`
		Port6TxDropped   float64   `json:"port_6-tx_dropped"`
		Port8TxDropped   float64   `json:"port_8-tx_dropped"`
	} `json:"sw"`
}
