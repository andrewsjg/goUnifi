package gounifi

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
