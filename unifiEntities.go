package gounifi

//SiteHealth - Site Health entity
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
