package gounifi

import "time"

//Events - Events are returned as an array of Event objects
type Events struct {
	Meta   EventsMetaData `json:"meta"`
	Events []Event        `json:"data"`
}

//EventsMetaData - Meta Data about the returned data
type EventsMetaData struct {
	Rc    string `json:"rc"`
	Count int    `json:"count"`
}

// Event - An Event
type Event struct {
	ID          string    `json:"_id"`
	IP          string    `json:"ip,omitempty"`
	Admin       string    `json:"admin,omitempty"`
	SiteID      string    `json:"site_id"`
	IsAdmin     bool      `json:"is_admin,omitempty"`
	Key         string    `json:"key"`
	Subsystem   string    `json:"subsystem"`
	Time        int64     `json:"time"`
	Datetime    time.Time `json:"datetime"`
	Msg         string    `json:"msg"`
	User        string    `json:"user,omitempty"`
	Network     string    `json:"network,omitempty"`
	Ssid        string    `json:"ssid,omitempty"`
	Ap          string    `json:"ap,omitempty"`
	Radio       string    `json:"radio,omitempty"`
	Channel     string    `json:"channel,omitempty"`
	Hostname    string    `json:"hostname,omitempty"`
	Duration    int       `json:"duration,omitempty"`
	Bytes       int       `json:"bytes,omitempty"`
	RadioFrom   string    `json:"radio_from,omitempty"`
	RadioTo     string    `json:"radio_to,omitempty"`
	ChannelFrom string    `json:"channel_from,omitempty"`
	ChannelTo   string    `json:"channel_to,omitempty"`
	Client      string    `json:"client,omitempty"`
	Gw          string    `json:"gw,omitempty"`
	GwName      string    `json:"gw_name,omitempty"`
	VersionFrom string    `json:"version_from,omitempty"`
	VersionTo   string    `json:"version_to,omitempty"`
}
