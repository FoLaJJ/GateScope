package geoip

import "net"

type GeoInfo struct {
	IP       string `json:"ip"`
	Country  string `json:"country"`
	Province string `json:"province"`
	City     string `json:"city"`
	ISP      string `json:"isp"`
	ASN      int    `json:"asn"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
}

type Service struct {
	dbPath string
}

func NewService(dbPath string) *Service {
	return &Service{dbPath: dbPath}
}

func (s *Service) Lookup(ipStr string) *GeoInfo {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	info := &GeoInfo{IP: ipStr}

	if ip.IsLoopback() {
		info.Country = "本地"
		info.City = "Loopback"
		return info
	}
	if ip.IsPrivate() {
		info.Country = "内网"
		info.City = "Private"
		return info
	}

	info.Country = "未知"
	return info
}

func (s *Service) IsAvailable() bool {
	return s.dbPath != ""
}
