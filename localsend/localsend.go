package localsend

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultAlias = "Localsend Discovery"
)

// {"alias":"...","version":"2.0","deviceModel":"Linux","deviceType":"desktop","fingerprint":"...","port":53317,"protocol":"https","download":false,"announcement":true,"announce":true}
// {"alias":"...","version":"2.0","deviceModel":"iPhone","deviceType":"mobile","fingerprint":"...","port":53317,"protocol":"https","download":false,"announcement":true,"announce":true}
type Register struct {
	Alias        string `json:"alias"`
	Version      string `json:"version"`
	DeviceModel  string `json:"deviceModel,omitempty"`
	DeviceType   string `json:"deviceType,omitempty"`
	FingerPrint  string `json:"fingerprint"`
	Port         uint16 `json:"port,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	Download     bool   `json:"download,omitempty"`
	Announcement bool   `json:"announcement,omitempty"`
	Announce     bool   `json:"announce,omitempty"`
}

func (r Register) Checksum() uint32 {
	return crc32.ChecksumIEEE([]byte(r.Alias + r.Version + r.DeviceModel + r.DeviceType + r.FingerPrint + r.Protocol + fmt.Sprintf("%d", r.Port)))
}

func SendHTTP(origin *net.UDPAddr, originRegister, selfRegister Register) error {
	selfRegister.Alias = GetAlias()
	b, _ := json.Marshal(selfRegister)

	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	var u url.URL
	u.Scheme = originRegister.Protocol
	u.Host = fmt.Sprintf("%s:%d", origin.IP.String(), originRegister.Port)
	u.Path = "/api/localsend/"
	if originRegister.Version == "1.0" {
		u.Path += "v1"
	} else {
		u.Path += "v2"
	}
	u.Path += "/register"
	_, err := c.Post(u.String(), "application/json", bytes.NewReader(b))
	return err
}

func SendUDP(addr string, selfRegister Register, loop bool, interval time.Duration) error {
	selfRegister.Alias = GetAlias()

	b, err := json.Marshal(selfRegister)
	if err != nil {
		return err
	}

	u, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp4", nil, u)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write(b)

	for loop {
		time.Sleep(interval)
		_, err = conn.Write(b)
	}

	return err
}

func GetAlias() string {
	r := []string{defaultAlias}
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		if i.Name == "lo" || i.Name == "docker0" || strings.Index(i.Name, "br-") == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			s := strings.Split(addr.String(), "/")
			if len(s) > 0 {
				if s[0] != "127.0.0.1" && strings.Index(s[0], ".") != -1 {
					r = append(r, s[0])
				}
			}
		}
	}
	return strings.Join(r, "\n")
}
