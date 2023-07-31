package localsend

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const (
	Alias = "Localsend Discovery"
	// https://github.com/localsend/localsend/blob/6dd28ce661dcf4b30cef47ac1f57a0ce410f0988/lib/constants.dart#L18-L25
	Port           = 53317
	MulticastGroup = "224.0.0.167"
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

func (r Register) String() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func SendHTTP(ctx context.Context, target *net.UDPAddr, origin, self Register) error {
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	var u url.URL
	u.Scheme = origin.Protocol
	u.Host = fmt.Sprintf("%s:%d", target.IP.String(), origin.Port)
	u.Path = "/api/localsend/"
	if origin.Version == "1.0" {
		u.Path += "v1"
	} else {
		u.Path += "v2"
	}
	u.Path += "/register"

	self.Alias = GetAlias()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader([]byte(self.String())))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	_, err = c.Do(req)

	return err
}

func GetAlias() string {
	r := []string{Alias}
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
					r = append(r, i.Name+" "+s[0])
				}
			}
		}
	}
	return strings.Join(r, "\n")
}
