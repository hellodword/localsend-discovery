// https://gist.github.com/fiorix/9664255
// https://en.wikipedia.org/wiki/Multicast_address
// https://support.mcommstv.com/hc/en-us/articles/202306226-Choosing-multicast-addresses-and-ports

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/hellodword/localsend-discovery/localsend"
	"github.com/hellodword/localsend-discovery/multicast"
)

const (
	// https://github.com/localsend/localsend/blob/6dd28ce661dcf4b30cef47ac1f57a0ce410f0988/lib/constants.dart#L18-L25
	defaultPort           = 53317
	defaultMulticastGroup = "224.0.0.167"

	// maxRetry          = 128
	broadcastInterval = time.Second * 5
)

func main() {
	var keyPath = path.Join(os.TempDir(), "localsend.key")
	var certPath = path.Join(os.TempDir(), "localsend.cert")

	fingerprint, err := localsend.GenerateCert(certPath, keyPath)
	if err != nil {
		log.Fatal(err)
	}

	var selfAnounce = localsend.Register{
		Alias:        "Localsend Discovery",
		Version:      "2.0",
		DeviceModel:  "Linux",
		DeviceType:   "desktop",
		FingerPrint:  fingerprint,
		Port:         defaultPort,
		Protocol:     "https",
		Download:     false,
		Announcement: true,
		Announce:     true,
	}

	var selfResponse = localsend.Register{
		Alias:        "Localsend Discovery",
		Version:      "2.0",
		DeviceModel:  "Linux",
		DeviceType:   "desktop",
		FingerPrint:  fingerprint,
		Port:         defaultPort,
		Protocol:     "https",
		Download:     false,
		Announcement: false,
		Announce:     false,
	}

	http.HandleFunc("/api/localsend/v2/register", httpHandler(selfResponse))
	server := http.Server{
		Addr: fmt.Sprintf("0.0.0.0:%d", defaultPort),
		// TLSConfig: &tls.Config{
		// 	MinVersion:   tls.VersionTLS13,
		// },
	}
	go func() {
		err = server.ListenAndServeTLS(certPath, keyPath)
		log.Println(err)
	}()

	go localsend.SendUDP(fmt.Sprintf("%s:%d", defaultMulticastGroup, defaultPort), selfAnounce, true, broadcastInterval)
	multicast.Listen(fmt.Sprintf("%s:%d", defaultMulticastGroup, defaultPort), udpHandler(selfResponse))
}

func httpHandler(self localsend.Register) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		log.Println("http read from", req.RemoteAddr)
		buffer := make([]byte, 8192)
		n, err := req.Body.Read(buffer)
		if (err != io.EOF && err != nil) || n == 0 {
			return
		}

		var r localsend.Register
		err = json.Unmarshal(buffer, &r)
		if err != nil {
			return
		}

		if r.FingerPrint == "" {
			return
		}

		if r.FingerPrint == self.FingerPrint {
			return
		}

		b, _ := json.Marshal(self)
		w.Write(b)
	}
}

func udpHandler(self localsend.Register) func(*net.UDPAddr, int, []byte) {
	return func(src *net.UDPAddr, n int, msg []byte) {
		var r localsend.Register
		err := json.Unmarshal(msg[:n], &r)
		if err != nil {
			log.Println(err)
			return
		}

		if r.FingerPrint == "" {
			return
		}

		if r.FingerPrint == self.FingerPrint {
			return
		}

		log.Println("udp read from", src, string(msg[:n]))

		go localsend.SendUDP(fmt.Sprintf("%s:%d", src.IP.String(), r.Port), self, false, 0)
		go localsend.SendHTTP(src, r, self)
	}
}
