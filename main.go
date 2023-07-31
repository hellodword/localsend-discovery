// https://gist.github.com/fiorix/9664255
// https://en.wikipedia.org/wiki/Multicast_address
// https://support.mcommstv.com/hc/en-us/articles/202306226-Choosing-multicast-addresses-and-ports

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/hellodword/localsend-discovery/localsend"
)

const (
	broadcastInterval = time.Second * 5
)

func main() {
	var keyPath = path.Join(os.TempDir(), "localsend.key")
	var certPath = path.Join(os.TempDir(), "localsend.cert")

	fingerprint, err := localsend.GenerateCert(certPath, keyPath)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var selfAnounce = localsend.Register{
		Alias:        "Localsend Discovery",
		Version:      "2.0",
		DeviceModel:  "Linux",
		DeviceType:   "desktop",
		FingerPrint:  fingerprint,
		Port:         localsend.Port,
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
		Port:         localsend.Port,
		Protocol:     "https",
		Download:     false,
		Announcement: false,
		Announce:     false,
	}

	http.HandleFunc("/api/localsend/v2/register", httpHandler(selfResponse))
	server := http.Server{
		Addr: fmt.Sprintf("0.0.0.0:%d", localsend.Port),
		// TLSConfig: &tls.Config{
		// 	MinVersion:   tls.VersionTLS13,
		// },
	}
	go func() {
		err = server.ListenAndServeTLS(certPath, keyPath)
		if err != nil { //  && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	go func() {
		err = broadcast(ctx, selfAnounce)
		if err != nil {
			log.Fatal(err)
		}
	}()

	go func() {
		err = listenMulticast(ctx,
			fmt.Sprintf("%s:%d", localsend.MulticastGroup, localsend.Port),
			udpHandler(ctx, selfResponse))
		if err != nil {
			log.Fatal(err)
		}
	}()

	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGTERM)

	select {
	case <-ctx.Done():
		break
	case <-exit:
		server.Shutdown(ctx)
		cancel()
	}
}

func listenMulticast(ctx context.Context,
	address string,
	handler func(*net.UDPAddr, int, []byte)) error {

	addr, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		return err
	}

	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	conn.SetReadBuffer(8192)

	for {
		select {
		case <-ctx.Done():
			return context.Canceled
		default:
			break
		}

		buffer := make([]byte, 8192)
		numBytes, src, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return err
		}

		handler(src, numBytes, buffer)
	}
}

func broadcast(ctx context.Context, self localsend.Register) error {
	addr, err := net.ResolveUDPAddr("udp4",
		fmt.Sprintf("%s:%d", localsend.MulticastGroup, localsend.Port))
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	self.Alias = localsend.GetAlias()
	_, err = conn.Write([]byte(self.String()))
	if err != nil {
		return err
	}

	ticker := time.NewTicker(broadcastInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return context.Canceled
		case <-ticker.C:
			self.Alias = localsend.GetAlias()
			_, err = conn.Write([]byte(self.String()))
			if err != nil {
				return err
			}
		}
	}
}

func httpHandler(self localsend.Register) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			return
		}

		buffer := make([]byte, 8192)
		n, err := req.Body.Read(buffer)
		if (err != io.EOF && err != nil) || n == 0 {
			return
		}

		var r localsend.Register
		err = json.Unmarshal(buffer[:n], &r)
		if err != nil {
			return
		}

		if r.FingerPrint == "" {
			return
		}

		if r.FingerPrint == self.FingerPrint {
			return
		}

		if !r.Announce {
			return
		}

		log.Println("http read from", req.RemoteAddr, string(buffer[:n]))

		b, _ := json.Marshal(self)
		w.Write(b)
	}
}

func udpHandler(ctx context.Context, self localsend.Register) func(*net.UDPAddr, int, []byte) {
	return func(src *net.UDPAddr, n int, msg []byte) {
		var r localsend.Register
		err := json.Unmarshal(msg[:n], &r)
		if err != nil {
			return
		}

		if r.FingerPrint == "" {
			return
		}

		if r.FingerPrint == self.FingerPrint {
			return
		}

		if !r.Announce {
			return
		}

		log.Println("udp read from", src, string(msg[:n]))

		go func() {
			addr, err := net.ResolveUDPAddr("udp4",
				fmt.Sprintf("%s:%d", src.IP.String(), r.Port))
			if err != nil {
				return
			}

			conn, err := net.DialUDP("udp4", nil, addr)
			if err != nil {
				return
			}

			defer conn.Close()

			self.Alias = localsend.GetAlias()
			_, err = conn.Write([]byte(self.String()))
		}()

		go func() {
			localsend.SendHTTP(ctx, src, r, self)
		}()

		return
	}
}
