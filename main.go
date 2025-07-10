package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	f, err := os.Open("packet1.pcap")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	handle, err := pcapgo.NewReader(f)
	if err != nil {
		panic(err)
	}

	for {
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			break
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		app := packet.ApplicationLayer()
		if app != nil {
			payload := string(app.Payload())
			if isHTTPRequest(payload) {
				fmt.Printf("HTTP request found at %v\n", ci.Timestamp)
				fmt.Println(extractRequest(payload))
				fmt.Println()
			}
		}
	}
}

func isHTTPRequest(payload string) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "}
	for _, m := range methods {
		if strings.HasPrefix(payload, m) {
			return true
		}
	}
	return false
}

func extractRequest(payload string) string {
	idx := strings.Index(payload, "\r\n\r\n")
	if idx != -1 {
		return payload[:idx]
	}
	return payload
}
