package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/golang/snappy"
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
			payload := app.Payload()
			if isHTTPRequest(payload) {
				fmt.Printf("HTTP request found at %v\n", ci.Timestamp)
				header, body := splitRequest(payload)
				fmt.Println(string(header))

				if len(body) > 0 {
					decoded, err := io.ReadAll(snappy.NewReader(bytes.NewReader(body)))
					if err != nil {
						fmt.Println("snappy decode error:", err)
					} else {
						fmt.Printf("Decoded body (%d bytes)\n", len(decoded))
						os.Stdout.Write(decoded)
						fmt.Println()
					}
				}

				fmt.Println()
			}
		}
	}
}

func isHTTPRequest(payload []byte) bool {
	methods := [][]byte{
		[]byte("GET "),
		[]byte("POST "),
		[]byte("PUT "),
		[]byte("DELETE "),
		[]byte("HEAD "),
		[]byte("OPTIONS "),
		[]byte("PATCH "),
	}
	for _, m := range methods {
		if bytes.HasPrefix(payload, m) {
			return true
		}
	}
	return false
}

func splitRequest(payload []byte) ([]byte, []byte) {
	idx := bytes.Index(payload, []byte("\r\n\r\n"))
	if idx != -1 {
		return payload[:idx], payload[idx+4:]
	}
	return payload, nil
}
