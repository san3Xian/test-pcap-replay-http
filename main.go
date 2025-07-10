package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/golang/snappy"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type connKey struct {
	src string
	dst string
}

type connData struct {
	buf   []byte
	start time.Time
}

type parsedReq struct {
	headers       string
	body          []byte
	contentType   string
	contentLength int
	method        string
	path          string
	host          string
}

func main() {
	file := "packet1.pcap"
	if len(os.Args) > 1 {
		file = os.Args[1]
	}
	f, err := os.Open(file)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	handle, err := pcapgo.NewReader(f)
	if err != nil {
		panic(err)
	}

	buffers := make(map[connKey]*connData)
	type result struct {
		src        string
		dst        string
		method     string
		url        string
		timestamp  time.Time
		decodedLen int
		contentLen int
	}
	var results []result
	count := 0

	for {
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			break
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)

		var srcIP, dstIP string
		if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
			ip := ip4.(*layers.IPv4)
			srcIP = ip.SrcIP.String()
			dstIP = ip.DstIP.String()
		} else if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
			ip := ip6.(*layers.IPv6)
			srcIP = ip.SrcIP.String()
			dstIP = ip.DstIP.String()
		}
		if srcIP == "" || dstIP == "" {
			continue
		}
		k := connKey{src: fmt.Sprintf("%s:%d", srcIP, tcp.SrcPort), dst: fmt.Sprintf("%s:%d", dstIP, tcp.DstPort)}
		if len(tcp.Payload) == 0 {
			continue
		}
		cd, ok := buffers[k]
		if !ok {
			cd = &connData{start: ci.Timestamp}
			buffers[k] = cd
		}
		if len(cd.buf) == 0 {
			cd.start = ci.Timestamp
		}
		cd.buf = append(cd.buf, tcp.Payload...)
		for {
			req, rest, ok := parseRequest(cd.buf)
			if !ok {
				break
			}
			cd.buf = rest
			decoded, err := decodeBody(req.contentType, req.body)
			if err != nil {
				log.Printf("WARNING: decode failed for request #%d: %v", count+1, err)
			}
			url := req.path
			if req.host != "" {
				url = req.host + req.path
			}
			results = append(results, result{
				src:        k.src,
				dst:        k.dst,
				method:     req.method,
				url:        url,
				timestamp:  cd.start,
				decodedLen: len(decoded),
				contentLen: req.contentLength,
			})
			count++
			cd.start = ci.Timestamp
		}
	}
	fmt.Printf("Total HTTP requests: %d\n", count)
	for i, r := range results {
		fmt.Printf("Request %d: %s -> %s %s %s at %s decoded length %d, content-length %d\n",
			i+1, r.src, r.dst, r.method, r.url,
			r.timestamp.Format(time.RFC3339), r.decodedLen, r.contentLen)
	}
}

func parseRequest(data []byte) (parsedReq, []byte, bool) {
	var pr parsedReq
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return pr, data, false
	}
	headersPart := data[:headerEnd]
	// parse headers
	lines := strings.Split(string(headersPart), "\r\n")
	if len(lines) == 0 {
		return pr, data, false
	}
	first := lines[0]
	fmt.Sscanf(first, "%s %s", &pr.method, &pr.path)
	var contentLength int
	var ctype string
	var host string
	for _, l := range lines[1:] {
		lower := strings.ToLower(l)
		if strings.HasPrefix(lower, "content-length:") {
			fmt.Sscanf(strings.TrimSpace(l[len("Content-Length:"):]), "%d", &contentLength)
		} else if strings.HasPrefix(lower, "content-type:") {
			ctype = strings.TrimSpace(l[len("Content-Type:"):])
		} else if strings.HasPrefix(lower, "host:") {
			host = strings.TrimSpace(l[len("Host:"):])
		}
	}
	totalLen := headerEnd + 4 + contentLength
	if len(data) < totalLen {
		return pr, data, false
	}
	body := data[headerEnd+4 : totalLen]
	pr = parsedReq{headers: string(headersPart), body: body, contentType: ctype, contentLength: contentLength, method: pr.method, path: pr.path, host: host}
	rest := data[totalLen:]
	return pr, rest, true
}

func decodeBody(ctype string, body []byte) ([]byte, error) {
	ctype = strings.ToLower(strings.TrimSpace(strings.Split(ctype, ";")[0]))
	switch ctype {
	case "application/x-snappy", "application/snappy":
		return snappy.Decode(nil, body)
	case "", "text/plain", "application/json":
		return body, nil
	default:
		return body, nil
	}
}
