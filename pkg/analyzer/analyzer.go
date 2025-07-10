// Package analyzer provides functionality to parse pcap files and
// extract HTTP request information.
package analyzer

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

// Result describes information extracted from a single HTTP request.
type Result struct {
	Src        string
	Dst        string
	Method     string
	URL        string
	Timestamp  time.Time
	DecodedLen int
	ContentLen int
}

// Analyze parses the given pcap file and returns a slice of HTTP request results.
func Analyze(file string) ([]Result, int, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	handle, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, 0, err
	}

	type connKey struct{ src, dst string }
	type connData struct {
		buf   []byte
		start time.Time
	}

	buffers := make(map[connKey]*connData)
	var results []Result
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
		tcp := tcpLayer.(*layers.TCP)

		// Determine source/destination IPs
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
		k := connKey{
			src: fmt.Sprintf("%s:%d", srcIP, tcp.SrcPort),
			dst: fmt.Sprintf("%s:%d", dstIP, tcp.DstPort),
		}
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
			results = append(results, Result{
				Src:        k.src,
				Dst:        k.dst,
				Method:     req.method,
				URL:        url,
				Timestamp:  cd.start,
				DecodedLen: len(decoded),
				ContentLen: req.contentLength,
			})
			count++
			cd.start = ci.Timestamp
		}
	}
	return results, count, nil
}

// parsedReq holds intermediate parsed HTTP request data.
type parsedReq struct {
	headers       string
	body          []byte
	contentType   string
	contentLength int
	method        string
	path          string
	host          string
}

// parseRequest attempts to parse a single HTTP request from data.
// It returns the parsed request, the remaining unconsumed bytes, and
// a boolean indicating success.
func parseRequest(data []byte) (parsedReq, []byte, bool) {
	var pr parsedReq
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return pr, data, false
	}
	headersPart := data[:headerEnd]
	lines := strings.Split(string(headersPart), "\r\n")
	if len(lines) == 0 {
		return pr, data, false
	}
	fmt.Sscanf(lines[0], "%s %s", &pr.method, &pr.path)
	var contentLength int
	var ctype, host string
	for _, l := range lines[1:] {
		lower := strings.ToLower(l)
		switch {
		case strings.HasPrefix(lower, "content-length:"):
			fmt.Sscanf(strings.TrimSpace(l[len("Content-Length:"):]), "%d", &contentLength)
		case strings.HasPrefix(lower, "content-type:"):
			ctype = strings.TrimSpace(l[len("Content-Type:"):])
		case strings.HasPrefix(lower, "host:"):
			host = strings.TrimSpace(l[len("Host:"):])
		}
	}
	totalLen := headerEnd + 4 + contentLength
	if len(data) < totalLen {
		return pr, data, false
	}
	body := data[headerEnd+4 : totalLen]
	pr = parsedReq{
		headers:       string(headersPart),
		body:          body,
		contentType:   ctype,
		contentLength: contentLength,
		method:        pr.method,
		path:          pr.path,
		host:          host,
	}
	rest := data[totalLen:]
	return pr, rest, true
}

// decodeBody decodes the request body based on Content-Type.
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
