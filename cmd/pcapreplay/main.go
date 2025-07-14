package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"

	"test-pcap/pkg/analyzer"
)

var version = "dev"

func main() {
	var pcapFile string
	var replay bool

	rootCmd := &cobra.Command{
		Use:     "pcapreplay",
		Short:   "Analyze HTTP requests in a pcap file",
		Version: version,
		RunE: func(cmd *cobra.Command, args []string) error {
			if pcapFile == "" {
				return fmt.Errorf("pcap file required")
			}
			results, count, err := analyzer.Analyze(pcapFile)
			if err != nil {
				return err
			}
			fmt.Printf("Total HTTP requests: %d\n", count)
			for i, r := range results {
				fmt.Printf("Request %d: %s:%d -> %s:%d %s %s at %s decoded length %d, content-length %d\n",
					i+1, r.SrcIP, r.SrcPort, r.DstIP, r.DstPort, r.Method, r.URL, r.Timestamp.Format(time.RFC3339), r.DecodedLen, r.ContentLen)
			}
			if replay {
				interactiveReplay(results)
			}
			return nil
		},
	}

	rootCmd.SetVersionTemplate("pcapreplay version {{.Version}}\n")

	rootCmd.Flags().StringVarP(&pcapFile, "file", "f", "", "path to pcap file")
	rootCmd.Flags().BoolVarP(&replay, "replay", "r", false, "enter interactive replay mode")
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}

// interactiveReplay allows the user to select a captured request and replay it
// with optional modifications.
func interactiveReplay(results []analyzer.Result) {
	for {
		items := make([]string, len(results))
		for i, r := range results {
			loc, _ := time.LoadLocation("Asia/Shanghai")
			ts := r.Timestamp.In(loc)

			items[i] = fmt.Sprintf("%d: %-20s %s %s", i+1, ts.Format(time.RFC3339), r.Method, r.URL)
		}

		sel := promptui.Select{
			Label:             "Select request to replay",
			Items:             items,
			StartInSearchMode: true,
			Searcher: func(input string, index int) bool {
				return strings.Contains(strings.ToLower(items[index]), strings.ToLower(input))
			},
		}
		idx, _, err := sel.Run()
		if err != nil {
			fmt.Println("selection cancelled")
			return
		}
		r := results[idx]

		host := r.Host
		if host == "" {
			host = r.URL
		}
		path := r.Path

		prompt := promptui.Prompt{Label: "Host(with port)", Default: host}
		host, _ = prompt.Run()
		prompt = promptui.Prompt{Label: "Path", Default: path}
		path, _ = prompt.Run()

		scheme := "http"
		schemeSel := promptui.Select{Label: "Scheme", Items: []string{"http", "https"}}
		_, scheme, _ = schemeSel.Run()

		prompt = promptui.Prompt{Label: "DstIP", Default: r.DstIP}
		dstIP, _ := prompt.Run()

		portDefault := r.DstPort
		prompt = promptui.Prompt{Label: "DstPort", Default: fmt.Sprintf("%d", portDefault)}
		port, _ := prompt.Run()

		skipVerify := false
		if scheme == "https" {
			svSel := promptui.Select{Label: "Skip TLS verify?", Items: []string{"no", "yes"}}
			_, ans, _ := svSel.Run()
			if ans == "yes" {
				skipVerify = true
			}
		}

		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(r.Raw)))
		if err != nil {
			fmt.Println("parse request failed: ", err)
			return
		}
		bodyBytes, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
		req.URL.Scheme = scheme
		req.URL.Host = host
		req.Host = host
		req.URL.Path = path
		fmt.Print("Replaying request: \n", req.Method, " ", req.URL.String(), "\n", req.Header, "\n")

		resp, info, err := sendRequest(req, scheme, dstIP, port, skipVerify)
		if err != nil {
			fmt.Println("replay failed:", err)
		} else {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			fmt.Printf("TCP local addr %s, handshake %v\n", info.LocalAddr, info.TCP)
			if scheme == "https" {
				fmt.Printf("TLS handshake %v\n", info.TLS)
			}
			fmt.Printf("Session time %v\n", info.Session)
			fmt.Printf("HTTP/%d.%d %s\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status)
			for k, vals := range resp.Header {
				for _, v := range vals {
					fmt.Printf("%s: %s\n", k, v)
				}
			}
			fmt.Printf("\n%s\n", string(body))
		}

		againSel := promptui.Select{Label: "Replay another?", Items: []string{"no", "yes"}}
		_, again, _ := againSel.Run()
		if again != "yes" {
			return
		}
	}
}

type replayInfo struct {
	DNS       time.Duration
	IP        string
	LocalAddr string
	TCP       time.Duration
	TLS       time.Duration
	Session   time.Duration
}

func sendRequest(req *http.Request, scheme, dstAddr, port string, skipVerify bool) (*http.Response, replayInfo, error) {
	var info replayInfo
	// var ips []net.IP
	var err error
	//if host is an IP address, we skip DNS lookup
	fmt.Print(dstAddr, ":", port)
	if net.ParseIP(dstAddr) != nil {
		info.IP = dstAddr
	} else {
		return nil, info, fmt.Errorf("invalid IP address: %s", dstAddr)
	}
	// else { //在pcap里面不可能是域名
	// 	ips, err = net.LookupIP(dstAddr)
	// 	info.DNS = time.Since(start)
	// }
	// if info.IP == "" && err == nil && len(ips) > 0 {
	// 	info.IP = ips[0].String()
	// }
	// target := dstAddr
	// if info.IP != "" {
	// 	target = info.IP
	// }
	d := &net.Dialer{}
	start := time.Now()
	conn, err := d.Dial("tcp", net.JoinHostPort(dstAddr, port))
	info.TCP = time.Since(start)
	if err != nil {
		return nil, info, err
	}
	info.LocalAddr = conn.LocalAddr().String()

	var rw net.Conn = conn
	if scheme == "https" {
		tlsStart := time.Now()
		tconn := tls.Client(conn, &tls.Config{ServerName: req.Host, InsecureSkipVerify: skipVerify})
		if err := tconn.Handshake(); err != nil {
			return nil, info, err
		}
		info.TLS = time.Since(tlsStart)
		rw = tconn
	}

	start = time.Now()
	if err := req.Write(rw); err != nil {
		return nil, info, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(rw), req)
	info.Session = time.Since(start)
	return resp, info, err
}
