package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
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
				fmt.Printf("Request %d: %s -> %s %s %s at %s decoded length %d, content-length %d\n",
					i+1, r.Src, r.Dst, r.Method, r.URL, r.Timestamp.Format(time.RFC3339), r.DecodedLen, r.ContentLen)
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
			items[i] = fmt.Sprintf("%d: %s %s", i+1, r.Method, r.URL)
		}

		sel := promptui.Select{
			Label: "Select request to replay",
			Items: items,
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

		prompt := promptui.Prompt{Label: "Host", Default: host}
		host, _ = prompt.Run()
		prompt = promptui.Prompt{Label: "Path", Default: path}
		path, _ = prompt.Run()

		scheme := "http"
		schemeSel := promptui.Select{Label: "Scheme", Items: []string{"http", "https"}}
		_, scheme, _ = schemeSel.Run()

		portDefault := "80"
		if scheme == "https" {
			portDefault = "443"
		}
		prompt = promptui.Prompt{Label: "Port", Default: portDefault}
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
			fmt.Println("parse request failed:", err)
			return
		}
		bodyBytes, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
		req.URL.Scheme = scheme
		req.URL.Host = net.JoinHostPort(host, port)
		req.Host = host
		req.URL.Path = path

		resp, info, err := sendRequest(req, scheme, host, port, skipVerify)
		if err != nil {
			fmt.Println("replay failed:", err)
		} else {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			fmt.Printf("DNS lookup took %v, ip %s\n", info.DNS, info.IP)
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

func sendRequest(req *http.Request, scheme, host, port string, skipVerify bool) (*http.Response, replayInfo, error) {
	var info replayInfo
	start := time.Now()
	ips, err := net.LookupIP(host)
	info.DNS = time.Since(start)
	if err == nil && len(ips) > 0 {
		info.IP = ips[0].String()
	}
	target := host
	if info.IP != "" {
		target = info.IP
	}
	d := &net.Dialer{}
	start = time.Now()
	conn, err := d.Dial("tcp", net.JoinHostPort(target, port))
	info.TCP = time.Since(start)
	if err != nil {
		return nil, info, err
	}
	info.LocalAddr = conn.LocalAddr().String()

	var rw net.Conn = conn
	if scheme == "https" {
		tlsStart := time.Now()
		tconn := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: skipVerify})
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
