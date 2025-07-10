package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"test-pcap/pkg/analyzer"
)

func main() {
	var pcapFile string

	rootCmd := &cobra.Command{
		Use:   "pcapreplay",
		Short: "Analyze HTTP requests in a pcap file",
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
			return nil
		},
	}

	rootCmd.Flags().StringVarP(&pcapFile, "file", "f", "", "path to pcap file")
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}
