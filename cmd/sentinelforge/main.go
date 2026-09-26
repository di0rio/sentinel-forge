package main

import (
	"os"

	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:          "sentinelforge",
		Short:        "Detection-as-Code engine for security events",
		SilenceUsage: true,
	}
	root.AddCommand(replayCmd(), rulesCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
