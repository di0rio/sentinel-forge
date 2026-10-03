package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:           "sentinelforge",
		Short:         "Detection-as-Code engine for security events",
		SilenceUsage:  true,
		SilenceErrors: true, // printed below, sanitized
	}
	root.AddCommand(replayCmd(), rulesCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", cleanLines(err.Error()))
		os.Exit(1)
	}
}
