package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/di0rio/sentinelforge/internal/rule"
)

func rulesCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "rules", Short: "Manage detection rules"}
	cmd.AddCommand(&cobra.Command{
		Use:   "validate [dir]",
		Short: "Validate every rule file in dir (default: rules)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "rules"
			if len(args) == 1 {
				dir = args[0]
			}
			rules, err := rule.LoadDir(dir)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			for _, r := range rules {
				fmt.Fprintf(out, "✓ %s v%d  %s\n", r.ID, r.Version, r.Name)
			}
			fmt.Fprintf(out, "\n%d rules valid\n", len(rules))
			return nil
		},
	})
	return cmd
}
