package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newInfoCmd returns a diagnostic command that prints registered analyzers
// and their supported kinds. Useful for sanity-checking the build.
func newInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Print registered analyzers and supported resource kinds",
		RunE: func(cmd *cobra.Command, args []string) error {
			reg := buildRegistry()
			fmt.Fprintln(cmd.OutOrStdout(), "Registered analyzers:")
			for _, a := range reg.All() {
				fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", a.Name())
				for _, gvk := range a.SupportedKinds() {
					fmt.Fprintf(cmd.OutOrStdout(), "      %s\n", gvk.String())
				}
			}
			return nil
		},
	}
}
