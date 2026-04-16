package main

import (
	"github.com/spf13/cobra"
)

// newServeCmd returns a placeholder for the REST API server command.
// We'll flesh this out in the next iteration — the analyze flow has to be
// stable first.
func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "serve",
		Short:  "Run the Foresight REST API server (coming soon)",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("serve: not yet implemented — coming in the next iteration")
			return nil
		},
	}
	return cmd
}
