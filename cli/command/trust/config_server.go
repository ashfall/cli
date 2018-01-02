package trust

import (
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/spf13/cobra"
)

func newTrustConfigServerCommand(dockerCli command.Streams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Configure the notary server location for a given image name",
		Args:  cli.NoArgs,
		RunE:  command.ShowHelp(dockerCli.Err()),
	}

	return cmd
}
