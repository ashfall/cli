package trust

import (
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/spf13/cobra"
)

func newTrustConfigCommand(dockerCli command.Streams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configure Trust Settings",
		Args:  cli.NoArgs,
		RunE:  command.ShowHelp(dockerCli.Err()),
	}
	cmd.AddCommand(
		newTrustConfigTOFUCommand(dockerCli),
		newTrustConfigPinCommand(dockerCli),
		newTrustConfigServerCommand(dockerCli),
	)
	return cmd
}
