package trust

import (
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/spf13/cobra"
)

func newTrustConfigPinCommand(dockerCli command.Streams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pin",
		Short: "Pin specific certificates or CAs for a GUN",
		Args:  cli.NoArgs,
		RunE:  command.ShowHelp(dockerCli.Err()),
	}

	return cmd
}
