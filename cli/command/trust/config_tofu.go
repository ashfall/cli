package trust

import (
	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/spf13/cobra"
)

func newTrustConfigTOFUCommand(dockerCli command.Streams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tofu",
		Short: "Enable or disable Trust On First Use Securely mode",
		Args:  cli.NoArgs,
		RunE:  command.ShowHelp(dockerCli.Err()),
	}
	cmd.AddCommand(
		newTOFUEnableCommand(dockerCli),
		newTOFUDisableCommand(dockerCli),
	)
	return cmd
}

func newTOFUEnableCommand(dockerCli command.Streams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable Trust On First Use Securely mode",
		Args:  cli.NoArgs,
		RunE:  command.ShowHelp(dockerCli.Err()),
	}
	return cmd
}

func newTOFUDisableCommand(dockerCli command.Streams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable Trust On First Use Securely mode",
		Args:  cli.NoArgs,
		RunE:  command.ShowHelp(dockerCli.Err()),
	}
	return cmd
}
