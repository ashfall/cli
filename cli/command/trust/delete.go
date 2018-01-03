package trust

import (
	"context"
	"fmt"
	"os"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/registry"
	"github.com/spf13/cobra"
	"github.com/theupdateframework/notary/client"
)

func newDeleteCommand(dockerCli command.Cli) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove IMAGE",
		Short: "Delete all trust data and uninitialize trust repo",
		Args:  cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return deleteTrustRepo(dockerCli, args[0])
		},
	}
	return cmd
}

func deleteTrustRepo(cli command.Cli, remote string) error {
	// Ask for confirmation
	in := os.Stdin
	out := cli.Out()
	deleteRemote := command.PromptForConfirmation(in, out, fmt.Sprintf("Please confirm you would like to delete all trust data for %s?", remote))
	if !deleteRemote {
		fmt.Fprintf(cli.Out(), "\nAborting action.\n")
		return nil
	}

	// get ref
	ref, err := reference.ParseNormalizedNamed(remote)
	if err != nil {
		return err
	}

	// Resolve the Repository name from fqn to RepositoryInfo
	repoInfo, err := registry.ParseRepositoryInfo(ref)
	if err != nil {
		return err
	}

	ctx := context.Background()
	authConfig := command.ResolveAuthConfig(ctx, cli, repoInfo.Index)
	server, err := trust.Server(repoInfo.Index)
	if err != nil {
		return err
	}
	tr, err := trust.GetTransport(command.UserAgent(), repoInfo, server, &authConfig, "*")

	notaryRepo, err := trust.GetNotaryRepositoryWithTransport(in, out, repoInfo, server, tr)
	if err != nil {
		return err
	}

	// Delete trust data for this repo
	if err := client.DeleteTrustData(
		trust.GetTrustDirectory(),
		notaryRepo.GetGUN(),
		server,
		tr,
		deleteRemote); err != nil {
		return trust.NotaryError(ref.Name(), err)
	}

	// No need to publish.
	fmt.Println("Successfully deleted all trust data for %s", remote)
	return nil

}
