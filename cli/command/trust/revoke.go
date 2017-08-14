package trust

import (
	"fmt"
	"os"

	"github.com/docker/notary/client"
	"github.com/docker/notary/tuf/data"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/trust"
	"github.com/spf13/cobra"
)

type revokeOptions struct {
	forceYes bool
}

func newRevokeCommand(dockerCli command.Cli) *cobra.Command {
	options := revokeOptions{}
	cmd := &cobra.Command{
		Use:   "revoke [OPTIONS] IMAGE[:TAG]",
		Short: "Remove trust for an image",
		Args:  cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return revokeTrust(dockerCli, args[0], options)
		},
	}
	flags := cmd.Flags()
	flags.BoolVarP(&options.forceYes, "yes", "y", false, "Answer yes to the removal question (no confirmation)")
	return cmd
}

func revokeTrust(cli command.Cli, remote string, options revokeOptions) error {
	_, ref, repoInfo, authConfig, err := getImageReferencesAndAuth(cli, remote)
	if err != nil {
		return err
	}
	tag, err := getTag(ref)
	if err != nil {
		return err
	}
	if tag == "" && !options.forceYes {
		in := os.Stdin
		fmt.Fprintf(
			cli.Out(),
			"Please confirm you would like to delete all signature data for %s? (y/n) ",
			remote,
		)
		deleteRemote := askConfirm(in)
		if !deleteRemote {
			fmt.Fprintf(cli.Out(), "\nAborting action.\n")
			return nil
		}
	}

	notaryRepo, err := trust.GetNotaryRepository(cli, repoInfo, *authConfig, "push", "pull")
	if err != nil {
		return err
	}

	if err := revokeTestHelper(notaryRepo, tag); err != nil {
		return fmt.Errorf("could not remove signature for %s: %s", remote, err)
	}
	fmt.Fprintf(cli.Out(), "Successfully deleted signature for %s\n", remote)
	return nil
}

func revokeTestHelper(notaryRepo *client.NotaryRepository, tag string) error {
	if tag != "" {
		// Revoke signature for the specified tag
		if err := revokeSingleSig(notaryRepo, tag); err != nil {
			return err
		}
	} else {
		// revoke all signatures for the image, as no tag was given
		if err := revokeAllSigs(notaryRepo); err != nil {
			return err
		}
	}

	//  Publish change
	return notaryRepo.Publish()
}

func revokeSingleSig(notaryRepo *client.NotaryRepository, tag string) error {
	releasedTargetWithRole, err := notaryRepo.GetTargetByName(tag, trust.ReleasesRole, data.CanonicalTargetsRole)
	if err != nil {
		return err
	}
	releasedTarget := releasedTargetWithRole.Target
	return getSignableRolesForTargetAndRemove(releasedTarget, notaryRepo)
}

func revokeAllSigs(notaryRepo *client.NotaryRepository) error {

	releasedTargetWithRoleList, err := notaryRepo.ListTargets(trust.ReleasesRole, data.CanonicalTargetsRole)
	if err != nil {
		return err
	}

	// we need all the roles that signed each released target so we can remove from all roles.
	for _, releasedTargetWithRole := range releasedTargetWithRoleList {
		// remove from all roles
		if err := getSignableRolesForTargetAndRemove(releasedTargetWithRole.Target, notaryRepo); err != nil {
			return err
		}
	}
	return nil
}

// get all the roles that signed the target and removes it from all roles.
func getSignableRolesForTargetAndRemove(releasedTarget client.Target, notaryRepo *client.NotaryRepository) error {
	signableRoles, err := getSignableRoles(notaryRepo, &releasedTarget)
	if err != nil {
		return err
	}
	// remove from all roles
	return notaryRepo.RemoveTarget(releasedTarget.Name, signableRoles...)
}
