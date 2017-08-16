package trust

import (
	"fmt"
	"os"

	"github.com/docker/notary/client"
	"github.com/docker/notary/tuf/data"

	"github.com/docker/cli/cli"
	"github.com/docker/cli/cli/command"
	"github.com/docker/cli/cli/trust"
	"github.com/docker/distribution/reference"
	"github.com/spf13/cobra"
)

func newRevokeCommand(dockerCli command.Cli) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke [OPTIONS] IMAGE[:TAG]",
		Short: "Remove trust for an image",
		Args:  cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return revokeTrust(dockerCli, args[0])
		},
	}
	return cmd
}

func revokeTrust(cli command.Cli, remote string) error {
	ref, repoInfo, authConfig, err := getImageReferencesAndAuth(cli, remote)
	if err != nil {
		return err
	}

	var tag reference.NamedTagged

	switch ref.(type) {
	case reference.Digested, reference.Canonical:
		return fmt.Errorf("cannot remove signature for digest")
	case reference.NamedTagged:
		tag = ref.(reference.NamedTagged)
	default:
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
		return trust.NotaryError(ref.Name(), err)
	}

	// Call revokeTrustHelper with
	if err := revokeTrustHelper(cli, notaryRepo, tag); err != nil {
		return fmt.Errorf("could not remove signature for %s: %s", remote, err)
	}

	//  Publish change
	if err := notaryRepo.Publish(); err != nil {
		return trust.NotaryError(ref.Name(), err)
	}

	fmt.Fprintf(cli.Out(), "Successfully deleted signature for %s\n", remote)
	return nil
}

func revokeTrustHelper(cli command.Cli, notaryRepo *client.NotaryRepository, tag reference.NamedTagged) error {
	// make this entirely local.
	if tag != nil {
		if err := revokeSingleSig(notaryRepo, tag.Tag()); err != nil {
			return err
		}
	} else {
		if err := revokeAllSigs(notaryRepo, tag); err != nil {
			return err
		}
	}
	return nil
}

func revokeSingleSig(notaryRepo *client.NotaryRepository, tag string) error {
	releasedTargetWithRole, err := notaryRepo.GetTargetByName(tag, trust.ReleasesRole, data.CanonicalTargetsRole)
	if err != nil {
		return err
	}
	releasedTarget := releasedTargetWithRole.Target

	if err := getSignableRolesForTargetAndRemove(releasedTarget, notaryRepo); err != nil {
		return err
	}
	return nil
}

func revokeAllSigs(notaryRepo *client.NotaryRepository, ref reference.Named) error {

	targetList, err := notaryRepo.ListTargets(trust.ReleasesRole, data.CanonicalTargetsRole)
	if err != nil {
		return err
	}

	releasedTargetList := []client.Target{}
	for _, targetWithRole := range targetList {
		target := targetWithRole.Target
		releasedTargetList = append(releasedTargetList, target)
	}

	// we need all the roles that signed each released target so we can remove from all roles.
	for _, releasedTarget := range releasedTargetList {
		// remove from all roles
		if err := getSignableRolesForTargetAndRemove(releasedTarget, notaryRepo); err != nil {
			return err
		}
	}

	return nil
}

// gets all the roles that signed the target and removes it from all roles.
func getSignableRolesForTargetAndRemove(releasedTarget client.Target, notaryRepo *client.NotaryRepository) error {
	signableRoles, err := getSignableRoles(notaryRepo, &releasedTarget)
	if err != nil {
		return trust.NotaryError(releasedTarget.Name, err)
	}
	// remove from all roles
	if err := notaryRepo.RemoveTarget(releasedTarget.Name, signableRoles...); err != nil {
		return trust.NotaryError(releasedTarget.Name, err)
	}
	return nil
}
