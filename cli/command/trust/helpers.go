package trust

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/docker/cli/cli/command"
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/registry"
	"github.com/docker/notary/client"
	"github.com/docker/notary/tuf/data"
	"github.com/pkg/errors"
)

func getImageReferencesAndAuth(cli command.Cli, imgName string) (reference.Named, *registry.RepositoryInfo, *types.AuthConfig, error) {
	ref, err := reference.ParseNormalizedNamed(imgName)
	if err != nil {
		return nil, nil, nil, err
	}

	// Resolve the Repository name from fqn to RepositoryInfo
	repoInfo, err := registry.ParseRepositoryInfo(ref)
	if err != nil {
		return nil, nil, nil, err
	}

	ctx := context.Background()
	authConfig := command.ResolveAuthConfig(ctx, cli, repoInfo.Index)
	return ref, repoInfo, &authConfig, err
}

// getSignableRoles returns a list of roles for which we have valid signing
// keys, given a notary repository and a target
func getSignableRoles(repo *client.NotaryRepository, target *client.Target) ([]data.RoleName, error) {
	var signableRoles []data.RoleName
	// translate the full key names, which includes the GUN, into just the key IDs
	allCanonicalKeyIDs := make(map[string]struct{})
	for fullKeyID := range repo.CryptoService.ListAllKeys() {
		allCanonicalKeyIDs[path.Base(fullKeyID)] = struct{}{}
	}

	allDelegationRoles, err := repo.GetDelegationRoles()
	if err != nil {
		return signableRoles, err
	}

	// if there are no delegation roles, then just try to sign it into the targets role
	if len(allDelegationRoles) == 0 {
		signableRoles = append(signableRoles, data.CanonicalTargetsRole)
		return signableRoles, nil
	}

	// there are delegation roles, find every delegation role we have a key for, and
	// attempt to sign into into all those roles.
	for _, delegationRole := range allDelegationRoles {
		// We do not support signing any delegation role that isn't a direct child of the targets role.
		// Also don't bother checking the keys if we can't add the target
		// to this role due to path restrictions
		if path.Dir(delegationRole.Name.String()) != data.CanonicalTargetsRole.String() || !delegationRole.CheckPaths(target.Name) {
			continue
		}

		for _, canonicalKeyID := range delegationRole.KeyIDs {
			if _, ok := allCanonicalKeyIDs[canonicalKeyID]; ok {
				signableRoles = append(signableRoles, delegationRole.Name)
				break
			}
		}
	}

	if len(signableRoles) == 0 {
		return signableRoles, errors.Errorf("no valid signing keys for delegation roles")
	}

	return signableRoles, nil
}

func askConfirm(input io.Reader) bool {
	var res string
	if _, err := fmt.Fscanln(input, &res); err != nil {
		return false
	}
	if strings.EqualFold(res, "y") || strings.EqualFold(res, "yes") {
		return true
	}
	return false
}
