# Releasing RepoRook

Releases run only from version tags and require approval through the `npm-release` GitHub environment. The package versions in `cli/package.json` and `mcp-server/package.json` must exactly match the tag.

## One-time bootstrap

npm requires a package to exist before staged publishing can be enabled. Bootstrap `v0.1.0` as follows:

1. Confirm the `reporook` package name and `@reporook` scope are controlled by the maintainer account.
2. Enable two-factor authentication on the npm maintainer account.
3. Create a short-lived granular npm token that can publish both packages and bypass 2FA for automation.
4. Store it only as the `NPM_TOKEN` secret in the `npm-release` GitHub environment.
5. Push the `v0.1.0` tag and approve the protected GitHub deployment after reviewing the packed-artifact smoke results.
6. Confirm both public npm packages and their provenance attestations.

Do not put an npm token in repository files, command history, issues, or chat.

## Retire the bootstrap credential

Immediately after the first release:

1. Configure an npm trusted publisher for each package using repository `cisoventures/RepoRook`, workflow `release.yml`, environment `npm-release`, and stage-publish-only permission.
2. Change each package's publishing access to require 2FA and disallow traditional tokens. Trusted publishing continues to work.
3. Delete the `NPM_TOKEN` GitHub environment secret and revoke every granular token created for the bootstrap.

## Normal staged release

1. Update both package versions and the root lockfile, then merge the tested release commit.
2. Tag that exact commit as `v<version>` and push the tag.
3. Review and approve the protected `npm-release` GitHub deployment.
4. Confirm the workflow stages both npm tarballs through OIDC and creates a draft GitHub release with all three artifacts.
5. Inspect both entries in npm's **Staged Packages** view, then approve each with 2FA.
6. Verify both versions and provenance attestations from the public registry.
7. Publish the matching draft GitHub release.

Never retry a publish blindly after npm has accepted a package or stage. First check the staged-package view and public registry; npm package versions are immutable.

Trusted publishing requires npm 11.5.1 or later. Staged publishing and the `npm trust` command require npm 11.15.0 or later and Node.js 22.14.0 or later. The release workflow pins npm 11.18.0 and uses the current Node.js 22 release.
