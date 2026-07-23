# Releasing RepoRook

Releases run only from version tags and require approval through the `npm-release` GitHub environment. The package versions in `cli/package.json` and `mcp-server/package.json` must exactly match the tag.

## First release bootstrap

npm requires a package to exist before staged publishing can be enabled. Bootstrap `v0.1.0` as follows:

1. Confirm the `reporook` package name and `@reporook` scope are controlled by the maintainer account.
2. Enable two-factor authentication on the npm maintainer account.
3. Create a short-lived granular npm token that can publish both packages and bypass 2FA for automation.
4. Store it only as the `NPM_TOKEN` secret in the `npm-release` GitHub environment.
5. Push the `v0.1.0` tag and approve the protected GitHub deployment after reviewing the packed-artifact smoke results.
6. Confirm both public npm packages and their provenance attestations.

Do not put an npm token in repository files, command history, issues, or chat.

## Remove the bootstrap credential

Immediately after the first release:

1. Configure an npm trusted publisher for each package using repository `cisoventures/RepoRook`, workflow `release.yml`, environment `npm-release`, and stage-publish-only permission.
2. Delete the `NPM_TOKEN` GitHub environment secret and revoke the granular npm token.
3. Change the workflow from `npm publish` to `npm stage publish`.
4. For each later release, inspect the staged tarballs and approve them with npm 2FA before they become public.

Trusted publishing requires npm 11.5.1 or later. Staged publishing and the `npm trust` command require npm 11.15.0 or later and Node.js 22.14.0 or later. The release workflow pins npm 11.18.0 and uses the current Node.js 22 release.
