# Release without a running developer machine

The `build, test and release` workflow runs on GitHub-hosted runners. Once an
authorized release commit reaches `main`, GitHub builds Windows, macOS and Linux,
runs the tests, extracts and verifies the core from each package, and publishes
the release with installers and SHA-256 checksums. Closing the desktop app or
turning off the developer machine does not stop these server-side jobs.

The package version in `package.json` chooses the release tag. `prerelease: true`
keeps the release marked as a prerelease. Release text comes from
`docs/releases/v<version>.md`. Publication depends on every package job succeeding;
a failed build cannot publish a partially completed new release.

When a merged pull request has a successful build of the identical source tree,
the workflow reuses its tested packages. Otherwise it builds the merged source.
Pushing an existing release version does not start another release. A manual
`workflow_dispatch` builds artifacts without publishing.

Track progress on the repository's **Actions** page. If a job fails, its log names
the failing step; fix the underlying issue and rerun the failed jobs on GitHub.
GitHub continues already submitted jobs independently, but does not automatically
invent fixes for a failing build or bypass a test failure.
