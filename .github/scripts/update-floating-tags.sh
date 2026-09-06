#!/usr/bin/env bash
#
# Create or force-update the floating major (vX) and minor (vX.Y) git tags
# to point at the release tag just published by semantic-release.
#
# Usage: update-floating-tags.sh <version> <git-tag>
#   <version>  bare semver, e.g. "1.2.3"
#   <git-tag>  the full release tag, e.g. "v1.2.3"
#
# Invoked from `.releaserc.json` via `@semantic-release/exec`'s `successCmd`,
# after @semantic-release/git has pushed the release commit + tag.

set -euo pipefail

VERSION="${1:?missing version (arg 1)}"
GIT_TAG="${2:?missing git tag (arg 2)}"

MAJOR="${VERSION%%.*}"
REST="${VERSION#"${MAJOR}."}"
MINOR="${REST%%.*}"

MAJOR_TAG="v${MAJOR}"
MINOR_TAG="v${MAJOR}.${MINOR}"

echo "Moving floating tags ${MAJOR_TAG} and ${MINOR_TAG} to ${GIT_TAG}"
git tag --force "${MAJOR_TAG}" "${GIT_TAG}"
git tag --force "${MINOR_TAG}" "${GIT_TAG}"
git push --force origin "${MAJOR_TAG}" "${MINOR_TAG}"
