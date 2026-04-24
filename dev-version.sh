#!/bin/bash
# dev-version.sh -- generates version labels for prereleases.
#   main/manual CI builds: 'viam-agent-v0.15.1-dev.4-<arch>' (commits past last tag)
#   PR dev-release builds: 'viam-agent-v0.15.1-pr.<head-sha>-<arch>' (unique per commit)
# To test locally, comment out the `git status` stanza and do:
# `GITHUB_REF_NAME=main ./dev-setup.sh` (to just see the version)
# `GITHUB_REF_NAME=main make all` (for an actual build)

# Exit with a blank if tree is dirty
if [ -n "$(git status -s)" ]; then
	exit 0
fi

# See if we have a direct tag
DIRECT_TAG=$(git tag --points-at | tr - \~ | sort -Vr | tr \~ - | head -n1)
if [ -n "$DIRECT_TAG" ]; then
	echo ${DIRECT_TAG}
	exit 0
fi

if [ -z "$GITHUB_REF_NAME" ]; then
	GITHUB_REF_NAME=$(git rev-parse --abbrev-ref HEAD)
fi

# Outside of CI, only main gets an automated version (avoids local branch
# builds producing CI-looking version labels).
if [ -z "$GITHUB_ACTIONS" ] && [ "$GITHUB_REF_NAME" != "main" ]; then
	exit 0
fi

# If we don't have a direct tag, use the most recent non-RC tag
DESC=$(git describe --tags --match="v*" --exclude="*-rc*" --long | sed 's/^v//')

BASE_VERSION=$(echo "$DESC" | cut -d'-' -f1)
COMMITS_SINCE_TAG=$(echo "$DESC" | cut -d'-' -f2)

# Calculate next version by incrementing patch number
NEXT_VERSION=$(echo "$BASE_VERSION" | awk -F. '{$3+=1}1' OFS=.)

# Set TAG_VERSION based on commits since last tag
if [ "$COMMITS_SINCE_TAG" -eq 0 ]; then
	TAG_VERSION="$BASE_VERSION"
elif [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then
	# PR builds use the head commit SHA for unambiguous provenance across
	# simultaneous PRs branched from the same base. PR_HEAD_SHA is plumbed
	# from github.event.pull_request.head.sha; fall back to HEAD for local use.
	TAG_VERSION="${NEXT_VERSION}-pr.${PR_HEAD_SHA:-$(git rev-parse HEAD)}"
else
	TAG_VERSION="${NEXT_VERSION}-dev.${COMMITS_SINCE_TAG}"
fi

# Set PATH_VERSION based on TAG_VERSION
PATH_VERSION="v${TAG_VERSION}"

echo ${PATH_VERSION}
