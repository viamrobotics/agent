#!/bin/bash

# Verify that published viam-agent manifests advertise the sha256 of the object
# their upload-path actually points at.
#
# The manifest and the binary it describes are written by two separate gsutil
# calls, so concurrent runs building the same version can interleave them and
# leave a manifest describing a binary nobody can download. When that happens
# every agent targeting that version rejects its download and retries forever
# (see v1.0.1 windows), so a mismatch is worth failing loudly over.

set -euo pipefail

BUCKET="packages.viam.com"
MANIFEST_DIR="apps/viam-subsystems"
PREFIX="$MANIFEST_DIR/viam-agent-"
BASE_URL="https://storage.googleapis.com"
PLATFORMS="x86_64|aarch64|windows-x86_64|darwin-aarch64"

usage() {
	cat <<'EOF'
Usage:
  verify-manifests.sh --version v1.0.1       every platform for one version
  verify-manifests.sh --count 20             the 20 most recently written manifests
  verify-manifests.sh --count 0              every release manifest
  verify-manifests.sh --count 0 --include-prerelease   ... plus -dev./-pr.
  verify-manifests.sh --version v1.0.1 --fix rewrite mismatched manifests

--fix rewrites a mismatched manifest's sha256 to the published binary's and
re-uploads it, and needs gsutil authenticated for the bucket. It is only the
correct repair when the published binary is the artifact you meant to ship; if
the binary is what is wrong, rebuild the tag instead. Nothing passes --fix
automatically -- the Fix Manifest workflow is the deliberate entry point.
EOF
}

count=""
include_prerelease=false
version_filter=""
fix_mode=false

while [ $# -gt 0 ]; do
	case "$1" in
	--count)
		count="${2:?--count needs a value}"
		shift
		;;
	--include-prerelease)
		include_prerelease=true
		;;
	--version)
		version_filter="${2:?--version needs a value}"
		shift
		;;
	--fix)
		fix_mode=true
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "unknown argument: $1" >&2
		usage >&2
		exit 2
		;;
	esac
	shift
done

if [ -n "$version_filter" ] && [ -n "$count" ]; then
	echo "--version and --count select different things; pass only one" >&2
	exit 2
fi

tmpdir=""
if [ "$fix_mode" = true ]; then
	if ! command -v gsutil >/dev/null; then
		echo "--fix needs gsutil on PATH, authenticated for gs://$BUCKET" >&2
		exit 2
	fi
	tmpdir=$(mktemp -d)
	trap 'rm -rf "$tmpdir"' EXIT
fi

sha256() {
	if command -v sha256sum >/dev/null; then
		sha256sum
	else
		shasum -a 256
	fi
}

# Emit "<updated>\t<object name>" for every object under a prefix. Anonymous
# reads are enough; no gcloud auth required.
list_objects() {
	local prefix="$1" token="" url page
	while :; do
		url="$BASE_URL/storage/v1/b/$BUCKET/o?prefix=$prefix&fields=items(name,updated),nextPageToken&maxResults=1000"
		if [ -n "$token" ]; then
			url="$url&pageToken=$token"
		fi
		page=$(curl -fsS --retry 3 -H "Cache-Control: no-cache" "$url")
		jq -r '.items[]? | "\(.updated)\t\(.name)"' <<<"$page"
		token=$(jq -r '.nextPageToken // empty' <<<"$page")
		if [ -z "$token" ]; then
			break
		fi
	done
}

if [ -n "$version_filter" ]; then
	# Listed under the version's own prefix, so this is one small API call rather
	# than a full bucket listing. The platform-suffix anchor still matters: the
	# prefix v1.0.1- also matches v1.0.1-dev.N, a different set of artifacts.
	escaped=$(printf '%s' "$version_filter" | sed 's/\./\\./g')
	candidates=$(list_objects "$PREFIX$version_filter-" | cut -f2 |
		grep -E "/viam-agent-${escaped}-($PLATFORMS)\.json$" | sort || true)
else
	# Newest first by mtime rather than by version: a clobbered manifest gets a
	# fresh mtime, so the recently-written window is where a race shows up.
	candidates=$(list_objects "$PREFIX" | sort -r | cut -f2)
	if [ "$include_prerelease" != true ]; then
		candidates=$(printf '%s\n' "$candidates" | grep -v -e '-dev\.' -e '-pr\.' || true)
	fi
	if [ "${count:-20}" -gt 0 ]; then
		candidates=$(printf '%s\n' "$candidates" | sed -n "1,${count:-20}p")
	fi
fi

if [ -z "$candidates" ]; then
	echo "no manifests matched gs://$BUCKET/$PREFIX${version_filter}*" >&2
	exit 1
fi

names=()
while IFS= read -r object; do
	names+=("${object##*/}")
done <<<"$candidates"

echo "Checking ${#names[@]} manifest(s) in gs://$BUCKET/$MANIFEST_DIR/"
echo

sha=""
fix_json=""
reason_lines=()

# Compare one manifest against the object its upload-path names. Sets `sha` on
# success, `reason_lines` and `fix_json` on failure.
check_manifest() {
	local name="$1" manifest_url manifest want upload_path binary_url got
	sha=""
	fix_json=""
	reason_lines=()

	manifest_url="$BASE_URL/$BUCKET/$MANIFEST_DIR/$name"
	if ! manifest=$(curl -fsS --retry 3 -H "Cache-Control: no-cache" "$manifest_url"); then
		reason_lines=("manifest not readable at $manifest_url")
		return 1
	fi

	want=$(jq -r '.sha256 // empty' <<<"$manifest")
	upload_path=$(jq -r '."upload-path" // empty' <<<"$manifest")
	if [ -z "$want" ] || [ -z "$upload_path" ]; then
		reason_lines=("manifest is missing sha256 or upload-path")
		return 1
	fi

	binary_url="$BASE_URL/$upload_path"
	if ! got=$(curl -fsSL --retry 3 -H "Cache-Control: no-cache" "$binary_url" | sha256 | cut -d' ' -f1); then
		reason_lines=("cannot download upload-path $binary_url")
		return 1
	fi

	if [ "$want" != "$got" ]; then
		reason_lines=("manifest sha256 $want" "binary   sha256 $got  ($binary_url)")
		# Printed, and applied only under --fix. A mismatch looks the same whether
		# the manifest's sha is wrong or the wrong binary landed at upload-path,
		# and this script cannot tell which; applying it in the second case
		# blesses the wrong artifact for every agent on that version.
		fix_json=$(jq --tab --arg s "$got" '.sha256 = $s' <<<"$manifest")
		reason_lines+=("" "if the object above is the artifact you meant to publish," "correct the manifest with:" "")
		while IFS= read -r line; do
			reason_lines+=("  $line")
		done <<<"$fix_json"
		reason_lines+=("" "  gsutil -h \"Cache-Control:no-cache\" cp $name gs://$BUCKET/$MANIFEST_DIR/" "")
		reason_lines+=("otherwise the binary itself is wrong; see the summary below.")
		return 1
	fi

	sha="$want"
	return 0
}

failures=0
for name in "${names[@]}"; do
	if check_manifest "$name"; then
		echo "ok    $name  $sha"
		continue
	fi

	# An upload writes the binary before the manifest, so re-publishing a version
	# looks like a mismatch until its manifest lands. Re-check once before
	# failing; a real mismatch persists.
	sleep 10
	if check_manifest "$name"; then
		echo "ok    $name  $sha  (cleared on re-check, publish was in flight)"
		continue
	fi

	# --fix only ever repairs the manifest side, which is safe exactly when the
	# published binary is the intended artifact. The workflow makes the caller
	# assert that; the script does not decide it.
	if [ "$fix_mode" = true ] && [ -n "$fix_json" ]; then
		echo "fix   $name  rewriting sha256 to $(jq -r '.sha256' <<<"$fix_json")"
		printf '%s\n' "$fix_json" >"$tmpdir/$name"
		gsutil -h "Cache-Control:no-cache" cp "$tmpdir/$name" "gs://$BUCKET/$MANIFEST_DIR/$name"
		if check_manifest "$name"; then
			echo "ok    $name  $sha  (corrected)"
			continue
		fi
		echo "FAIL  $name  still mismatched after --fix"
	fi

	echo "FAIL  $name"
	printf '        %s\n' "${reason_lines[@]}"
	failures=$((failures + 1))
done

echo
if [ "$failures" -gt 0 ]; then
	echo "$failures of ${#names[@]} manifest(s) do not match the object they point at."
	echo
	echo "Repair with the Fix Manifest workflow, choosing the mode that matches"
	echo "what the object at upload-path actually is:"
	echo
	echo "  mode=manifest  The published binary is the artifact you meant to"
	echo "                 ship and only the sha256 is wrong. Rewrites the"
	echo "                 manifest as printed above. Binaries are untouched."
	echo "                 This is the repair for a concurrent-run clobber."
	echo
	echo "  mode=rebuild   The binary itself is wrong. Rebuilds the tag and"
	echo "                 replaces binary, manifest and MSI together. Windows"
	echo "                 binaries are not reproducible (Authenticode"
	echo "                 timestamps), so this publishes new bytes rather than"
	echo "                 restoring the old ones; linux and darwin rebuild"
	echo "                 byte-identical under -trimpath."
	echo
	echo "Either way, agents cache the bad sha in version_cache.json and"
	echo "version_control.go returns early on an unchanged version string, so"
	echo "expect a version bump or cache clear to unstick machines that already"
	echo "pulled it."
	exit 1
fi
echo "All ${#names[@]} manifest(s) match."
