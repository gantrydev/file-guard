#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
requested_release=${FILE_GUARD_RELEASE_TAG:-latest}
local_deb=${FILE_GUARD_DEB_PATH:-}
docker_bin=${DOCKER:-docker}
require_fuse=${FILE_GUARD_REQUIRE_FUSE:-1}

command -v "$docker_bin" >/dev/null || {
    echo "error: Docker is required (set DOCKER to its executable)" >&2
    exit 1
}
tmp_dir=$(mktemp -d)
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

if [[ -n "$local_deb" ]]; then
    [[ "$requested_release" != latest ]] || {
        echo "error: FILE_GUARD_RELEASE_TAG is required with FILE_GUARD_DEB_PATH" >&2
        exit 1
    }
    deb_path=$(realpath "$local_deb")
    [[ -r "$deb_path" ]] || {
        echo "error: local Debian package is not readable at $deb_path" >&2
        exit 1
    }
    release_tag=$requested_release
    asset_name=$(basename "$deb_path")
    asset_digest=''
    echo "Testing local package $asset_name before publication"
else
    command -v curl >/dev/null || {
        echo "error: curl is required to download the release asset" >&2
        exit 1
    }
    command -v python3 >/dev/null || {
        echo "error: python3 is required to resolve the release asset metadata" >&2
        exit 1
    }

    if [[ "$requested_release" == latest ]]; then
        api_url="https://api.github.com/repos/gantrydev/file-guard/releases/latest"
    else
        api_url="https://api.github.com/repos/gantrydev/file-guard/releases/tags/${requested_release}"
    fi
    release_json="$tmp_dir/release.json"
    echo "Resolving Debian asset from $api_url"
    curl --fail --silent --show-error --location \
        --header 'Accept: application/vnd.github+json' \
        --retry 3 --retry-delay 1 \
        "$api_url" >"$release_json"

    mapfile -t asset_info < <(python3 - "$release_json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    release = json.load(handle)

assets = [
    asset
    for asset in release.get("assets", [])
    if asset.get("name", "").startswith("file-guard_")
    and asset.get("name", "").endswith("_amd64.deb")
]
if len(assets) != 1:
    raise SystemExit(f"expected exactly one amd64 Debian asset, found {len(assets)}")

asset = assets[0]
print(release["tag_name"])
print(asset["name"])
print(asset["browser_download_url"])
print(asset.get("digest") or "")
PY
    )

    if [[ "${#asset_info[@]}" -ne 4 || -z "${asset_info[0]}" || -z "${asset_info[1]}" || -z "${asset_info[2]}" ]]; then
        echo "error: GitHub release did not contain a usable amd64 .deb asset" >&2
        exit 1
    fi

    release_tag=${asset_info[0]}
    asset_name=${asset_info[1]}
    asset_url=${asset_info[2]}
    asset_digest=${asset_info[3]}
    deb_path="$tmp_dir/$asset_name"
    echo "Downloading $asset_name"
    curl --fail --silent --show-error --location \
        --retry 3 --retry-delay 1 \
        "$asset_url" -o "$deb_path"
fi

image=${FILE_GUARD_DEB_TEST_IMAGE:-file-guard-deb-test:${release_tag#v}}

if [[ -n "$asset_digest" ]]; then
    expected_digest=${asset_digest#sha256:}
    actual_digest=$(sha256sum "$deb_path" | awk '{print $1}')
    [[ "$actual_digest" == "$expected_digest" ]] || {
        echo "error: downloaded asset digest mismatch" >&2
        exit 1
    }
    echo "Verified release digest $actual_digest"
fi

echo "Building integration-test image $image"
"$docker_bin" build \
    --pull \
    --platform linux/amd64 \
    --file "$repo_root/Dockerfile.deb.test" \
    --tag "$image" \
    "$repo_root"

echo "Running package integration checks"
docker_args=(
    --rm
    --platform linux/amd64
    --security-opt=no-new-privileges
    --mount "type=bind,src=$deb_path,dst=/tmp/file-guard.deb,readonly"
    --env "FILE_GUARD_EXPECTED_VERSION=${release_tag#v}"
    --env "FILE_GUARD_REQUIRE_FUSE=$require_fuse"
)
if [[ -c /dev/fuse ]]; then
    docker_args+=(
        --device /dev/fuse
        --cap-add SYS_ADMIN
        --security-opt apparmor=unconfined
    )
elif [[ "$require_fuse" == 1 ]]; then
    echo "error: /dev/fuse is required (set FILE_GUARD_REQUIRE_FUSE=0 for package-only checks)" >&2
    exit 1
fi

"$docker_bin" run "${docker_args[@]}" \
    "$image"
