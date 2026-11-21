#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

version=${1:-}
if [[ ! $version =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-dev\.[0-9a-f]+)?$ ]]; then
  printf 'Pass a release version such as v0.1.0.\n' >&2
  exit 2
fi

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
destination="$root/bin/release/$version"
staging=$(mktemp -d)
trap 'rm -rf -- "$staging"' EXIT
source_date=$(git log -1 --format=%ct)

copy_licenses() {
  local module_dir=$1 arch=$2 licenses=$3
  local go_root dependencies module dir terms

  go_root=$(cd "$module_dir" && mise exec -- go env GOROOT)
  install -D -m 0644 "$go_root/LICENSE" "$licenses/go/LICENSE"
  install -m 0644 "$go_root/PATENTS" "$licenses/go/PATENTS"

  dependencies=$(
    cd "$module_dir" && mise exec -- env CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go list -deps \
      -f '{{with .Module}}{{if not .Main}}{{.Path}}{{" "}}{{.Dir}}{{end}}{{end}}' "./cmd/revmcp-$module_dir" |
      sort -u
  )
  while IFS=' ' read -r module dir; do
    [[ -n $module && $module != github.com/revmcp/revmcp/proto ]] || continue
    shopt -s nullglob nocaseglob
    terms=("$dir"/{LICENSE*,COPYING*,NOTICE*,PATENTS*})
    shopt -u nullglob nocaseglob
    if (( ${#terms[@]} == 0 )); then
      printf 'No license or notices found for %s\n' "$module" >&2
      return 1
    fi
    mkdir -p "$licenses/$module"
    install -m 0644 -- "${terms[@]}" "$licenses/$module"
  done <<< "$dependencies"
}

package() {
  local role=$1 arch=$2 binary=$3
  local name="revmcp-$role-$version-linux-$arch"
  local package_dir="$staging/$name"

  if ! readelf -l "$binary" | awk '/^[[:space:]]*(INTERP|DYNAMIC)[[:space:]]/ {dynamic = 1} END {exit dynamic}'; then
    printf 'Expected a static ELF binary at %s\n' "$binary" >&2
    return 1
  fi

  install -D -m 0755 "$binary" "$package_dir/$(basename -- "$binary")"
  install -m 0644 LICENSE README.md "$package_dir/"
  if [[ $role == hub ]]; then
    install -D -m 0644 deploy/hub.channels.example.yaml "$package_dir/deploy/hub.channels.example.yaml"
    install -m 0644 deploy/nginx.example.conf "$package_dir/deploy/"
  fi
  copy_licenses "$role" "$arch" "$package_dir/third-party-licenses"

  tar --sort=name --mtime="@$source_date" --owner=0 --group=0 --numeric-owner \
    -C "$staging" -cf - "$name" | gzip -n > "$staging/$name.tar.gz"
}

package hub amd64 bin/revmcp-hub
package agent amd64 bin/revmcp-agent-linux-amd64
package agent arm64 bin/revmcp-agent-linux-arm64

(cd "$staging" && sha256sum -- *.tar.gz > SHA256SUMS)
mkdir -p "$destination"
mv -- "$staging"/*.tar.gz "$staging/SHA256SUMS" "$destination/"
printf 'Release packages written to %s\n' "$destination"
