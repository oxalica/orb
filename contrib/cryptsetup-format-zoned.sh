#!/usr/bin/env bash
# This script is the workaround for cryptsetup-luksFormat on zoned device
# See: https://gitlab.com/cryptsetup/cryptsetup/-/issues/877
set -euo pipefail

if [[ $# < 1 || ! -b "$1" ]]; then
    echo "Usage: $0 <DEVICE> [CRYPTSETUP_OPTS...]" >&2
    exit 1
fi

if [[ $UID -ne 0 ]]; then
    echo "WARNING: The script is not running as root. Operations may fail." >&2
fi

bdev="$1"
shift
zone_size="$(lsblk --noheadings --nodeps --bytes -o ZONE-SZ "$bdev")"
if [[ ! "$zone_size" =~ [0-9]+ ]]; then
    echo "Invalid zone size for $bdev: $zone_size" >&2
    exit 1
fi

header_size=$(( 16 << 20 ))
format_args=(--luks2-keyslots-size 15M)
if (( zone_size < header_size )); then
    header_size=$zone_size
    format_args=()
fi

echo -n "Reset the first zone of $bdev and format it as LUKS? This will kill all data on the device [y/N]: " >&2
read -r line
if [[ "$line" != [yY] ]]; then
    echo "Cancelled" >&2
    exit 1
fi

header="$(mktemp /dev/shm/header.XXX)"
trap 'rm -vf "$header"' EXIT
truncate -s "$header_size" "$header"

set -x
blkzone reset --offset 0 --count 1 "$bdev"
cryptsetup luksFormat --header "$header" --offset "$(( zone_size >> 9 ))" "${format_args[@]}" "$bdev" "$@"
dd if="$header" of="$bdev" bs=4k count=$(( header_size >> 12 )) oseek=0 conv=notrunc,sync oflag=direct
