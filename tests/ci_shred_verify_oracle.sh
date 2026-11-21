#!/usr/bin/env bash
# OmniConnect Sentinel — Out-of-Band CI-Only Anti-Forensic Shred Verification Oracle (CSE-29, ADR-012)
#
# Purpose:
#   Empirically verify NIST SP 800-88 Rev. 2 Clear (3-pass write-through overwrite +
#   read-back SHA-256 verification + MFT/directory rename scrambling + free-space fill)
#   against real loopback ext4 (16 MiB) and FAT32 (36 MiB) filesystem images WITHOUT
#   shipping a single byte of DFIR carving/undelete code inside Sentinel binaries.
#
# Usage:
#   bash tests/ci_shred_verify_oracle.sh --bin target/release/sentinel

set -euo pipefail
export PATH="$PATH:/usr/sbin:/sbin"

SENTINEL_BIN="target/release/sentinel"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --bin requires a path argument" >&2
        exit 2
      fi
      SENTINEL_BIN="$2"
      shift 2
      ;;
    *)
      echo "ERROR: Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! -x "$SENTINEL_BIN" ]]; then
  if [[ -x "target/debug/sentinel" ]]; then
    SENTINEL_BIN="target/debug/sentinel"
  else
    echo "ERROR: Sentinel binary not executable at '$SENTINEL_BIN'" >&2
    exit 1
  fi
fi

SENTINEL_BIN="$(realpath "$SENTINEL_BIN")"
for tool in dd mkfs.ext4 mkfs.vfat mount umount sync grep strings; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "ERROR: Required Linux CI oracle tool '$tool' not found in PATH" >&2
    exit 1
  fi
done

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/sentinel_shred_oracle.XXXXXX")"
LEDGER_DIR="$WORKDIR/ledger_cwd"
mkdir -p "$LEDGER_DIR"
ACTIVE_MNT=""

cleanup() {
  set +e
  if [[ -n "$ACTIVE_MNT" ]] && mountpoint -q "$ACTIVE_MNT" 2>/dev/null; then
    sudo umount "$ACTIVE_MNT" || sudo umount -l "$ACTIVE_MNT"
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

# Count exact occurrences of a fixed canary in a binary image without failing on
# grep exit code 1 (0 matches) under `set -euo pipefail`, while still failing closed
# on grep exit code >= 2 (I/O or invocation error).
count_grep_matches() {
  local needle="$1"
  local file="$2"
  local matches rc=0
  matches="$(grep -a -o -F -- "$needle" "$file")" || rc=$?
  if [[ "$rc" -ge 2 ]]; then
    echo "ERROR: grep failed with exit code ${rc} while scanning '${file}'" >&2
    return "$rc"
  fi
  if [[ -z "$matches" ]]; then
    printf '0\n'
  else
    printf '%s\n' "$matches" | wc -l | tr -d ' '
  fi
}

count_strings_matches() {
  local needle="$1"
  local file="$2"
  local extracted matches rc=0
  extracted="$(strings -n 16 -- "$file")"
  matches="$(printf '%s\n' "$extracted" | grep -o -F -- "$needle")" || rc=$?
  if [[ "$rc" -ge 2 ]]; then
    echo "ERROR: grep failed with exit code ${rc} while scanning strings output for '${file}'" >&2
    return "$rc"
  fi
  if [[ -z "$matches" ]]; then
    printf '0\n'
  else
    printf '%s\n' "$matches" | wc -l | tr -d ' '
  fi
}

# Generate a unique 64-byte high-entropy canary string (exact length: 64 ASCII bytes)
RAND_HEX="$(od -An -tx1 -N 22 /dev/urandom | tr -d ' \n')"
CANARY="SENTINEL_SHRED_CANARY_${RAND_HEX:0:42}"
if [[ "${#CANARY}" -ne 64 ]]; then
  echo "ERROR: Canary length mismatch (${#CANARY} != 64)" >&2
  exit 1
fi

echo "=== OmniConnect Sentinel CI Anti-Forensic Shred Oracle (CSE-29) ==="
echo "Binary: $SENTINEL_BIN"
echo "Canary (64B): $CANARY"

verify_loopback_fs() {
  local fs_type="$1"
  local size_mib="$2"
  local img="$WORKDIR/${fs_type}_loopback.img"
  local mnt="$WORKDIR/mnt_${fs_type}"
  mkdir -p "$mnt"

  echo ""
  echo "--- Testing ${size_mib} MiB loopback ${fs_type} image ---"
  dd if=/dev/zero of="$img" bs=1M count="$size_mib" status=none

  if [[ "$fs_type" == "ext4" ]]; then
    # Reserve 0% blocks (-m 0) so unprivileged runner --fill-free-space reaches all free blocks
    mkfs.ext4 -F -q -m 0 "$img"
    sudo mount -o loop "$img" "$mnt"
    ACTIVE_MNT="$mnt"
    sudo chown "$(id -u):$(id -g)" "$mnt"
  elif [[ "$fs_type" == "fat32" ]]; then
    # FAT32 specification mandates >= 65,525 clusters (~33 MiB minimum at 512B/cluster)
    mkfs.vfat -F 32 -s 1 "$img" >/dev/null
    sudo mount -o "loop,uid=$(id -u),gid=$(id -g)" "$img" "$mnt"
    ACTIVE_MNT="$mnt"
  else
    echo "ERROR: Unsupported filesystem type '$fs_type'" >&2
    exit 2
  fi

  local target="$mnt/canary_target.bin"
  # Write 128 KiB (2,048 repetitions of exact 64-byte canary) so multiple clusters/extents are populated
  for _ in $(seq 1 2048); do
    printf '%s' "$CANARY"
  done > "$target"
  sync

  # Positive control: unmount and verify canary IS present on raw image bytes BEFORE shredding
  sudo umount "$mnt"
  ACTIVE_MNT=""
  local before_matches
  before_matches="$(count_grep_matches "$CANARY" "$img")"
  if [[ "$before_matches" -lt 1 ]]; then
    echo "ERROR: Positive control failed — 64-byte canary not observed in raw ${fs_type} image before shredding!" >&2
    exit 1
  fi
  echo "[Positive Control] Observed ${before_matches} raw canary occurrence(s) in ${fs_type} image prior to shred."

  # Remount and execute Sentinel NIST SP 800-88 Rev. 2 Clear + free-space fill
  if [[ "$fs_type" == "ext4" ]]; then
    sudo mount -o loop "$img" "$mnt"
  else
    sudo mount -o "loop,uid=$(id -u),gid=$(id -g)" "$img" "$mnt"
  fi
  ACTIVE_MNT="$mnt"

  (
    cd "$LEDGER_DIR"
    export SENTINEL_UNIFIED_AUDIT_LEDGER="$LEDGER_DIR/oracle_audit_${fs_type}.jsonl"
    "$SENTINEL_BIN" shred --path "$target" --passes 3 --fill-free-space
  )

  if [[ -e "$target" ]]; then
    echo "ERROR: Target file '$target' still exists after sentinel shred!" >&2
    exit 1
  fi

  sync
  sudo umount "$mnt"
  ACTIVE_MNT=""

  # Forensic verification oracle: scan raw loopback image via BOTH `grep -a` and `strings`
  local grep_hits strings_hits
  grep_hits="$(count_grep_matches "$CANARY" "$img")"
  strings_hits="$(count_strings_matches "$CANARY" "$img")"

  echo "[Oracle Check] ${fs_type} raw image grep -a matches: ${grep_hits}, strings matches: ${strings_hits}"
  if [[ "$grep_hits" -ne 0 || "$strings_hits" -ne 0 ]]; then
    echo "FAIL: Residual canary bytes detected in raw ${fs_type} image (grep=${grep_hits}, strings=${strings_hits})!" >&2
    exit 1
  fi
  echo "PASS: 0 canary matches remaining in raw ${size_mib} MiB ${fs_type} loopback image."
}

# 1. 16 MiB loopback ext4 image
verify_loopback_fs "ext4" 16

# 2. 36 MiB loopback FAT32 image (minimum compliant FAT32 cluster geometry for USB flash emulation)
verify_loopback_fs "fat32" 36

echo ""
echo "ALL CI ANTI-FORENSIC SHRED ORACLE CHECKS PASSED (0 canary matches across ext4 & FAT32)."
