#!/bin/sh
set -eu

umask 077

usage() {
  cat <<'EOF'
Usage: benchmark-linux.sh --pid PID --output FILE [options]

Measure one explicitly selected Linux process without global process discovery.

Required:
  --pid PID                    Process ID to measure.
  --output FILE                New JSON receipt path; existing files are not overwritten.

Options:
  --duration-seconds N         Requested duration in seconds (default: 900).
  --sample-seconds N           Sampling interval in seconds (default: 5).
  --queue-path FILE            Optional bounded queue file to size without reading it.
  --help                       Show this help.
EOF
}

fail() {
  printf '%s\n' "benchmark error: $*" >&2
  exit 1
}

read_process_snapshot() {
  stat_line=$(cat "/proc/$pid/stat") || fail "cannot read selected process stat"
  stat_fields=${stat_line##*) }
  # /proc/<pid>/stat fields 14/15 are CPU ticks and field 22 is starttime.
  # After removing pid and comm these are fields 12/13 and 20 respectively.
  printf '%s\n' "$stat_fields" | awk '
    NF >= 20 && $12 ~ /^[0-9]+$/ && $13 ~ /^[0-9]+$/ && $20 ~ /^[0-9]+$/ {
      printf "%.0f %.0f\n", $12 + $13, $20
      found = 1
    }
    END { if (!found) exit 1 }
  '
}

require_positive_integer() {
  case "$2" in
    ''|*[!0-9]*) fail "$1 must be a positive integer" ;;
  esac
  [ "$2" -gt 0 ] || fail "$1 must be greater than zero"
}

pid=''
output=''
duration_seconds=900
sample_seconds=5
queue_path=''

while [ "$#" -gt 0 ]; do
  case "$1" in
    --pid)
      [ "$#" -ge 2 ] || fail "--pid requires a value"
      pid=$2
      shift 2
      ;;
    --output)
      [ "$#" -ge 2 ] || fail "--output requires a value"
      output=$2
      shift 2
      ;;
    --duration-seconds)
      [ "$#" -ge 2 ] || fail "--duration-seconds requires a value"
      duration_seconds=$2
      shift 2
      ;;
    --sample-seconds)
      [ "$#" -ge 2 ] || fail "--sample-seconds requires a value"
      sample_seconds=$2
      shift 2
      ;;
    --queue-path)
      [ "$#" -ge 2 ] || fail "--queue-path requires a value"
      queue_path=$2
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

require_positive_integer "pid" "$pid"
require_positive_integer "duration-seconds" "$duration_seconds"
require_positive_integer "sample-seconds" "$sample_seconds"
[ "$duration_seconds" -le 259200 ] || fail "duration-seconds must not exceed 259200 (72 hours)"
[ "$sample_seconds" -le "$duration_seconds" ] || fail "sample-seconds must not exceed duration-seconds"
[ -n "$output" ] || fail "--output is required"
[ ! -e "$output" ] || fail "output already exists: $output"
initial_process_snapshot=$(read_process_snapshot) || fail "invalid selected process stat"
process_start_ticks=${initial_process_snapshot#* }
[ -r "/proc/$pid/stat" ] || fail "cannot read /proc/$pid/stat"
[ -r "/proc/$pid/status" ] || fail "cannot read /proc/$pid/status"
[ -d "/proc/$pid/fd" ] || fail "cannot inspect /proc/$pid/fd"

process_io_available=true
if [ ! -r "/proc/$pid/io" ]; then
  process_io_available=false
fi

for command_name in awk cat date dirname find getconf ln mktemp rm sleep sort stat wc; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: $command_name"
done
find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 -print -quit >/dev/null 2>&1 || fail "cannot inspect /proc/$pid/fd"

output_dir=$(dirname -- "$output")
[ -d "$output_dir" ] || fail "output directory does not exist: $output_dir"

samples_file=$(mktemp "${TMPDIR:-/tmp}/felixwatch-fw0401-samples.XXXXXX")
receipt_file=$(mktemp "$output_dir/.felixwatch-fw0401-receipt.XXXXXX")
cleanup() {
  rm -f -- "$samples_file" "$receipt_file"
}
trap cleanup EXIT HUP INT TERM

read_total_ticks() {
  awk '/^cpu / { total = 0; for (i = 2; i <= NF; i++) total += $i; print total; exit }' /proc/stat
}

ensure_process_identity() {
  current_process_snapshot=$(read_process_snapshot) || fail "invalid or unavailable selected process stat"
  current_start_ticks=${current_process_snapshot#* }
  [ "$current_start_ticks" = "$process_start_ticks" ] || fail "selected PID identity changed during measurement"
  process_ticks=${current_process_snapshot%% *}
}

read_rss_kib() {
  awk '/^VmRSS:/ { print $2; found = 1; exit } END { if (!found) print 0 }' "/proc/$pid/status"
}

read_io_value() {
  if [ "$process_io_available" != true ]; then
    printf '0\n'
    return
  fi
  awk -v key="$1:" '$1 == key { print $2; found = 1; exit } END { if (!found) print 0 }' "/proc/$pid/io"
}

read_fd_count() {
  find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 -printf '.\n' 2>/dev/null | wc -l | awk '{ print $1 }'
}

read_queue_bytes() {
  if [ -z "$queue_path" ] || [ ! -f "$queue_path" ]; then
    printf '0\n'
    return
  fi
  stat -c '%s' -- "$queue_path"
}

column_mean() {
  awk -v column="$1" '{ sum += $column; count++ } END { if (count == 0) print "0.000000"; else printf "%.6f", sum / count }' "$samples_file"
}

column_max() {
  awk -v column="$1" 'NR == 1 || $column > maximum { maximum = $column } END { if (NR == 0) print 0; else print maximum }' "$samples_file"
}

column_p95() {
  awk -v column="$1" '{ print $column }' "$samples_file" | sort -n | awk '{ values[NR] = $1 } END { if (NR == 0) { print 0; exit }; percentile_index = int((NR * 95 + 99) / 100); print values[percentile_index] }'
}

cpu_count=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1\n')
require_positive_integer "online CPU count" "$cpu_count"
sample_count=$(( (duration_seconds + sample_seconds - 1) / sample_seconds ))
[ "$sample_count" -le 100000 ] || fail "benchmark would exceed the 100000-sample limit"
start_unix=$(date +%s)
start_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
previous_total_ticks=$(read_total_ticks)
ensure_process_identity
previous_process_ticks=$process_ticks
read_bytes_start=$(read_io_value read_bytes)
write_bytes_start=$(read_io_value write_bytes)
queue_bytes_start=$(read_queue_bytes)

sample_index=0
while [ "$sample_index" -lt "$sample_count" ]; do
  sleep "$sample_seconds"
  [ -r "/proc/$pid/stat" ] || fail "process exited before benchmark completion"

  total_ticks=$(read_total_ticks)
  ensure_process_identity
  total_delta=$((total_ticks - previous_total_ticks))
  process_delta=$((process_ticks - previous_process_ticks))
  cpu_percent=$(awk -v process_delta="$process_delta" -v total_delta="$total_delta" -v cpu_count="$cpu_count" 'BEGIN { if (total_delta <= 0) print "0.000000"; else printf "%.6f", (process_delta / total_delta) * cpu_count * 100 }')
  rss_kib=$(read_rss_kib)
  fd_count=$(read_fd_count)
  queue_bytes=$(read_queue_bytes)
  printf '%s\t%s\t%s\t%s\n' "$cpu_percent" "$rss_kib" "$fd_count" "$queue_bytes" >> "$samples_file"

  previous_total_ticks=$total_ticks
  previous_process_ticks=$process_ticks
  sample_index=$((sample_index + 1))
done

end_unix=$(date +%s)
end_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ensure_process_identity
read_bytes_end=$(read_io_value read_bytes)
write_bytes_end=$(read_io_value write_bytes)
ensure_process_identity
read_bytes_delta=$((read_bytes_end - read_bytes_start))
write_bytes_delta=$((write_bytes_end - write_bytes_start))
[ "$read_bytes_delta" -ge 0 ] || read_bytes_delta=0
[ "$write_bytes_delta" -ge 0 ] || write_bytes_delta=0

cpu_mean=$(column_mean 1)
cpu_p95=$(column_p95 1)
cpu_max=$(column_max 1)
rss_mean=$(column_mean 2)
rss_p95=$(column_p95 2)
rss_max=$(column_max 2)
fd_mean=$(column_mean 3)
fd_p95=$(column_p95 3)
fd_max=$(column_max 3)
queue_mean=$(column_mean 4)
queue_p95=$(column_p95 4)
queue_max=$(column_max 4)
queue_bytes_end=$(read_queue_bytes)

cat > "$receipt_file" <<EOF
{
  "profile": "FELIX_WATCH_FW_0401_RESOURCE_BENCHMARK_V1",
  "status": "MEASUREMENT_ONLY_NOT_PHYSICAL_ACCEPTANCE",
  "pid": $pid,
  "process_start_ticks": $process_start_ticks,
  "started_at_utc": "$start_utc",
  "ended_at_utc": "$end_utc",
  "actual_duration_seconds": $((end_unix - start_unix)),
  "requested_duration_seconds": $duration_seconds,
  "sample_interval_seconds": $sample_seconds,
  "samples": $sample_count,
  "online_cpu_count": $cpu_count,
  "capabilities": {"process_io": $process_io_available},
  "cpu_percent": {"mean": $cpu_mean, "p95": $cpu_p95, "max": $cpu_max},
  "rss_kib": {"mean": $rss_mean, "p95": $rss_p95, "max": $rss_max},
  "file_descriptors": {"mean": $fd_mean, "p95": $fd_p95, "max": $fd_max},
  "process_io_bytes": {"read_delta": $read_bytes_delta, "write_delta": $write_bytes_delta},
  "queue_bytes": {"start": $queue_bytes_start, "end": $queue_bytes_end, "mean": $queue_mean, "p95": $queue_p95, "max": $queue_max},
  "privacy": {"global_process_scan": false, "command_line_read": false, "environment_read": false, "queue_content_read": false}
}
EOF

ln -- "$receipt_file" "$output" || fail "output was created concurrently and was not overwritten: $output"
rm -f -- "$receipt_file"
trap - EXIT HUP INT TERM
rm -f -- "$samples_file"
printf '%s\n' "$output"
