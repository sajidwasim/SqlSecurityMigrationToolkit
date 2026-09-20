#!/usr/bin/env python3
"""Summarize timestamped PLAN log phases without double-counting nested intervals.

Accepts an ignored, local Session.log. Prints aggregate JSON; does not upload data,
change SQL state, or assume all time outside POSTPLAN markers is planning CPU.
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

STAMP = re.compile(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})\s+\[\w+\]\s+(.*)$')
MARKER = re.compile(r'\bPOSTPLAN\s+(START|END):\s*([\w-]+)')
SQL_MS = re.compile(r'\bElapsedMs=(\d+)\b')


def summarize(text):
    first = last = None
    started = defaultdict(list)
    phases = defaultdict(list)
    unmatched_ends = []
    sql_samples = []
    for line in text.splitlines():
        entry = STAMP.match(line)
        if not entry:
            continue
        ts = datetime.strptime(entry.group(1), '%Y-%m-%d %H:%M:%S.%f')
        first = ts if first is None else min(first, ts)
        last = ts if last is None else max(last, ts)
        msg = entry.group(2)
        marker = MARKER.search(msg)
        if marker:
            event, name = marker.groups()
            if event == 'START':
                started[name].append(ts)
            elif started[name]:
                begin = started[name].pop()
                if ts >= begin:
                    phases[name].append((begin, ts))
            else:
                unmatched_ends.append(name)
        # An elapsed SQL measurement is not a wall-clock phase; report separately.
        if 'POSTPLAN' not in msg:
            sample = SQL_MS.search(msg)
            if sample:
                sql_samples.append(int(sample.group(1)))
    intervals = sorted((a, b) for values in phases.values() for a, b in values)
    occupied = 0.0
    if intervals:
        start, end = intervals[0]
        for a, b in intervals[1:]:
            if a <= end:
                end = max(end, b)
            else:
                occupied += (end - start).total_seconds()
                start, end = a, b
        occupied += (end - start).total_seconds()
    wall = (last - first).total_seconds() if first and last else None
    durations = {name: round(sum((b - a).total_seconds() for a, b in values), 3)
                 for name, values in sorted(phases.items())}
    return {
        'wall_seconds_between_first_last_log': wall,
        'phase_duration_seconds_inclusive_may_overlap': durations,
        'union_of_measured_phase_seconds': round(occupied, 3),
        'time_outside_measured_phase_intervals_seconds': round(max(wall - occupied, 0), 3) if wall is not None else None,
        'sum_of_sql_ElapsedMs_samples': sum(sql_samples),
        'sql_sample_count': len(sql_samples),
        'unclosed_phases': {k: len(v) for k, v in started.items() if v},
        'unmatched_end_markers': unmatched_ends,
        'limitations': 'Do not add overlapping inclusive phases. SQL ElapsedMs samples can occur inside measured phases and must not be added to wall time. Unattributed time is not proven CPU time.'
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('session_log', type=Path)
    args = parser.parse_args(argv)
    try:
        result = summarize(args.session_log.read_text(encoding='utf-8-sig'))
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['wall_seconds_between_first_last_log'] is not None else 1


if __name__ == '__main__':
    sys.exit(main())
