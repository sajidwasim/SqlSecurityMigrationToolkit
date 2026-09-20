#!/usr/bin/env python3
"""Compare two PLAN CSV files without changing or uploading their contents.

Default behavior is deliberately strict: same schema, same rows, same ordering.
Use --ignore-order only when a separately reviewed change permits reordering.
Does not infer SQL execution correctness or approval from equal CSVs.
"""
import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

REQUIRED = frozenset({'Database', 'Kind', 'Name', 'Stage', 'Status', 'Reason'})


def load(path):
    with Path(path).open('r', encoding='utf-8-sig', newline='') as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError(f'{path}: missing or duplicate CSV headers')
        headers = tuple(reader.fieldnames)
        if not REQUIRED.issubset(headers):
            raise ValueError(f'{path}: required PLAN columns missing: {sorted(REQUIRED - set(headers))}')
        rows = []
        for index, row in enumerate(reader, 2):
            if None in row:
                raise ValueError(f'{path}: invalid extra CSV fields on line {index}')
            if any(value is None for value in row.values()):
                raise ValueError(f'{path}: missing CSV fields on line {index}')
            rows.append(tuple(row[key] for key in headers))
    return headers, rows


def compare(baseline, candidate, ignore_order=False):
    first_headers, first_rows = load(baseline)
    second_headers, second_rows = load(candidate)
    if set(first_headers) != set(second_headers):
        return {'equivalent': False, 'reason': 'schema_mismatch',
                'baseline_columns': first_headers, 'candidate_columns': second_headers}
    if first_headers != second_headers:
        positions = tuple(second_headers.index(key) for key in first_headers)
        second_rows = [tuple(row[pos] for pos in positions) for row in second_rows]
    equivalent = (Counter(first_rows) == Counter(second_rows) if ignore_order
                  else first_rows == second_rows)
    status_position = first_headers.index('Status')
    baseline_status = dict(sorted(Counter(row[status_position] for row in first_rows).items()))
    candidate_status = dict(sorted(Counter(row[status_position] for row in second_rows).items()))
    return {
        'equivalent': equivalent,
        'reason': 'same_actions' if equivalent else 'action_or_order_difference',
        'baseline_count': len(first_rows),
        'candidate_count': len(second_rows),
        'baseline_status': baseline_status,
        'candidate_status': candidate_status,
        'order_checked': not ignore_order,
        'first_different_row': next((i + 1 for i, (a, b) in
                                     enumerate(zip(first_rows, second_rows)) if a != b),
                                    None) if not equivalent and not ignore_order else None,
        'note': 'CSV equivalence is necessary but not sufficient: also verify scope, inventory completeness, dependencies, manifests and drift checks.'
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('--ignore-order', action='store_true')
    args = parser.parse_args(argv)
    try:
        result = compare(args.baseline, args.candidate, args.ignore_order)
    except (OSError, ValueError) as exc:
        print(json.dumps({'equivalent': False, 'error': str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['equivalent'] else 1

if __name__ == '__main__':
    sys.exit(main())
