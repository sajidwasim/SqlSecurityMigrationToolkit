import unittest
from tools.Analyze_PlanSession import summarize


class LogAnalyzerTests(unittest.TestCase):
    def test_nested_phase_union_not_sum(self):
        log = '\n'.join([
            '2026-01-01 00:00:00.000 [INFO] POSTPLAN START: Outer',
            '2026-01-01 00:00:02.000 [INFO] POSTPLAN START: Inner',
            '2026-01-01 00:00:05.000 [INFO] Query SQL ElapsedMs=100',
            '2026-01-01 00:00:08.000 [INFO] POSTPLAN END: Inner',
            '2026-01-01 00:00:10.000 [INFO] POSTPLAN END: Outer',
        ])
        result = summarize(log)
        self.assertEqual(result['wall_seconds_between_first_last_log'], 10)
        self.assertEqual(result['phase_duration_seconds_inclusive_may_overlap']['Outer'], 10)
        self.assertEqual(result['phase_duration_seconds_inclusive_may_overlap']['Inner'], 6)
        self.assertEqual(result['union_of_measured_phase_seconds'], 10)
        self.assertEqual(result['sum_of_sql_ElapsedMs_samples'], 100)

    def test_missing_markers_explicit(self):
        log = '\n'.join([
            '2026-01-01 00:00:00.000 [INFO] POSTPLAN START: MissingEnd',
            '2026-01-01 00:00:01.000 [INFO] POSTPLAN END: Unknown',
        ])
        result = summarize(log)
        self.assertEqual(result['unclosed_phases']['MissingEnd'], 1)
        self.assertEqual(result['unmatched_end_markers'], ['Unknown'])


if __name__ == '__main__':
    unittest.main()
