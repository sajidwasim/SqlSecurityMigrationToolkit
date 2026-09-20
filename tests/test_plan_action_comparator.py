import csv
import tempfile
import unittest
from pathlib import Path
from tools.Compare_PlanActions import compare

HEADERS = ['SourceDatabase', 'Database', 'Kind', 'Name', 'Principal', 'Role', 'Stage', 'Status', 'Reason']


class ComparatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.a = Path(self.temp.name) / 'baseline.csv'
        self.b = Path(self.temp.name) / 'candidate.csv'
        self.row = ['A', 'B', 'Database permission', 'SELECT', 'user', '', 'Permissions', 'Blocked', 'test']

    def write(self, path, rows):
        with path.open('w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(HEADERS)
            writer.writerows(rows)

    def test_equal(self):
        self.write(self.a, [self.row]); self.write(self.b, [self.row])
        self.assertTrue(compare(self.a, self.b)['equivalent'])

    def test_changed_reason(self):
        self.write(self.a, [self.row])
        self.write(self.b, [self.row[:-1] + ['changed']])
        self.assertFalse(compare(self.a, self.b)['equivalent'])

    def test_duplicates_not_ignored(self):
        self.write(self.a, [self.row, self.row]); self.write(self.b, [self.row])
        self.assertFalse(compare(self.a, self.b)['equivalent'])

    def test_order_sensitive_by_default(self):
        row2 = self.row[:-1] + ['other']
        self.write(self.a, [self.row, row2]); self.write(self.b, [row2, self.row])
        self.assertFalse(compare(self.a, self.b)['equivalent'])
        self.assertTrue(compare(self.a, self.b, ignore_order=True)['equivalent'])

    def test_broken_csv_fails_closed(self):
        self.write(self.a, [self.row]); self.write(self.b, [self.row + ['excess']])
        with self.assertRaises(ValueError):
            compare(self.a, self.b)


if __name__ == '__main__':
    unittest.main()
