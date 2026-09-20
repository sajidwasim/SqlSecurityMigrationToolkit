# Performance Benchmark

## Status

No controlled before/after live PLAN benchmark was completed in this run. The requested endpoint discovery stopped at encrypted SQL login because the certificate chain was not trusted, and no trust exception was authorized.

## Available baseline

The local historical session was analyzed with `tools/Analyze_PlanSession.py`. It reported a 1,243-second first-to-last log span, 825 seconds of unioned recorded post-processing intervals, and 418 seconds outside those intervals. The result is not a complete exclusive CPU/IO breakdown.

## Reproduction

```powershell
python .\tools\Analyze_PlanSession.py .\Results\BASELINE_SESSION\Session.log
python -m unittest discover -s tests -p 'test_*.py'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\SmokeTest.ps1
```

Do not compare runs with different database scope, SQL state, profile policy, code revision, or endpoint identity. Keep session logs and inventories under ignored, ACL-protected local results.
