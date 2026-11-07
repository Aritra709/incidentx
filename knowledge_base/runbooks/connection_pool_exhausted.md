# Runbook: Connection pool exhaustion

1. Confirm the current pool max, active connections, and waiting requests.
2. Check the last deploy or config change for a pool-size edit.
3. Measure peak concurrent requests against pool capacity.
4. Look for long-running queries holding connections.
5. Check for connection leaks in application code.
6. If a recent change reduced the pool, roll it back or restore the previous value.
7. Add replicas only as a temporary capacity measure.
8. Confirm recovery by watching pool wait time return to zero.
