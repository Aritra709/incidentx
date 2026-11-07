# Runbook: Database connection failure

1. Confirm the database process is running.
2. Check network reachability from the failing service to the database port.
3. Check database logs for crash, disk, or connection-limit errors.
4. Compare connection pool metrics with the previous hour.
5. Check whether a recent deploy or config change touched connection settings.
6. If a change is the likely cause, roll it back before changing database settings.
7. If the database itself is unhealthy, follow the database owner's restart procedure.
8. Confirm recovery with a read and a write test.
