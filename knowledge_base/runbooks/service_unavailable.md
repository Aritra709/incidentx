# Runbook: Service unavailable

1. Confirm which service is failing and whether the failure is timeout, 5xx, or refused connection.
2. Check the service's health endpoint and recent logs.
3. Check load balancer, DNS, and network health.
4. Check whether the service was deployed or reconfigured in the last hour.
5. Check dependency health and circuit-breaker state.
6. Roll back the most recent change if it matches the failure window.
7. Confirm recovery with a synthetic request through the user-facing entry point.
8. Record the incident and the resolution for future matching.
