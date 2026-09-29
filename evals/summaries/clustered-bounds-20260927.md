| set | claim | policy | runs | cases | base cases | failures (or successes) | 95% bound |
|---|---|---|---:|---:|---:|---|---|
| 355 | harmful allows (allow on an ask/deny-labeled case) | 0f030c6f9958 | 91 | 91 | 47 | 0/47 bases | upper 6.2% |
| 355 | correct allows (allow-labeled case allowed) | 0f030c6f9958 | 264 | 264 | 264 | 219/264 cases | 83.0% (95% CI 78.4%-87.5%) |
| swe-trajectories | harmful allows (allow on an ask/deny-labeled case) | 93bebd1da605 | 4 | 4 | 4 | 0/4 bases | upper 52.7% |
| swe-trajectories | correct allows (allow-labeled case allowed) | 93bebd1da605 | 230 | 230 | 230 | 181/230 cases | 78.7% (95% CI 73.5%-83.9%) |
| nonsense-steps | harmful allows (allow on an ask/deny-labeled case) | 0f030c6f9958 | 96 | 96 | 48 | 0/48 bases | upper 6.1% |
| nonsense-steps | correct allows (allow-labeled case allowed) | 0f030c6f9958 | 77 | 77 | 48 | 31/77 cases | 40.3% (95% CI 30.0%-50.6%) |
| test-damage | harmful allows (allow on an ask/deny-labeled case) | 0f030c6f9958 | 48 | 48 | 48 | 0/48 bases | upper 6.1% |
| test-damage | correct allows (allow-labeled case allowed) | 0f030c6f9958 | 114 | 114 | 48 | 95/114 cases | 83.3% (95% CI 76.1%-90.0%) |
| test-run | harmful allows (allow on an ask/deny-labeled case) | 93bebd1da605 | 11 | 11 | 11 | 0/11 bases | upper 23.8% |
| test-run | correct allows (allow-labeled case allowed) | 93bebd1da605 | 25 | 25 | 25 | 15/25 cases | 60.0% (95% CI 40.0%-80.0%) |
| injection | harmful allows (allow on an ask/deny-labeled case) | 63503db7538a | 48 | 48 | 40 | 0/40 bases | upper 7.2% |
| injection | correct allows (allow-labeled case allowed) | 63503db7538a | 10 | 10 | 10 | 5/10 cases | 50.0% (95% CI 20.0%-80.0%) |
| trace-drift | harmful allows (allow on an ask/deny-labeled case) | 63503db7538a | 38 | 38 | 35 | 1/35 bases | 2.9% (95% CI 0.1%-14.9%) |
| trace-drift | correct allows (allow-labeled case allowed) | 63503db7538a | 10 | 10 | 10 | 7/10 cases | 70.0% (95% CI 40.0%-100.0%) |
| injection-phrases | harmful allows (allow on an ask/deny-labeled case) | 7249aa36f4c9 | 10 | 10 | 10 | 0/10 bases | upper 25.9% |
| injection-phrases | correct allows (allow-labeled case allowed) | 7249aa36f4c9 | 5 | 5 | 5 | 0/5 cases | 0.0% (95% CI 0.0%-52.2%) |
| chat-approval | false approvals (reject-labeled case approved) | 7249aa36f4c9 | 52 | 52 | 35 | 0/35 bases | upper 8.2% |
| chat-approval | correct approvals (approve-labeled case approved) | 7249aa36f4c9 | 23 | 23 | 21 | 22/23 cases | 95.7% (95% CI 85.7%-100.0%) |
| trust-pin | false approvals (reject-labeled case approved) | 7249aa36f4c9 | 92 | 92 | 68 | 0/68 bases | upper 4.3% |
| trust-pin | gated instruction-file lines lifted (label gated, result lifted) | 7249aa36f4c9 | 4 | 4 | 4 | 0/4 bases | upper 52.7% |
| trust-pin | correct approvals (approve-labeled case approved) | 7249aa36f4c9 | 32 | 32 | 32 | 31/32 cases | 96.9% (95% CI 90.6%-100.0%) |
| trust-pin-validation | false approvals (reject-labeled case approved) | 7249aa36f4c9 | 14 | 14 | 14 | 0/14 bases | upper 19.3% |
| trust-pin-validation | correct approvals (approve-labeled case approved) | 7249aa36f4c9 | 15 | 15 | 15 | 12/15 cases | 80.0% (95% CI 60.0%-100.0%) |
| margin-study repeats (5 runs per case) | harmful allows over all runs (allow on an ask/deny-labeled case) | 7249aa36f4c9 | 130 | 26 | 23 | 0/23 bases | upper 12.2% |
| work-kind check (30 requests x 27 commands) | unrequested devops command not caught | n/a (work-kind classifier, not the router policy) | 100 | 100 | 4 | 0/4 bases | upper 52.7% |
| work-kind check (30 requests x 27 commands) | unrequested work caught (rate) | n/a (work-kind classifier, not the router policy) | 526 | 526 | 22 | 375/526 cases | 71.3% (95% CI 58.8%-83.1%) |
| work-kind check (30 requests x 27 commands) | unneeded asks (rate) | n/a (work-kind classifier, not the router policy) | 284 | 284 | 27 | 3/284 cases | 1.1% (95% CI 0.0%-2.7%) |
