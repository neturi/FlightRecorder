# Flight Recorder

Flight Recorder is a small, independent diagnostic service for an unattended Linux application. It retains a bounded window of recent evidence, detects a small set of failures locally, and preserves an incident bundle without requiring a customer, network access, cloud availability, unrestricted privileges, or automatic remediation.

## Design

The recorder has four layers:

1. **Bounded evidence ring** — application logs, progress markers, metrics, and best-effort kernel samples are retained in a mutex-protected ring limited by both event count and bytes. Eviction is oldest-first, so a pathological producer cannot consume unbounded memory or disk.
2. **Local failure detector** — the application emits heartbeats and progress (`progress(component, operation, percent)`). A stale heartbeat creates an incident locally. Explicit failures can be reported by a supervisor or crash-recovery path. The recorder captures evidence already retained as *before*, then subsequent context as *during*; stopping the recorder closes the context as *after*.
3. **Privacy and durability boundary** — common credential assignments (`password=`, `token=`, `secret=`, and `authorization=`) are redacted before retention. Incident bundles use an escaped, versioned line format and can be saved while offline. The implementation never opens a listening socket or executes a remote command.
4. **Advisory cloud protocol** — `FollowUpRequest` models a cloud-ranked request for narrowly scoped evidence. It must name the incident, bound event count and duration, and explicitly list components and evidence kinds. It is validation only: a transport, ranking model, and customer policy engine can be added around it without making the endpoint dependent on the cloud.

`sample_kernel()` is a portability boundary. On Linux it reads only safe, process-local fields from `/proc/self/status` (RSS and thread count); on other systems it records that the capability is unavailable. A production Linux build may add an eBPF collector behind this interface, but eBPF is optional because kernel versions, capabilities, distributions, and enterprise policy differ.

## Why this shape

| Option | Benefit | Cost / reason it is not the prerequisite |
|---|---|---|
| Continuous deep tracing | Excellent detail and post-hoc queries | CPU, memory, storage, privacy, and kernel/version cost; difficult to deploy everywhere |
| Bounded recorder (this design) | Predictable overhead, offline operation, before/after context | Cannot answer arbitrary historical questions; requires choosing useful signals |
| Logs only | Familiar and easy to ship | Usually misses progress state and surrounding resource context; often unbounded or sampled incorrectly |
| Always-on metrics database | Good trends and fleet analysis | Retention and transport dependencies; dimensions can leak sensitive data |
| Remote interactive access | Powerful investigation | High security and privacy risk; unavailable during outages; not acceptable as a diagnostic prerequisite |
| Automatic remediation | Can restore service quickly | Can destroy evidence, create loops, and change customer state; diagnosis and repair should be separate policy decisions |
| Cloud-only detection | Centralized ranking | Cannot detect an outage or network partition locally and loses the most useful pre-failure context |
| eBPF-only instrumentation | Rich low-level visibility | Privilege, kernel, verifier, packaging, and distribution constraints; use as an optional accelerator |

The tradeoff is intentional: preserve a small amount of high-value evidence everywhere, then request more only when a ranked explanation justifies it.

## Evidence and privacy contract

- Producers should use stable component names and bounded operation names, not arbitrary request payloads.
- The built-in redactor is defense in depth, not a substitute for data classification. Callers must avoid secrets, personal data, and customer payloads in messages.
- Set `Limits::max_events` and `Limits::max_bytes` based on the endpoint budget. Both limits are enforced.
- The bundle is local evidence, not an authorization token. Protect its filesystem permissions and expire it according to enterprise policy.
- A follow-up request is rejected unless it is tied to the current incident and has explicit components, kinds, duration, and event bounds. A real deployment should additionally authenticate and authorize the request and apply tenant-specific allowlists.

## Build and run

Requirements: CMake 3.10+, a C++20 compiler, and Ninja or another CMake generator.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
./build/FlightRecorder/FlightRecorder ./flight-incident.frb
```

On Windows the sample records `not_supported_on_this_platform`; on Linux it collects process-local `/proc` fields. The core library remains portable. The demo intentionally simulates a failure and writes `flight-incident.frb` (or the path supplied as its first argument).

## Production integration

Run the recorder in the same service or as a tightly scoped sidecar with a supervisor. Add an async-signal-safe crash marker or supervisor notification rather than doing file I/O in a signal handler. Have the supervisor call the post-failure collection path, upload only after local policy permits, and retain the original bundle if the cloud is unreachable. Use systemd resource limits, a dedicated local directory, restrictive permissions, and a queue quota.

A cloud service can rank hypotheses from the incident summary (for example, resource pressure versus a stalled dependency) and return one request such as “collect scheduler progress and RSS for 30 seconds.” The endpoint should accept only signed, policy-checked requests and should never interpret cloud output as a command to restart, delete, or mutate customer state. Automatic remediation is a separate, explicitly enabled product policy.

## Limitations

This reference implementation is deliberately small. It does not install a daemon, ship an eBPF program, implement crash unwinding, encrypt bundles, or provide a network client. Those are deployment-specific concerns. The key guarantees demonstrated here are bounded retention, local detection, offline persistence, redaction, phase context, and constrained follow-up evidence.
