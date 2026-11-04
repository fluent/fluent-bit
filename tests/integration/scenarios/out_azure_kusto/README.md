# Kusto resource TLS regression and memory reproduction

This opt-in scenario exercises the real `azure_kusto` output against a local
HTTPS protocol fixture. It needs Docker with Linux containers, Python 3, and no
Azure account. OAuth names are overridden **only inside a private Docker
network**. It does not publish ports or change host DNS, hosts files, or trust.

All credentials, tokens and URL signatures are synthetic. Temporary certificates
are generated for each run and deleted during cleanup. Neither keys nor results
belong in git.

## Build and focused regression tests

From the repository root:

```sh
docker build \
  -f tests/integration/scenarios/out_azure_kusto/Dockerfile \
  --build-arg 'TEST_TARGETS=flb-rt-out_azure_kusto flb-rt-out_azure_kusto_resources' \
  -t kusto-tls-test .
docker run --rm --network none --entrypoint ctest kusto-tls-test \
  --test-dir /src/build -R flb-rt-out_azure_kusto --output-on-failure
```

The fixture uses a minimal debug build with the dummy/lib inputs and Kusto,
null/lib outputs. Both runtime and internal tests are enabled. Optional
backtrace, LuaJIT, WASM, Unicode conversion and Kafka support are disabled;
Valgrind coroutine support is enabled. These flags are test-image settings, not
recommended production configuration changes. Do not compare images built with
different flags, allocators, trust bundles or base images as patch evidence.

Install the integration suite dependencies using its normal setup procedure.
On Windows, use a Python virtualenv and the suite's requirements as appropriate.
Set `KUSTO_TEST_IMAGE` to the image above, then:

```sh
python -m pytest tests/integration/scenarios/out_azure_kusto -q
```

The tests cover verified HTTPS with separate blob/queue SNI names, refresh and
failed-candidate recovery, multiple outputs/workers, delayed uploads, untrusted
certificates, hostname rejection, and buffered shutdown. The Docker-dependent
tests explicitly skip when
`KUSTO_TEST_IMAGE` is unset; setting it makes missing infrastructure a failure.

For the memory-safety pass:

```sh
VALGRIND=1 VALGRIND_STRICT=1 \
  python tests/integration/run_tests.py scenarios/out_azure_kusto
```

PowerShell equivalent:

```powershell
$env:KUSTO_TEST_IMAGE = "kusto-tls-test"
$env:VALGRIND = "1"
$env:VALGRIND_STRICT = "1"
tests\integration\.venv\Scripts\python.exe tests\integration\run_tests.py scenarios\out_azure_kusto
```

Here Valgrind runs **inside the Linux logger container**, not on the host pytest
process. It checks definite/indirect leaks and memory errors and must exit cleanly;
its report is retained beside each test's JSON result in pytest's temporary
directory. The instrumented tests use a larger limit than the memory comparison
to avoid treating checker overhead as a plugin regression. This is also the
memory-checker route from Windows; native Windows Valgrind is not required.

## Matched 512 MiB comparison

Build an unmodified and patched checkout with the same Dockerfile/options and
base image. The default CA source is the exact public v5.0.4 image digest from
the original reproduction, extracted automatically. The patched binary remains
the binary from the chosen `--image`.

Run each image using a shared, temporary `--material-dir` so the generated CA
and configuration hashes match:

```sh
python tests/integration/scenarios/out_azure_kusto/reproduce.py \
  --image kusto-tls-baseline --helper-image kusto-tls-test \
  --material-dir tests/integration/results/kusto-material \
  --seconds 3600 --min-rotations 12 --stop-after-rotations 12 \
  --result tests/integration/results/kusto-baseline.json
python tests/integration/scenarios/out_azure_kusto/reproduce.py \
  --image kusto-tls-test --helper-image kusto-tls-test \
  --material-dir tests/integration/results/kusto-material \
  --seconds 3600 --min-rotations 12 --stop-after-rotations 12 \
  --result tests/integration/results/kusto-candidate.json
```

The defaults are five outputs, 20 blob plus 20 queue resources per output, one
worker/output, one tiny record per second, compression on and buffering off.
The logger has 512 MiB with no extra swap, one CPU, a 64-PID ceiling, read-only
root filesystem, dropped capabilities, and no-new-privileges. The mock and
observer run outside its memory cgroup. The observer has SYS_PTRACE only to
read the logger's proc data, shares its PID namespace, and has no network.

The diagnostic refresh interval is 1s, but upstream refresh jitter is unchanged:
**this does not mean one rotation each second**. Check actual per-output rotation
and old-list cleanup counts. A bounded run with insufficient rotations is
inconclusive, not a pass.
These commands stop once every output reaches 12 rotations, with a one-hour
cap; the CLI fails if the cap is reached without the requested coverage.

Results include image identity, engine/kernel, config/CA hashes, sampled
anonymous memory and cgroup memory/peak/events, OOM/exit state, per-output rotations,
cleanup counts and successful mock requests. OOM saves the result and exits 137.
Other process/checker failures exit nonzero. Existing result files are never
overwritten. The last sample can precede the final OOM spike, so the sampled
cgroup peak is not guaranteed to capture the final high-water mark.
Raw authorization headers/bodies and Docker inspect dumps are not
saved.

Compare runs with matching hashes. Require successful HTTPS ingestion and
cleanup, no patched-image OOM, and a substantial memory reduction (the working
acceptance target is at least 50% peak anonymous reduction and 12 rotations per
output). Do not interpret finite-run success as proof of a permanent plateau.
No claim is made that this mechanism explains every production OOM.

The public image itself can be selected with `--image` using the pinned digest
in `reproduce.py`; it needs
`--ca-target /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`.
Source-built Debian images use the default CA target. `--help` lists bounded
functional/negative controls and `--valgrind`. An empty or mock-only production
trust store is not a mitigation recommended by this test.

After matched runs, delete the two generated files `cert.pem` and `key.pem` from
the chosen material directory. Without `--material-dir`, keys are deleted
automatically. Containers and the uniquely named network are always cleaned up;
cleanup errors are surfaced. Downloaded/built images are intentionally retained
for reproducibility.

## Ownership regression

The runtime resource test compiles the actual private configuration lifecycle
with renamed entry points and local command/allocation substitutes. It does not
add production test hooks or contact a service. It verifies one context per
generation, retained-generation ordering, preservation of verification/vhost and
existing resource CA/client-certificate behavior, partial-construction cleanup,
TLS/upstream/metadata allocation failures, identity-token failure and recovery.

Resource TLS is deliberately separate from the output ingestion endpoint TLS:
the existing plugin does not inherit output CA/client-key overrides into resource
nodes. This patch preserves that behavior rather than changing trust policy as a
side effect of reducing memory. Fresh generations reload default trust; the
existing deferred cleanup schedule is preserved, not replaced with a promise
of indefinite retention for arbitrarily long requests.
