# Windows TLS root updates

When Fluent Bit verifies a peer using a Windows certificate store and cannot
find a trusted issuer, it asks Windows to build the peer's chain in the
background. Windows may install a missing public root according to the
machine's Automatic Root Certificates Update policy. Fluent Bit supplies the
peer's certificates and disables retrieval from their AIA URLs.

The triggering handshake fails verification. A new connection reads the
certificate store again and can succeed after the update. For an output,
configure retries if a buffered batch must survive the first failed handshake.
New connections import the currently selected anchors and exclude certificates
explicitly listed in the Windows Disallowed store. An established TLS
connection keeps the result of its original verification.
OpenSSL performs certificate verification on each new handshake.

Each TLS context schedules at most one lookup per minute and runs at most one
lookup at a time. At debug level Fluent Bit logs when it schedules a lookup.
After Windows successfully builds the chain, the next connection logs the
result at info level. An explicit CA file or directory bypasses this lookup.

Set the process environment variable `FLB_WINDOWS_AUTO_ROOT_UPDATE=off` to
disable background lookups in Fluent Bit. Windows administrators can also
[configure trusted root updates through Group Policy](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-trusted-roots-disallowed-certificates).

The Windows x64 integration tests exercise retries against an isolated store.
To test an actual Windows Update download on a networked Windows host, set
`FLUENT_BIT_BINARY` to the executable and `FLB_TEST_WINDOWS_ROOT_DOWNLOAD=1`
and run `python -m pytest tests/integration/scenarios/tls/tests/test_windows_root_update.py`.
The test skips roots already installed and leaves newly installed public roots
under Windows management.
