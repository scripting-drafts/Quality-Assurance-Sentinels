# Compatibility

QA Sentinels targets Ubuntu LTS and interim releases through 26.10. The same
baseline is used by the companion QA SIEM repository.

## Baseline

- Ubuntu 22.04.5 LTS (tested)
- Python 3.10+
- SQLite 3.37+
- systemd 249+ (cron remains supported)
- Linux kernel 5.15+
- C11 compiler and `make` for the sampler

The Python implementation uses the standard library only. The C sampler and
optional eBPF tracer are rebuilt on the host.

## Upgrade path

| Release | Status |
|---|---|
| 22.04 LTS | baseline, tested |
| 24.04 LTS | supported |
| 24.10 | supported |
| 25.04 | supported |
| 25.10 | supported |
| 26.04 LTS | supported |
| 26.10 | supported |

## Verify a host

```bash
./bin/qa compat
./bin/qa compat --strict
./bin/qa preflight
```

`compat` reports the Ubuntu release, Python, SQLite, systemd and kernel against
the documented minimums. `--strict` exits non-zero outside the baseline.
`preflight` includes the same compatibility check.

## Upgrade procedure

1. Back up `var/`, `config/`, and `evidence/`.
2. Run `./bin/qa compat --strict`.
3. Run `python3 -m unittest discover -s tests`.
4. Rebuild the sampler: `make -C src install`.
5. Reinstall the scheduler: `sudo ./root/install-system.sh --takeover`
   (or keep the cron schedule).
6. Rebuild optional eBPF/perf artifacts for the new kernel.
7. Run `./bin/qa preflight` and `./bin/qa cycle`.
8. Run the QA SIEM `compat` check and verify the forwarder.

## Release-specific notes

- **Python 3.13/3.14:** the code avoids removed `distutils`/`imp` APIs and uses
  stable `argparse`, `sqlite3`, `urllib`, `ssl`, and `datetime` interfaces.
- **systemd:** unit files use directives available in 249 and later. Keep the
  capability-scoped `qa-sentinel.service` rather than running the cycle as root.
- **eBPF:** the tracer is kernel-specific. `qa deep` checks the build stamp and
  refuses a stale object; rebuild after every kernel change.
- **LSM:** the root LSM helper is optional and reports unavailable securityfs
  state instead of inventing it.
- **NVIDIA/lockdown:** do not add `lockdown=integrity` unless all required
  modules are signed; the installer does not enable it by default.
- **QA SIEM sync:** keep `schema_version` at `1.0` and update both repositories'
  compatibility matrices in the same change.

## Limits

The project does not vendor a Python runtime or kernel modules. A release
upgrade must be validated on the target host because journal, coredump, perf,
AppArmor, IMA, and firmware interfaces can change.
