# Hardware-health tier

The hardware tier collects **hardware health telemetry exposed by the kernel,
drivers, firmware, and vendor tools**. It is not a logic analyzer, JTAG probe,
or full PCIe/DRAM trace.

## Sources

| Source | Data | Typical privilege |
|---|---|---|
| `ras` | `ras-mc-ctl --summary/--errors`, rasdaemon state, EDAC UE/CE, PCIe AER counters, ACPI APEI tables, pstore summaries | EDAC/AER often readable; rasdaemon DB and ACPI may need root |
| `storage` | `smartctl -a -j`, `nvme smart-log -o json`, SMART health, media errors, wear, spare, temperature | root or CAP_SYS_RAWIO |
| `gpu` | `nvidia-smi -q -x`, temperature, utilization, memory, ECC, retired pages, throttle reasons, power | user |
| `bmc` | `ipmitool sel elist` or optional Redfish SEL | root/CAP_DAC_OVERRIDE |
| `sensors` | `sensors -j` temperatures and limits | user |
| `turbostat` | package/core summary | root/CAP_SYS_RAWIO |
| `pcm` | Intel PCM one-second sample | root |
| `uncore` | selected `perf` uncore PMU events | CAP_PERFMON |
| `vendor` | configured firmware/BMC log files | file read access |

## Commands

```bash
./bin/qa hardware collect
./bin/qa hardware show
./bin/qa hardware check
./bin/qa hardware collect --sources ras,storage,gpu,bmc,sensors
./bin/qa findings --only open
```

`cycle` runs the tier every `QA_HARDWARE_INTERVAL_S` seconds (default 900) when
`QA_HARDWARE_ENABLE=1`. Each source records `ok`, `partial`, `needs-root`, or
`unavailable`; no missing tool fails the cycle.

## Privileged scheduling

The ordinary user cron cannot read SMART/NVMe raw devices, IPMI, or uncore
counters. Install the capability-scoped timers:

```bash
sudo ./root/install-hardware.sh
systemctl status qa-hardware.timer qa-hardware-storage.timer
journalctl -u qa-hardware.service -u qa-hardware-storage.service -n 50
```

The operator hardware timer runs as the operator with narrow capabilities. A
separate **root-owned** probe is installed as
`/usr/local/sbin/qa-hardware-storage-probe`; it writes
`var/hardware-storage-root.json` (root:<operator-group>, 0640). The operator
collector reads that handoff, so root is only granted to this probe and never
to the Python collector or the QA database.

The probe owns every read that requires root:

- SMART/NVMe device access (`CAP_SYS_RAWIO`, `CAP_DAC_OVERRIDE`)
- the root-only rasdaemon database (`ras-mc-ctl --summary/--errors`)
- `turbostat`, whose `access(R_OK)` check ignores ambient capabilities
- LSM state (AppArmor profiles, IMA policy) and file ownership

The service also needs `CAP_CHOWN` to hand the file to the operator group and
`CAP_SYS_NICE` for turbostat. The installer places the root-owned lockdown
helper at `/usr/local/sbin/qa-lsm-enforce-lockdown`.

Remove them:

```bash
sudo ./root/install-hardware.sh --uninstall
```

`qa hardware check` exits non-zero when a *required* tool is missing.
`qa hardware collect` and the cycle exit non-zero when any required hardware
source is not `ok` (missing tool, permission failure, or unreadable data).
Required sources default to:

```text
ras,storage,gpu,bmc,sensors,turbostat,pcm,uncore,vendor
```

`qa hardware discover` writes the host's scoped contract to
`config/hardware-sources.json`. Sources the platform cannot provide are listed
under `not_applicable` with a reason and are omitted from `required_sources`.
This host is an AMD desktop without a BMC, so `pcm` (Intel-only) and `bmc` are
scoped out explicitly rather than reported as permanent failures. All other
required sources must be `ok`; `failed_sources` must be empty.

`vendor` is **mandatory**: configure `config/hardware-sources.json` with at
least one readable vendor log, or the hardware source and cycle fail.
Override the required list with `QA_HARDWARE_REQUIRED_SOURCES` only for a
deliberate exception.

## Findings

Hardware findings use the existing `findings` table:

- `hardware.edac.ue`, `hardware.edac.dimm_ue`, `hardware.edac.ce`
- `hardware.aer.fatal`, `hardware.aer.nonfatal`, `hardware.aer.correctable`
- `hardware.apei.pstore`
- `hardware.storage.smart`, `hardware.storage.media`, `hardware.storage.wear`,
  `hardware.storage.spare`, `hardware.storage.reallocated`,
  `hardware.storage.pending`, `hardware.storage.uncorrectable`,
  `hardware.storage.critical_warning`
- `hardware.gpu.ecc_uncorrected`, `hardware.gpu.retired_pages`,
  `hardware.gpu.temperature`, `hardware.gpu.throttle`
- `hardware.bmc.sel`
- `hardware.thermal.sensor`
- `hardware.vendor.log`
- `hardware.coverage` when key sources are unavailable or need privilege

Thresholds are at the lowest meaningful trigger points by default:

| Setting | Default | Meaning |
|---|---:|---|
| `QA_HARDWARE_CE_ALERT` | `1` | any corrected EDAC errors |
| `QA_HARDWARE_AER_CE_ALERT` | `1` | any correctable PCIe AER error |
| `QA_HARDWARE_NVME_USED_ALERT` | `1` | any NVMe wear percentage |
| `QA_HARDWARE_NVME_SPARE_ALERT` | `100` | warn on any drop below 100% spare |
| `QA_HARDWARE_GPU_TEMP_ALERT_C` | `65` | early GPU temperature warning |
| `QA_HARDWARE_SENSOR_TEMP_ALERT_C` | `70` | early sensor temperature warning |
| `QA_HARDWARE_STORAGE_TEMP_ALERT_C` | `50` | early SMART/NVMe temperature warning |

Override them in the environment or in the service unit when a higher site
threshold is required.

## Vendor logs and Redfish

Copy `config/hardware-sources.example.json` to `config/hardware-sources.json`
and add at least one readable vendor log path; the vendor source is mandatory.
Redfish remains opt-in and reads the bearer token from
the environment variable named by `token_env`; credentials are never stored in
the database or printed.

```json
{
  "vendor_logs": ["/var/log/vendor-firmware.log"],
  "redfish": {
    "enabled": true,
    "base_url": "https://bmc.example.invalid",
    "token_env": "QA_REDFISH_TOKEN"
  }
}
```

## Limits

- SMART/NVMe, IPMI, PCM, turbostat and uncore often need privileges. This
  host routes the root-only reads through the single root probe handoff.
- ACPI tables are recorded as hashes/metadata, not fully decoded.
- The tier does not read BMC firmware, PCIe analyzer captures, DRAM patrol
  scrub, JTAG, or vendor debug registers.
- Raw output is capped and redacted before evidence export; local database
  retention defaults to 14 days.
