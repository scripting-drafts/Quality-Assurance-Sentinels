# pstore panic export

`systemd-pstore` moves EFI pstore records to `/var/lib/systemd/pstore` at the
next boot. Those files are root-only, so the unprivileged boot sentinel cannot
read the panic that journald never saw.

`./install.sh` installs `qa-pstore-export.service`. It runs after
`systemd-pstore.service`, exports only panic/oops lines to
`var/pstore/<archive>/summary.txt`, and refreshes recorded boots so a previous
`archive:<dir>:root-only` becomes `archive:<dir>:panic`.

Manual fallback:

    sudo root/pstore-export.sh --refresh

`QA_PSTORE_ARCHIVE_DIR` and `QA_PSTORE_EXPORT_DIR` override the source and
destination. The export is read-only with respect to the archive; it copies
only matching lines and preserves the repository owner's uid/gid.
