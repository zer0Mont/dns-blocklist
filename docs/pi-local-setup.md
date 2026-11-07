# Pi-local stats and Gravity prep

This is review-only preparation. Installing these files, reading this page, or running the command with no arguments does not enable a timer, refresh Gravity, or send telemetry.

The existing morning Grok routine, around 09:00 Europe/London, reviews upstream list changes and opens a pull request. It does not auto-merge, and it does not collect stats. Stats collection is a separate Pi-local job at 00:20 Europe/London. Daily Gravity is deferred and is not implemented: this package does not install a Gravity timer and does not edit `/etc/cron.d/pihole`. The stock weekly `pihole updateGravity` job stays as Pi-hole installed it.

## What the collector records

Pi-hole v6 `GET /api/stats/database/summary` requires `from` and `until`. The collector asks for the previous completed Europe/London civil day. That day is 23, 24, or 25 hours when DST changes. The live dashboard endpoint `GET /api/stats/summary` is not that day, so its query totals are ignored. `total_clients`, top domains, and the query log are not stored.

A failed, unauthorised, or schema-invalid read is `unavailable`. It is not stored as zero. A validated day with `sum_queries` 0 stays a real zero, and the percentage is left empty because the denominator is zero.

The database summary schema this code accepts is the one in FTL's API tests: `sum_queries`, `sum_blocked`, `percent_blocked`, and `total_clients`. `total_clients` is checked and then discarded. No other fields are copied. Uptime is not read, and it is never used to claim the day is complete. `completeness.day_coverage` stays `not-evidenced`.

Whether `until` is inclusive is not known for this Pi. The instance `/api/docs` page is the authority, and no installed version was verified from here. Leave `database_summary_until` null until you have read that page and set it to `inclusive` or `exclusive`. While it is null, the collector does not send a database summary query.

`GET /api/info/version`, `GET /api/dns/blocking`, and the `gravity` object on `GET /api/stats/summary` are included only when those responses match the fields FTL's API tests assert (`version.ftl.local.version`, `blocking` of `enabled` or `disabled`, `gravity.domains_being_blocked`). Anything else stays `unavailable`. `gravity.last_update` is copied only when that field is present and numeric; the current FTL tests do not require it.

## Guardian subscription check

`preflight` can read `GET /api/lists` and report whether the configured Guardian URL is exactly one enabled `type=block` subscription. That API value is database `adlist.type` 0. API `allow`, the word `antigravity`, or numeric type 1 is database type 1. Duplicates, a disabled row, or a missing URL fail the report. It does not delete or repair a row, and it does not treat any id, including 2, as the Guardian row. A reported duplicate allow entry was not re-checked from here.

That check does not refresh Gravity. Daily Gravity is deferred, so install does not run `pihole updateGravity` and does not change the stock weekly cron. The example Guardian URL is this repository's public `main` blocklist. The check will not add it.

## Secrets and transport

Pi-hole application passwords can be a single credential. Creating a replacement can break every other consumer of the current one. This package never calls `GET /api/auth/app` and never replaces a password file. Before you create or replace one in the Pi-hole UI, list the consumers that use it and decide that explicitly.

The stats service runs on the Pi as `DynamicUser` and talks to Pi-hole at `http://127.0.0.1`. Loopback HTTP does not leave the machine. Do not point this service at a LAN address with HTTP. The example config uses `password_source` `systemd-credential`, which reads `pihole_app_password` from systemd's credential directory. It does not match a world-readable unit environment variable.

To store a password you already created, on the Pi:

```bash
python3 -m pi_local provision-password --path /etc/pihole-daily-stats/app-password --store-existing-password
```

That prompt does not echo. It refuses a pipe, a symlink, a loose mode, a surprising owner, and an existing file. The file is created mode `0600` in one step. Copy `pi_local/examples/pi-local.example.json` to `/etc/pihole-daily-stats/config.json` and keep that mode `0600` as well. The unit loads both files with `LoadCredential`; the service user never opens the root-owned directory. The unit has no `Environment=` secret. The password is not accepted on the command line or in the URL. The session id stays in memory, is removed after `DELETE /api/auth`, and redirects are not followed.

HTTPS certificate checks stay on for any non-loopback URL. There is no insecure or skip-verify switch.

Output JSON is written mode `0600` under a mode `0700` directory. `dry-run` writes a synthetic aggregate only.

## Delivery

Cursor's routine help documents a private webhook as `POST` of JSON with `Authorization: Bearer <key>`. HTTP 200 means the run was accepted, not that it finished. Cursor does not define which JSON fields the routine expects.

Delivery stays disabled until you approve a private destination, who can use it, how long payloads are kept, and the acknowledgement rules. Prepare-only mode makes no delivery network call and writes no queue. HTTP 409 is not treated as success. A redirect is refused so the bearer token is not sent onward. Retries stop after 3 attempts, reuse the aggregate `record_id`, and do not continue after 409 or a redirect. No webhook URL or key is included. Do not send aggregates to GitHub.

A historical note of about 993MB free, roughly 86% used, is not a current measurement of this Pi. `disk-check` and preflight read free space when they run. The example floor is 256MiB. Change it if you want a different floor. It is not a report of how full the disk is now.

```bash
python3 -m pi_local disk-check --path /var/lib
```

## Install layout

`install` copies this package to `/opt/pi-local` and installs only `pihole-daily-stats.service` and `pihole-daily-stats.timer`, disabled. The service sets `WorkingDirectory=/opt/pi-local` and `PYTHONPATH=/opt/pi-local`, so `python3 -m pi_local` does not depend on the process being started in the source tree. It writes `install-manifest.json` under `/var/lib/pihole-daily-stats`. It does not enable the timer, does not create an application password, and does not replace a config or secret that is already there.

`uninstall` removes only manifest files that still match what install wrote. It leaves preexisting `config.json`, the application password, and aggregate JSON in place. `--remove-secrets` deletes only `/etc/pihole-daily-stats/app-password`. `--remove-data` deletes aggregate `*.json` in the state directory. Neither flag is the default. A symlink recorded in the manifest is skipped, not followed.

## Schedulers

Pi-hole's own `/etc/cron.d/pihole` runs `pihole updateGravity` weekly and also flushes logs and checks versions. This package does not edit that file and does not add another Gravity cron or timer. `activate` refuses, with or without `--go-live`, and changes nothing. After a later approval, the only stats command to type yourself is `systemctl enable --now pihole-daily-stats.timer`.

The stats timer is not enabled by `install`. `install` only copies files when you pass `--dest` and `--confirm-install-disabled-units`.

## Commands that are safe before go-ahead

Run the suites separately. `tests/test_pi_local.py` is the Pi-local suite. `tests/test_build_blocklist.py` is the blocklist suite. There is no combined test module.

```bash
python3 -m unittest tests/test_pi_local.py
python3 -m unittest tests/test_build_blocklist.py
python3 -m pi_local
python3 -m pi_local dry-run --output /tmp/pi-local-synthetic.json
python3 -m pi_local disk-check --path /var/lib
```

## Commands that need your go-ahead

Do not run these until you say the Pi may be changed.

```bash
# On the Pi, after you have approved any application-password change
# and config.json plus app-password exist, mode 0600.
python3 -m pi_local preflight --config /etc/pihole-daily-stats/config.json
python3 -m pi_local install --dest / --confirm-install-disabled-units
sudo systemctl enable --now pihole-daily-stats.timer
```

`python3 -m pi_local activate` does not do that enable for you.

Rollback is stats-only. It does not restore or edit Pi-hole's cron, and it keeps secrets and collected JSON unless you add the matching flag:

```bash
sudo systemctl disable --now pihole-daily-stats.timer
python3 -m pi_local uninstall --dest /
```

Merging a blocklist change on GitHub is still a separate approval. There is no auto-merge. The weekly Gravity cron is unchanged by this package.
