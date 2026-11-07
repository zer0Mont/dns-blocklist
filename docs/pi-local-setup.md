# Pi-local stats and Gravity prep

This is review-only preparation. Installing these files, reading this page, or running the command with no arguments does not enable a timer, refresh Gravity, or send telemetry.

The existing morning Grok routine, around 09:00 Europe/London, reviews upstream list changes and opens a pull request. It does not auto-merge, and it does not collect stats. Stats collection is a separate Pi-local job at 00:20 Europe/London. A daily Gravity refresh, if you later enable it, is another job at 04:20 Europe/London and only runs `pihole updateGravity`.

## What the collector records

Pi-hole v6 `GET /api/stats/database/summary` requires `from` and `until`. The collector asks for the previous completed Europe/London civil day. That day is 23, 24, or 25 hours when DST changes. The live dashboard endpoint `GET /api/stats/summary` is not that day, so its query totals are ignored. `total_clients`, top domains, and the query log are not stored.

A failed, unauthorised, or schema-invalid read is `unavailable`. It is not stored as zero. A validated day with `sum_queries` 0 stays a real zero, and the percentage is left empty because the denominator is zero.

The database summary schema this code accepts is the one in FTL's API tests: `sum_queries`, `sum_blocked`, `percent_blocked`, and `total_clients`. `total_clients` is checked and then discarded. No other fields are copied. Uptime is not read, and it is never used to claim the day is complete. `completeness.day_coverage` stays `not-evidenced`.

Whether `until` is inclusive is not known for this Pi. The instance `/api/docs` page is the authority, and no installed version was verified from here. Leave `database_summary_until` null until you have read that page and set it to `inclusive` or `exclusive`. While it is null, the collector does not send a database summary query.

`GET /api/info/version`, `GET /api/dns/blocking`, and the `gravity` object on `GET /api/stats/summary` are included only when those responses match the fields FTL's API tests assert (`version.ftl.local.version`, `blocking` of `enabled` or `disabled`, `gravity.domains_being_blocked`). Anything else stays `unavailable`. `gravity.last_update` is copied only when that field is present and numeric; the current FTL tests do not require it.

## Guardian subscription check

`pihole updateGravity` (the same action as `pihole -g`) only rebuilds lists that are already subscribed. This package never creates a list, never changes a list type, and never writes the gravity database.

Before a later activation, a read-only `GET /api/lists` check must find exactly one enabled subscription for the configured Guardian URL whose API `type` is `block`. That is database `adlist.type` 0. API `allow`, the word `antigravity`, or numeric type 1 is database type 1 and fails the check. Duplicates, a disabled block row, or a missing URL also fail. The check prints the ids the API returned and stops. It does not delete or repair a row, and it does not treat any id, including 2, as the Guardian row. A reported duplicate allow entry is not something this code has verified on the Pi; the check exists so activation cannot proceed while one is present.

The example Guardian URL is this repository's public `main` blocklist. Confirm it is the address already subscribed. The check will not add it.

## Secrets and transport

Pi-hole application passwords can be a single credential. Creating a replacement can break every other consumer of the current one. This package never calls `GET /api/auth/app` and never replaces a password file. Before you create or replace one in the Pi-hole UI, list the consumers that use it and decide that explicitly.

To store a password you already created, on the Pi:

```bash
python3 -m pi_local provision-password --path /etc/pihole-daily-stats/app-password --store-existing-password
```

That prompt does not echo. It refuses a pipe, a symlink, and an existing file. The file is created mode `0600` in one step. You can instead point systemd `LoadCredential=pihole_app_password` at that file. The unit has no `Environment=` secret. The password is not accepted on the command line or in the URL. The session id stays in memory, is removed after `DELETE /api/auth`, and redirects are not followed, so the session header is not sent to another host.

HTTPS certificate checks stay on. You can set `ca_file` to a PEM trust anchor you installed; that still validates the certificate. There is no insecure or skip-verify switch. HTTP is accepted only for `127.0.0.1`, `::1`, or `localhost`, because that traffic does not leave the machine. The Pi on the LAN is not loopback and must be HTTPS.

Output JSON is written mode `0600` under a mode `0700` directory. `dry-run` writes a synthetic aggregate only.

## Delivery

Cursor's routine help documents a private webhook as `POST` of JSON with `Authorization: Bearer <key>`. HTTP 200 means the run was accepted, not that it finished. Cursor does not define which JSON fields the routine expects.

Delivery stays disabled until you approve a private destination, who can use it, how long payloads are kept, and the acknowledgement rules. Prepare-only mode makes no delivery network call and writes no queue. HTTP 409 is not treated as success. A redirect is refused so the bearer token is not sent onward. Retries stop after 3 attempts, reuse the aggregate `record_id`, and do not continue after 409 or a redirect. No webhook URL or key is included. Do not send aggregates to GitHub.

A historical note of about 993MB free, roughly 86% used, is not a current measurement of this Pi. `disk-check` and preflight read free space when they run. The example floor is 256MiB. Change it if you want a different floor. It is not a report of how full the disk is now.

```bash
python3 -m pi_local disk-check --path /var/lib
```

## Schedulers

Pi-hole's own `/etc/cron.d/pihole` runs `pihole updateGravity` weekly and also flushes logs and checks versions. Do not hand-edit that file: Pi-hole overwrites it, and it contains jobs besides Gravity.

`activate` refuses to change the file when any command is not the stock `updateGravity`, `flush`, `updatechecker`, or pihole logrotate line, or when more than one Gravity line exists. With an explicit later `--go-live --accept-disable-stock-weekly-gravity`, it comments out only that one Gravity line and saves a mode `0600` backup. `restore` writes the backup back only if the file still matches the edited copy. Unknown jobs are left untouched because the edit is refused.

The systemd timers in this tree are not enabled by `install`. `install` only copies them when you pass `--dest` and `--confirm-install-disabled-units`.

## Commands that are safe before go-ahead

```bash
python3 -m pi_local
python3 -m unittest tests/test_pi_local.py tests/test_build_blocklist.py
python3 -m pi_local dry-run --output /tmp/pi-local-synthetic.json
python3 -m pi_local disk-check --path /var/lib
```

## Commands that need your go-ahead

Do not run these until you say the Pi may be changed.

```bash
# On the Pi, after the app password file exists and is mode 0600.
python3 -m pi_local preflight --config /etc/pihole-daily-stats/config.json
python3 -m pi_local install --dest / --confirm-install-disabled-units
python3 -m pi_local activate --go-live \
  --accept-disable-stock-weekly-gravity \
  --config /etc/pihole-daily-stats/config.json \
  --cron-file /etc/cron.d/pihole
sudo systemctl enable --now pihole-daily-stats.timer pihole-daily-gravity.timer
```

Rollback, after go-live, is to disable those two timers and then restore the cron backup only if the file still matches the edited copy:

```bash
sudo systemctl disable --now pihole-daily-stats.timer pihole-daily-gravity.timer
python3 -m pi_local restore --cron-file /etc/cron.d/pihole \
  --backup /etc/cron.d/pihole.pi-local-backup
```

Disabling the timers does not remove subscribed lists. `restore` does not enable anything.

Daily Gravity still only downloads lists already on the Pi. Merging a blocklist change on GitHub is a separate approval. There is no auto-merge.
