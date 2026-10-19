# Changelog

Newest first.  Dates are release dates.

## v0.1.0 (2026-10-19)

### Added

- First release.  Every file named by an `ssl_certificate` is read when a
  worker starts and again on a timer; one that is close to its end is
  reported at warn level, one that has passed it at error level, and one
  with time to spare at info level.

- `cert_expiry_warn` sets the threshold, `cert_expiry_check` the interval.

- `$ssl_expiry_days` reports the days left on the certificate the current
  connection was served with, which is the one OpenSSL picked rather than
  the first one configured.

- Only one worker reads and reports, and a certificate whose path carries
  variables is left alone rather than guessed at.

### Why this module exists

nginx serves an expiring certificate without a word until the moment a
client refuses it, and nothing on GitHub watches the dates from inside the
server.
