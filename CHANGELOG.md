# Changelog

## v0.1.0 (2026-10-19)

- First release: every file named by an `ssl_certificate` is read at worker
  start and on a timer, and reported at warn level when it is close to its
  end, at error level when it has passed it, at info level otherwise.
- `cert_expiry_warn` sets the threshold, `cert_expiry_check` the interval.
- `$ssl_expiry_days` reports the days left on the certificate the current
  connection was served with.
- One worker reports; a certificate whose path contains variables is left
  alone.
