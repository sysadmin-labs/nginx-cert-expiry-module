# Changelog

## v0.1.0 (2026-10-20)

- First release: every file named by an `ssl_certificate` is read at worker
  start and on a timer, and reported at warn level when it is close to its
  end, at error level when it has passed it, at info level otherwise.
- `cert_expiry_warn` sets the threshold, `cert_expiry_check` the interval.
- `$ssl_expiry_days` reports the days left on the certificate the current
  connection was served with.
- One worker reports; a certificate whose path contains variables or is
  given as `data:` or `engine:` is left alone.
- The dates are read in the master, where the configuration is read, so a
  certificate that only root may read is still read, and no worker does file
  I/O in its event loop.
- Days are rounded towards the past, so a certificate that ran out an hour
  ago reports -1 and not 0, and a notAfter too far out to fit a 32 bit
  time_t is pinned at a hundred years.
