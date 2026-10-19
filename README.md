# nginx-cert-expiry-module

[![Build&Test][build-test-badge]][build-test-link]
[![Expiry][expiry-badge]][expiry-link]
[![FreeBSD][freebsd-badge]][freebsd-link]
[![A/UBSan][sanitizers-badge]][sanitizers-link]
[![Valgrind][valgrind-badge]][valgrind-link]
[![Reload][reload-badge]][reload-link]
[![CodeQL][codeql-badge]][codeql-link]
[![Lint][lint-badge]][lint-link]

[build-test-badge]: https://github.com/sysadmin-labs/nginx-cert-expiry-module/actions/workflows/build-test.yml/badge.svg
[build-test-link]: https://github.com/sysadmin-labs/nginx-cert-expiry-module/actions/workflows/build-test.yml
[expiry-badge]: https://github.com/sysadmin-labs/nginx-cert-expiry-module/actions/workflows/expiry.yml/badge.svg
[expiry-link]: https://github.com/sysadmin-labs/nginx-cert-expiry-module/actions/workflows/expiry.yml
[freebsd-badge]: https://github.com/sysadmin-labs/nginx-cert-expiry-module/actions/workflows/freebsd.yml/badge.svg
[freebsd-link]: https://github.com/sysadmin-labs/nginx-cert-expiry-module/actions/workflows/freebsd.yml
[sanitizers-badge]: https://github.com/sysadmin-labs/nginx-cert-expiry-module/actions/workflows/sanitizers.yml/badge.svg
[sanitizers-link]: https://github.com/sysadmin-labs/nginx-cert-expiry-module/actions/workflows/sanitizers.yml
[valgrind-badge]: https://github.com/sysadmin-labs/nginx-cert-expiry-module/actions/workflows/valgrind.yml/badge.svg
[valgrind-link]: https://github.com/sysadmin-labs/nginx-cert-expiry-module/actions/workflows/valgrind.yml
[reload-badge]: https://github.com/sysadmin-labs/nginx-cert-expiry-module/actions/workflows/reload.yml/badge.svg
[reload-link]: https://github.com/sysadmin-labs/nginx-cert-expiry-module/actions/workflows/reload.yml
[codeql-badge]: https://github.com/sysadmin-labs/nginx-cert-expiry-module/actions/workflows/codeql.yml/badge.svg
[codeql-link]: https://github.com/sysadmin-labs/nginx-cert-expiry-module/actions/workflows/codeql.yml
[lint-badge]: https://github.com/sysadmin-labs/nginx-cert-expiry-module/actions/workflows/lint.yml/badge.svg
[lint-link]: https://github.com/sysadmin-labs/nginx-cert-expiry-module/actions/workflows/lint.yml

Warns in the error log before a certificate runs out and provides the days
left as a variable.

nginx says nothing about an expiring certificate.  It loads the file, serves
it until the last second and then presents a certificate the client refuses,
so an ACME client that stopped renewing weeks ago stays invisible until that
moment.

## Synopsis

```nginx
http {
    cert_expiry_warn  14d;
    cert_expiry_check 12h;

    server {
        listen 443 ssl;
        ssl_certificate     /usr/local/etc/ssl/shop.crt;
        ssl_certificate_key /usr/local/etc/ssl/shop.key;

        location = /cert-days {
            return 200 "$ssl_expiry_days\n";
        }
    }
}
```

The error log then carries, at worker start and on every check:

```
[warn] certificate "/usr/local/etc/ssl/shop.crt" expires in 9 days
[error] certificate "/usr/local/etc/ssl/old.crt" expired 5 days ago
[info] certificate "/usr/local/etc/ssl/other.crt" is good for 71 more days
```

## Directives

### `cert_expiry_warn`

**syntax:** `cert_expiry_warn <time>`
**default:** `14d`
**context:** `http`

Below this much remaining time a certificate is reported at warn level.  An
expired one is reported at error level regardless of this setting, one with
more time left at info level, so a log at that level holds the full
inventory.

### `cert_expiry_check`

**syntax:** `cert_expiry_check <time>`
**default:** `12h`
**context:** `http`

How often the certificates are read again.  Without it a server running for
months would keep reporting the state of the morning it started.

## Variables

### `$ssl_expiry_days`

Days left on the certificate the current connection was served with, which
is the one OpenSSL picked rather than the first one configured, the
difference being visible on a server carrying an RSA and an ECDSA
certificate at once.  Empty on a connection without TLS.

## Scope

Every file named by an `ssl_certificate` in any server is read once, however
many servers share it.

A certificate whose path contains variables is not watched: the file is only
known once a handshake has named a server, and the literal text of the
directive names no file.  Such a server is noted at info level when the
configuration is read, and `$ssl_expiry_days` still answers for its
connections.

One worker does the reading.  Every worker reporting the same files would
multiply the lines in the log without making a certificate fresher.

## Installation

The module requires an nginx with TLS:

```sh
./configure --with-http_ssl_module \
    --add-module=/path/to/nginx-cert-expiry-module
```

or as a loadable module

```sh
./configure --with-http_ssl_module \
    --add-dynamic-module=/path/to/nginx-cert-expiry-module
```

with `load_module modules/ngx_http_cert_expiry_module.so;` in the main
context.  A build without `--with-http_ssl_module` is rejected at configure
time.

## Tests

```sh
ci/build.sh 1.30.5 /tmp/nginx-test
TEST_NGINX_BINARY=/tmp/nginx-test/sbin/nginx prove -r t/
ci/expiry.sh /tmp/nginx-test/sbin/nginx
ci/reload.sh /tmp/nginx-test/sbin/nginx
```

`ci/expiry.sh` signs three certificates through a local CA, one three days
from its end, one with a year, one that expired five days ago, and reads
back what the module reports about each.

## License

BSD 2-Clause, see [LICENSE](LICENSE).
