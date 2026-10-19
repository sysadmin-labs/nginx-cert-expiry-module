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

A warning in the error log before a certificate runs out, and a variable
that says how many days are left.

nginx says nothing about an expiring certificate.  It loads the file,
serves it until the last second and then hands out a certificate the client
refuses -- the first notice usually comes from a user.  An ACME client that
stopped renewing six weeks ago is invisible until exactly that moment.

## Synopsis

```nginx
http {
    cert_expiry_warn  14d;      # warn below this
    cert_expiry_check 12h;      # and look again this often

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

The error log then carries, when a worker starts and on every check:

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

Below this much remaining time a certificate is reported at **warn**
level.  A certificate that has already expired is reported at **error**
level whatever this says, and one with more time left is mentioned at
**info** level, so a log at that level shows the whole inventory.

### `cert_expiry_check`

**syntax:** `cert_expiry_check <time>`
**default:** `12h`
**context:** `http`

How often the certificates are read again.  A server that runs for months
would otherwise report the state it found on the morning it started.

## Variables

### `$ssl_expiry_days`

Days left on the certificate **this connection** was served with -- not the
configured file but the one OpenSSL picked, which is the honest answer when
a server carries an RSA and an ECDSA certificate at once.  Empty on a
connection without TLS.

## What it watches, and what it cannot

Every file named by an `ssl_certificate` in any server, once, no matter how
many servers share it.

A certificate whose path carries variables is **not** watched: the file is
only known once a handshake names a server, and reporting on the literal
text of the directive would be reporting on a file that does not exist.
Such a server is noted at info level when the configuration is read.  The
variable still answers for those connections.

The reading is done by **one** worker.  Every worker reading the same files
and writing the same line would make the log harder to read, not the
certificate fresher.

## Building

The module needs an nginx with TLS:

```sh
./configure --with-http_ssl_module \
    --add-module=/path/to/nginx-cert-expiry-module
```

or, as a loadable module,

```sh
./configure --with-http_ssl_module \
    --add-dynamic-module=/path/to/nginx-cert-expiry-module
```

and then `load_module modules/ngx_http_cert_expiry_module.so;` in the main
context.  A build without `--with-http_ssl_module` is refused at configure
time.

## Testing

```sh
ci/build.sh 1.30.5 /tmp/nginx-test
TEST_NGINX_BINARY=/tmp/nginx-test/sbin/nginx prove -r t/
ci/expiry.sh /tmp/nginx-test/sbin/nginx
ci/reload.sh /tmp/nginx-test/sbin/nginx
```

`ci/expiry.sh` makes three certificates -- one three days from its end, one
with a year, one that expired five days ago -- and reads back what the
module says about each.

## License

BSD 2-Clause.  See [LICENSE](LICENSE).
