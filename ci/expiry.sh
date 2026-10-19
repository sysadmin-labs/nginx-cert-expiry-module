#!/bin/sh
#
# Hand the module three certificates whose end dates are known and read
# back what it says about them.
#
# A test suite cannot do this: the warning is written when the worker
# starts and again on a timer, it lands in the error log rather than in a
# response, and the interesting certificate is one that has already
# expired -- which no suite can wait for.  So the dates are made here.
#
# usage: ci/expiry.sh <nginx binary>
#
# Set EXPIRY_LOAD_MODULE to the path of ngx_http_cert_expiry_module.so to
# test a loadable build.

set -eu

NGINX=${1:?path to the nginx binary missing}
WORK=${CI_WORK:-$(cd "$(dirname "$0")/.." && pwd)/ci-work}/expiry
PORT=${EXPIRY_PORT:-18550}

command -v openssl > /dev/null || { echo "openssl(1) is needed" >&2; exit 2; }
command -v curl > /dev/null || { echo "curl(1) is needed" >&2; exit 2; }

rm -rf "$WORK"
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/certs"

fail=0
note() {
	echo "  $1" >&2
	fail=1
}

stamp() {
	# $1 days from now, in the format openssl wants
	date -u -d "$1 days" +%Y%m%d%H%M%SZ 2>/dev/null ||
		date -u -v"$1"d +%Y%m%d%H%M%SZ
}

make_cert() {
	# $1 name, $2 days until it expires (may be negative)
	openssl req -x509 -newkey rsa:2048 -nodes \
		-keyout "$WORK/certs/$1.key" -out "$WORK/certs/$1.crt" \
		-subj "/CN=$1.test" \
		-not_before "$(stamp -30)" -not_after "$(stamp "$2")" \
		> /dev/null 2>&1 ||
		{ echo "openssl could not make the $1 certificate" >&2; exit 2; }
}

make_cert soon 3
make_cert later 365
make_cert gone -5

for n in soon later gone; do
	printf '  %-6s notAfter %s\n' "$n" \
		"$(openssl x509 -in "$WORK/certs/$n.crt" -noout -enddate | cut -d= -f2)"
done

load=
[ -n "${EXPIRY_LOAD_MODULE:-}" ] && load="load_module $EXPIRY_LOAD_MODULE;"

cat > "$WORK/conf/nginx.conf" <<CONF
$load
daemon on;
master_process on;
worker_processes 1;
pid $WORK/logs/nginx.pid;
error_log $WORK/logs/error.log info;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path $WORK/tmp;

    cert_expiry_warn 14d;
    cert_expiry_check 2s;

    server {
        listen 127.0.0.1:$PORT ssl;
        server_name soon.test;
        ssl_certificate     $WORK/certs/soon.crt;
        ssl_certificate_key $WORK/certs/soon.key;

        location = /days { return 200 "\$ssl_expiry_days\n"; }
    }

    server {
        listen 127.0.0.1:$((PORT + 1)) ssl;
        server_name later.test;
        ssl_certificate     $WORK/certs/later.crt;
        ssl_certificate_key $WORK/certs/later.key;

        location = /days { return 200 "\$ssl_expiry_days\n"; }
    }

    server {
        listen 127.0.0.1:$((PORT + 2)) ssl;
        server_name gone.test;
        ssl_certificate     $WORK/certs/gone.crt;
        ssl_certificate_key $WORK/certs/gone.key;

        location = /days { return 200 "\$ssl_expiry_days\n"; }
    }
}
CONF

cleanup() {
	# every line survives a failure of its own: this runs from an EXIT
	# trap under set -e, where a failed test aborts the function and
	# makes its status the status of the whole script
	if [ -f "$WORK/logs/nginx.pid" ]; then
		kill -QUIT "$(cat "$WORK/logs/nginx.pid")" 2>/dev/null || true
	fi
	sleep 1
}
trap cleanup EXIT INT TERM

"$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf"
sleep 1

echo "--- what the worker said at startup ---"
grep -E 'certificate "' "$WORK/logs/error.log" | sed 's/^.*\] //' | sed 's/^/  /'

echo "--- a certificate three days from its end is a warning ---"
grep -q '\[warn\].*certificate .*soon.crt" expires in [0-9]* days' \
	"$WORK/logs/error.log" ||
	note "no warning for the certificate that expires in three days"

echo "--- a certificate that is already over is an error ---"
grep -q '\[error\].*certificate .*gone.crt" expired [0-9]* days ago' \
	"$WORK/logs/error.log" ||
	note "no error line for the expired certificate"

echo "--- a certificate with a year left is only mentioned ---"
grep -q '\[info\].*certificate .*later.crt" is good for [0-9]* more days' \
	"$WORK/logs/error.log" ||
	note "the long lived certificate was not mentioned at info level"
grep -E '\[(warn|error)\]' "$WORK/logs/error.log" | grep -q 'later.crt' &&
	note "the long lived certificate was warned about"

echo "--- the variable answers over a handshake ---"
days=$(curl -ks --max-time 5 "https://127.0.0.1:$PORT/days" || true)
echo "  soon.test says $days day(s) left"
case $days in
[0-9]*) ;;
*) note "the variable did not answer with a number: $days" ;;
esac
[ "${days:-99}" -le 3 ] 2>/dev/null ||
	note "the variable says $days days, the certificate has three"

echo "--- the check runs again on its own ---"
before=$(grep -c 'certificate .*soon.crt' "$WORK/logs/error.log" || true)
sleep 5
after=$(grep -c 'certificate .*soon.crt' "$WORK/logs/error.log" || true)
echo "  $before lines at first, $after after five seconds"
[ "$after" -gt "$before" ] ||
	note "the timer did not fire again"

echo "--- nothing alarming in the error log ---"
if grep -qE '\[(alert|emerg)\]' "$WORK/logs/error.log"; then
	note "alert or emerg in the error log"
	grep -E '\[(alert|emerg)\]' "$WORK/logs/error.log" | head -3 >&2
else
	echo "  clean"
fi

[ "$fail" -eq 0 ] || { echo "ci/expiry.sh: failed" >&2; exit 1; }
echo "ci/expiry.sh: ok"
