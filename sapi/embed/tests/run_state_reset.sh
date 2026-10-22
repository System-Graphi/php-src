#!/bin/sh
# --enable-embed=static で作成したビルドを変更せず、テスト用バイナリだけを一時作成する。
set -eu

if [ "$#" -ne 1 ]; then
	echo "usage: sh run_state_reset.sh /path/to/php-build" >&2
	exit 2
fi

build_dir=$(cd "$1" && pwd)
test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test_binary=$(mktemp "${TMPDIR:-/tmp}/php-cve-109619.XXXXXX")
trap 'rm -f "$test_binary"' EXIT HUP INT TERM

# ABI、ZTS、リンク依存関係を指定されたビルドに合わせる。
# CFLAGS には libtool 専用のオプションがあるため、CFLAGS_CLEAN を使う。
make -s --no-print-directory -C "$build_dir" -f Makefile -f - \
	CVE_STATE_SOURCE="$test_dir/cve_2026_109619_state_reset.c" \
	CVE_STATE_BINARY="$test_binary" cve-2026-109619-state-reset <<'MAKEFILE'
.PHONY: cve-2026-109619-state-reset
cve-2026-109619-state-reset:
	$(CC) $(CPPFLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS) $(INCLUDES) $(EXTRA_INCLUDES) \
		-DHAVE_CONFIG_H -I"$(top_builddir)" -I"$(top_builddir)/main" \
		-I"$(top_srcdir)" -I"$(top_srcdir)/main" -I"$(top_srcdir)/Zend" \
		-I"$(top_srcdir)/TSRM" -I"$(top_srcdir)/sapi/embed" \
		"$(CVE_STATE_SOURCE)" "$(top_builddir)/libs/libphp5.a" \
		$(EXTRA_LDFLAGS_PROGRAM) $(LDFLAGS) $(NATIVE_RPATHS) $(PHP_FRAMEWORKS) \
		$(EXTRA_LIBS) $(ZEND_EXTRA_LIBS) -o "$(CVE_STATE_BINARY)"
MAKEFILE
"$test_binary"
