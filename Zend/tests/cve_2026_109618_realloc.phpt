--TEST--
CVE-2026-109618: reallocation failure must not execute request shutdown callbacks
--INI--
memory_limit=16M
--FILE--
<?php
register_shutdown_function(function () { echo "UNSAFE SHUTDOWN\n"; });
$value = str_repeat("x", 4 * 1024 * 1024);
while (true) {
    $value .= $value;
}
?>
--EXPECTF--
Fatal error: Allowed memory size of %d bytes exhausted%r(?: at [^\r\n]+:\d+)?%r (tried to allocate %d bytes) in %s on line %d
