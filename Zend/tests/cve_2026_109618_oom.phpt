--TEST--
CVE-2026-109618: allocation failure must not execute request shutdown callbacks
--INI--
memory_limit=16M
--FILE--
<?php
register_shutdown_function(function () { echo "UNSAFE SHUTDOWN\n"; });
class OomShutdownProbe {
    public function __destruct() { echo "UNSAFE DESTRUCTOR\n"; }
}
$probe = new OomShutdownProbe();
$value = str_repeat("x", 32 * 1024 * 1024);
echo "UNSAFE CONTINUATION\n";
?>
--EXPECTF--
Fatal error: Allowed memory size of %d bytes exhausted%r(?: at [^\r\n]+:\d+)?%r (tried to allocate %d bytes) in %s on line %d
