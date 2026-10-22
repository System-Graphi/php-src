#!/usr/bin/env python3
"""Run bounded allocation regressions against a PHP 5.x build (Python 3)."""

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path, help="Configured PHP build with CLI, CGI and static embed")
    args = parser.parse_args()
    build = args.build.resolve()
    source = Path(__file__).resolve().parents[2]
    php = build / "sapi/cli/php"
    cgi = build / "sapi/cgi/php-cgi"
    results = []

    def record(name, passed, proc, detail=None):
        item = {"name": name, "passed": bool(passed), "exit": proc.returncode}
        if detail is not None:
            item["detail"] = detail
        if not passed:
            item["stdout"] = proc.stdout.decode(errors="replace")[:1200]
            item["stderr"] = proc.stderr.decode(errors="replace")[:1200]
        results.append(item)
        print(json.dumps(item), flush=True)

    with tempfile.TemporaryDirectory(prefix="php-cve-2026-alloc-") as tmp:
        work = Path(tmp)
        probe = work / "allocation-probe"
        makefile = (build / "Makefile").read_text()
        match = re.search(r"^EXTRA_LIBS\s*=\s*(.*)$", makefile, re.M)
        includes = ["-I" + str(build / part) for part in ["", "main", "Zend", "TSRM"]]
        command = shlex.split(os.environ.get("CC", "cc")) + ["-O0", "-g"] + includes
        command += [str(source / "sapi/embed/tests/cve_2026_109618_alloc.c"),
                    str(build / "libs/libphp5.a")] + shlex.split(match.group(1))
        command += ["-o", str(probe)]
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        for mode in ["normal", "overflow", "persistent", "persistent-realloc"]:
            proc = subprocess.run([str(probe), mode], capture_output=True, timeout=15)
            if mode == "normal":
                passed = proc.returncode == 0 and proc.stdout == b"NORMAL\nSHUTDOWN\nATEXIT\n"
            else:
                passed = (proc.returncode == 1 and b"Fatal error:" in proc.stderr
                          and proc.stdout == b"")
            record("embed-" + mode, passed, proc)

        scripts = {
            "limit-emalloc": "$value = str_repeat('x', 32 * 1024 * 1024);",
            "limit-erealloc": "$value = str_repeat('x', 4 * 1024 * 1024); while (true) { $value .= $value; }",
            "os-emalloc": "$value = str_repeat('x', 256 * 1024 * 1024);",
            "os-system-allocator": "$value = str_repeat('x', 256 * 1024 * 1024);",
        }
        for name, trigger in scripts.items():
            marker = work / (name + ".marker")
            script = work / (name + ".php")
            # この制限は OS の割り当て失敗を再現する子プロセスにだけ設定する。
            is_os_failure = name.startswith("os-")
            limit = "-1" if is_os_failure else "16M"
            if is_os_failure:
                try:
                    import resource
                except ImportError:
                    print(json.dumps({"name": name, "skipped": "POSIX resource limits unavailable"}))
                    continue
                def child_limit():
                    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            else:
                child_limit = None
            marker_php = str(marker).replace("\\", "\\\\").replace("'", "\\'")
            script.write_text("<?php\n"
                + "$marker = '" + marker_php + "';\n"
                + "register_shutdown_function(function () use ($marker) { file_put_contents($marker, 'shutdown', FILE_APPEND); });\n"
                + "class OomMarker { public function __destruct() { global $marker; file_put_contents($marker, 'destructor', FILE_APPEND); } }\n"
                + "$object = new OomMarker();\n"
                + "ob_start(function ($buffer) use ($marker) { file_put_contents($marker, 'output', FILE_APPEND); return $buffer; });\n"
                + trigger + "\necho 'UNSAFE CONTINUATION';\n")
            env = os.environ.copy()
            if name == "os-system-allocator":
                env["USE_ZEND_ALLOC"] = "0"
            else:
                env.pop("USE_ZEND_ALLOC", None)
            proc = subprocess.run([str(php), "-n", "-d", "memory_limit=" + limit,
                                   "-d", "display_errors=0", "-d", "log_errors=0", str(script)],
                                  env=env, capture_output=True, timeout=15,
                                  preexec_fn=child_limit)
            passed = (proc.returncode == 1 and not marker.exists()
                      and proc.stdout == b"" and b"Fatal error:" in proc.stderr)
            record(name, passed, proc, {"cleanup_marker": marker.exists()})

        script = work / "multipart.php"
        script.write_text("<?php echo isset($_POST['field']) ? $_POST['field'] : 'MISSING';")
        for name, header in [("ignored-headers", b"X-Ignored: x\r\n"),
                             ("duplicate-headers", b'Content-Disposition: form-data; name="field"\r\n')]:
            body = (b'--probe-boundary\r\nContent-Disposition: form-data; name="field"\r\n'
                    + header * 100000 + b'\r\nOK\r\n--probe-boundary--\r\n')
            env = os.environ.copy()
            env.update({"REDIRECT_STATUS": "1", "REQUEST_METHOD": "POST",
                        "SCRIPT_FILENAME": str(script), "CONTENT_LENGTH": str(len(body)),
                        "CONTENT_TYPE": "multipart/form-data; boundary=probe-boundary"})
            proc = subprocess.run([str(cgi), "-n", "-d", "memory_limit=8M",
                                   "-d", "post_max_size=8M"], input=body, env=env,
                                  capture_output=True, timeout=20)
            passed = proc.returncode == 0 and proc.stdout.endswith(b"\r\n\r\nOK")
            record("multipart-" + name, passed, proc)

    print(json.dumps({"passed": sum(r["passed"] for r in results), "total": len(results)}))
    return 0 if all(r["passed"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
