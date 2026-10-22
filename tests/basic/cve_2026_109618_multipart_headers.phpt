--TEST--
CVE-2026-109618: retain first supported multipart headers and ordinary upload data
--INI--
file_uploads=1
--POST_RAW--
Content-Type: multipart/form-data; boundary=security-boundary
--security-boundary
X-Ignored: ignored
 ignored continuation
Content-Disposition: form-data;
 name="file"; filename="sample.txt"
Content-Disposition: form-data; name="wrong"; filename="wrong.txt"
Content-Type: text/plain
Content-Type: application/octet-stream
X-Ignored: another ignored header

hello
--security-boundary
Content-Disposition: form-data; name="nested[key]"

value
--security-boundary--
--FILE--
<?php
var_dump($_POST['nested']['key']);
var_dump(count($_FILES), $_FILES['file']['name'], $_FILES['file']['type']);
var_dump($_FILES['file']['error'], $_FILES['file']['size']);
var_dump(file_get_contents($_FILES['file']['tmp_name']));
?>
--EXPECT--
string(5) "value"
int(1)
string(10) "sample.txt"
string(10) "text/plain"
int(0)
int(5)
string(5) "hello"
