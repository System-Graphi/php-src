--TEST--
CVE-2026-109618: multipart body part limit counts empty file controls
--INI--
file_uploads=1
max_file_uploads=20
max_input_vars=1000
max_multipart_body_parts=2
--POST_RAW--
Content-Type: multipart/form-data; boundary=security-boundary
--security-boundary
Content-Disposition: form-data; name="first"

ok
--security-boundary
Content-Disposition: form-data; name="empty"; filename=""
Content-Type: application/octet-stream


--security-boundary
Content-Disposition: form-data; name="last"

must-not-be-parsed
--security-boundary--
--FILE--
<?php
var_dump($_POST);
var_dump($_FILES['empty']['error']);
?>
--EXPECTF--
Warning: Unknown: Multipart body parts limit exceeded 2. To increase the limit change max_multipart_body_parts in php.ini. in Unknown on line 0
array(1) {
  ["first"]=>
  string(2) "ok"
}
int(4)
