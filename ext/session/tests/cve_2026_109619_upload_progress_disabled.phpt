--TEST--
CVE-2026-109619: upload progress stays disabled without breaking sessions or uploads
--DESCRIPTION--
起動時に有効化を指定しても進捗情報を作らず、通常のアップロードとセッション保存は継続する。
--INI--
file_uploads=1
upload_max_filesize=1M
post_max_size=2M
session.save_path={PWD}
session.name=CVESESSION
session.use_cookies=1
session.use_only_cookies=1
session.use_strict_mode=0
session.use_trans_sid=0
session.gc_probability=0
session.cache_limiter=
session.upload_progress.enabled=1
session.upload_progress.cleanup=0
session.upload_progress.prefix=upload_progress_
session.upload_progress.name=PHP_SESSION_UPLOAD_PROGRESS
session.upload_progress.freq=1%
session.upload_progress.min_freq=0
--SKIPIF--
<?php include('skipif.inc'); ?>
--COOKIE--
CVESESSION=cve2026109619
--POST_RAW--
Content-Type: multipart/form-data; boundary=CVE2026109619
--CVE2026109619
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

security-test
--CVE2026109619
Content-Disposition: form-data; name="file"; filename="sample.txt"
Content-Type: text/plain

data
--CVE2026109619--
--FILE--
<?php
ob_start();
var_dump(ini_get('session.upload_progress.enabled'));
var_dump($_POST['PHP_SESSION_UPLOAD_PROGRESS']);
var_dump($_FILES['file']['error'] === UPLOAD_ERR_OK);
var_dump(is_uploaded_file($_FILES['file']['tmp_name']));
var_dump(file_get_contents($_FILES['file']['tmp_name']));
var_dump(session_start());
var_dump(isset($_SESSION['upload_progress_security-test']));
$_SESSION['ordinary_session_value'] = 'preserved';
session_write_close();
var_dump(session_start());
var_dump($_SESSION['ordinary_session_value']);
session_destroy();
ob_end_flush();
?>
--CLEAN--
<?php
@unlink(__DIR__ . '/sess_cve2026109619');
?>
--EXPECT--
string(1) "0"
string(13) "security-test"
bool(true)
bool(true)
string(4) "data"
bool(true)
bool(false)
bool(true)
string(9) "preserved"
