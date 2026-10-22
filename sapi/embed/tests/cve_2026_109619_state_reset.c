/*
 * CVE-2026-109619: 実際の致命的エラーとリクエスト終了を通して、
 * 次の初期化前に参照される状態が残らないことを検証する。
 * --enable-embed=static でビルドした PHP を run_state_reset.sh に渡す。
 */
#include "php_embed.h"
#include "zend_exceptions.h"

static int failures = 0;

#define CHECK_STATE(condition, description) do { \
	if (!(condition)) { \
		fprintf(stderr, "FAIL: %s\n", description); \
		failures++; \
	} \
} while (0)

int main(int argc, char **argv)
{
	int i;
	volatile int interrupted = 0;
#ifdef ZTS
	void ***tsrm_ls;
#endif
	char script[] =
		"ini_set('display_errors', '0');"
		"ini_set('log_errors', '0');"
		"function cve_error_one() { return false; }"
		"function cve_error_two() { return false; }"
		"function cve_exception_one($e) {}"
		"function cve_exception_two($e) {}"
		"set_error_handler('cve_error_one');"
		"set_error_handler('cve_error_two');"
		"set_exception_handler('cve_exception_one');"
		"set_exception_handler('cve_exception_two');"
		"header('X-Security-Regression: first-request');"
		"header_register_callback(function () {});"
		"$_GET['request_owned_value'] = 'first-request';"
		"class CveInterruptedInfo extends SplFileInfo {"
		"  function __construct($path) {"
		"    trigger_error('expected interruption', E_USER_ERROR);"
		"  }"
		"}"
		"$info = new SplFileInfo('security-regression');"
		"$info->setInfoClass('CveInterruptedInfo');"
		"$info->getFileInfo();";

	php_embed_module.php_ini_ignore = 1;
	if (php_embed_init(argc, argv PTSRMLS_CC) == FAILURE) {
		fprintf(stderr, "FAIL: embed startup\n");
		return 1;
	}
	SG(headers_sent) = 0;
	php_handle_auth_data("Basic dXNlcjpwYXNz" TSRMLS_CC);

	/* SPL が EH_THROW を一時設定している最中にユーザーコードで中断する。 */
	zend_first_try {
		zend_eval_string(script, NULL, "CVE-2026-109619 producer" TSRMLS_CC);
	} zend_catch {
		interrupted = 1;
	} zend_end_try();
	CHECK_STATE(interrupted, "the producer must reach a fatal bailout");

	php_request_shutdown(NULL);

	/* 解放済み領域は読み取らず、公開参照が切られたことだけを確認する。 */
	CHECK_STATE(EG(error_handling) == EH_NORMAL, "error handling survives request shutdown");
	CHECK_STATE(EG(exception) == NULL && EG(prev_exception) == NULL,
		"exception state survives request shutdown");
	CHECK_STATE(EG(exception_class) == NULL, "exception class survives request shutdown");
	CHECK_STATE(EG(user_error_handler) == NULL && EG(user_exception_handler) == NULL,
		"user handlers survive request shutdown");
	CHECK_STATE(EG(user_error_handlers).elements == NULL
		&& EG(user_exception_handlers).elements == NULL
		&& EG(user_error_handlers_error_reporting).elements == NULL,
		"handler stacks retain freed storage");
	CHECK_STATE(EG(objects_store).object_buckets == NULL && EG(objects_store).top == 1,
		"object store remains reachable after shutdown");
	for (i = 0; i < NUM_TRACK_VARS; i++) {
		CHECK_STATE(PG(http_globals)[i] == NULL, "superglobal survives request shutdown");
	}
	CHECK_STATE(!PG(modules_activated), "module activation survives request shutdown");
	CHECK_STATE(SG(sapi_headers).headers.head == NULL && SG(sapi_headers).headers.tail == NULL,
		"header list retains freed storage");
	CHECK_STATE(SG(request_info).auth_user == NULL && SG(request_info).auth_password == NULL,
		"authentication data retains freed storage");
	CHECK_STATE(SG(callback_func) == NULL, "header callback retains freed storage");

	if (!failures) {
		/* mod_php 等の次リクエストで発生する初期化前診断と同じ消費経路。 */
		zend_first_try {
			zend_error(E_WARNING, "CVE-2026-109619 pre-initialization diagnostic");
		} zend_catch {
			CHECK_STATE(0, "a pre-initialization warning caused a bailout");
		} zend_end_try();
	}

	/* 同じワーカープロセスで次の正常リクエストを処理できることも確認する。 */
	if (php_request_startup(TSRMLS_C) == FAILURE) {
		fprintf(stderr, "FAIL: second request startup\n");
		return 1;
	}
	zend_first_try {
		zval result;
		INIT_ZVAL(result);
		if (zend_eval_string("21 * 2", &result, "CVE-2026-109619 next request" TSRMLS_CC) == FAILURE) {
			CHECK_STATE(0, "second request execution failed");
		} else {
			CHECK_STATE(Z_TYPE(result) == IS_LONG && Z_LVAL(result) == 42,
				"second request returned the wrong value");
			zval_dtor(&result);
		}
	} zend_catch {
		CHECK_STATE(0, "second request caused a bailout");
	} zend_end_try();
	php_embed_shutdown(TSRMLS_C);

	if (!failures) {
		puts("PASS: fatal interruption, shutdown, early diagnostic, next request");
	}
	return failures ? 1 : 0;
}
