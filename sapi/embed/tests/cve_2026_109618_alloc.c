#include "sapi/embed/php_embed.h"
#include <stdlib.h>
#include <string.h>

static void allocation_probe_atexit(void)
{
	fputs("ATEXIT\n", stdout);
	fflush(stdout);
}

int main(int argc, char **argv)
{
	const char *mode;
	void *block = NULL;
#ifdef ZTS
	void ***tsrm_ls;
#endif

	if (argc != 2) {
		return 64;
	}
	mode = argv[1];
	php_embed_module.php_ini_ignore = 1;
	if (php_embed_init(1, argv PTSRMLS_CC) == FAILURE) {
		return 77;
	}
	atexit(allocation_probe_atexit);

	zend_first_try {
		zend_eval_string("register_shutdown_function(function () { echo \"SHUTDOWN\\n\"; });", NULL, "allocation-probe" TSRMLS_CC);
		if (!strcmp(mode, "overflow")) {
			block = safe_emalloc((size_t)-1, 2, 0);
		} else if (!strcmp(mode, "persistent")) {
			block = pemalloc((size_t)-1, 1);
		} else if (!strcmp(mode, "persistent-realloc")) {
			block = pemalloc(32, 1);
			block = perealloc(block, (size_t)-1, 1);
		} else if (!strcmp(mode, "normal")) {
			block = safe_emalloc(16, 4, 0);
			memset(block, 'x', 64);
			efree(block);
			fputs("NORMAL\n", stdout);
			fflush(stdout);
		} else {
			return 64;
		}
	} zend_catch {
		fputs("BAILOUT\n", stdout);
	} zend_end_try();

	php_embed_shutdown(TSRMLS_C);
	return !strcmp(mode, "normal") ? 0 : 99;
}
