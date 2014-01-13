/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "buffer.h"
#include "str.h"
#include "str-sanitize.h"
#include "istream.h"
#include "ostream.h"
#include "test-common.h"
#include "http-url.h"
#include "http-request-parser.h"

#include <time.h>

/*
 * Test: valid requests
 */

struct http_request_valid_parse_test {
	const char *request;
	const char *method;
	const char *target_raw;
	struct {
		enum http_request_target_format format;
		struct http_url url;
	} target;
	unsigned char version_major;
	unsigned char version_minor;
	uoff_t content_length;
	const char *payload;
	bool connection_close;
	bool expect_100_continue;
};

static const struct http_request_valid_parse_test
valid_request_parse_tests[] = {
	{ .request =
			"GET / HTTP/1.1\r\n"
			"Host: example.com\r\n"
			"\r\n",
		.method = "GET",
		.target_raw = "/",
		.target = {
			.format = HTTP_REQUEST_TARGET_FORMAT_ORIGIN,
			.url = { .host_name = "example.com" }
		},
		.version_major = 1, .version_minor = 1,
	},{ .request =
			"OPTIONS * HTTP/1.0\r\n"
			"Host: example.com\r\n"
			"Connection: Keep-Alive\r\n"
			"\r\n",
		.method = "OPTIONS",
		.target_raw = "*",
		.target = {
			.format = HTTP_REQUEST_TARGET_FORMAT_ASTERISK,
			.url = { .host_name = "example.com" }
		},
		.version_major = 1, .version_minor = 0,
	},{ .request =
			"CONNECT example.com:443 HTTP/1.2\r\n"
			"Host: example.com:443\r\n"
			"\r\n",
		.method = "CONNECT",
		.target_raw = "example.com:443",
		.target = {
			.format = HTTP_REQUEST_TARGET_FORMAT_AUTHORITY,
			.url = { .host_name = "example.com", .have_port = TRUE, .port = 443 }
		},
		.version_major = 1, .version_minor = 2,
	},{ .request =
			"GET https://www.example.com:443 HTTP/1.1\r\n"
			"Host: www.example.com:80\r\n"
			"\r\n",
		.method = "GET",
		.target_raw = "https://www.example.com:443",
		.target = {
			.format = HTTP_REQUEST_TARGET_FORMAT_ABSOLUTE,
			.url = {
				.host_name = "www.example.com",
				.have_port = TRUE, .port = 443,
				.have_ssl = TRUE
			}
		},
		.version_major = 1, .version_minor = 1,
	},{ .request =
			"POST http://api.example.com:8080/commit?user=dirk HTTP/1.1\r\n"
			"Host: api.example.com:8080\r\n"
			"Content-Length: 10\r\n"
			"\r\n"
			"Content!\r\n",
		.method = "POST",
		.target_raw = "http://api.example.com:8080/commit?user=dirk",
		.target = {
			.format = HTTP_REQUEST_TARGET_FORMAT_ABSOLUTE,
			.url = { .host_name = "api.example.com", .have_port = TRUE, .port = 8080 }
		},
		.version_major = 1, .version_minor = 1,
		.payload = "Content!\r\n"
	},{ .request =
			"GET http://www.example.com/index.php?seq=1 HTTP/1.1\r\n"
			"Host: www.example.com\r\n"
			"Connection: close\r\n"
			"\r\n",
		.method = "GET",
		.target_raw = "http://www.example.com/index.php?seq=1",
		.target = {
			.format = HTTP_REQUEST_TARGET_FORMAT_ABSOLUTE,
			.url = { .host_name = "www.example.com" }
		},
		.version_major = 1, .version_minor = 1,
		.connection_close = TRUE
	},{ .request =
			"GET http://www.example.com/index.html HTTP/1.0\r\n"
			"Host: www.example.com\r\n"
			"\r\n",
		.method = "GET",
		.target_raw = "http://www.example.com/index.html",
		.target = {
			.format = HTTP_REQUEST_TARGET_FORMAT_ABSOLUTE,
			.url = { .host_name = "www.example.com" }
		},
		.version_major = 1, .version_minor = 0,
		.connection_close = TRUE
	},{ .request =
			"GET http://www.example.com/index.html HTTP/1.1\r\n"
			"Host: www.example.com\r\n"
			"Expect: 100-continue\r\n"
			"\r\n",
		.method = "GET",
		.target_raw = "http://www.example.com/index.html",
		.target = {
			.format = HTTP_REQUEST_TARGET_FORMAT_ABSOLUTE,
			.url = { .host_name = "www.example.com" }
		},
		.version_major = 1, .version_minor = 1,
		.expect_100_continue = TRUE
	}
};

unsigned int valid_request_parse_test_count =
	N_ELEMENTS(valid_request_parse_tests);

static const char *
_request_target_format(enum http_request_target_format target_format)
{
	switch (target_format) {
	case HTTP_REQUEST_TARGET_FORMAT_ORIGIN:
		return "origin";
	case HTTP_REQUEST_TARGET_FORMAT_ABSOLUTE:
		return "absolute";
	case HTTP_REQUEST_TARGET_FORMAT_AUTHORITY:
		return "authority";
	case HTTP_REQUEST_TARGET_FORMAT_ASTERISK:
		return "asterisk";
	}
	return t_strdup_printf("<<UNKNOWN: %u>>", target_format);
}

static void test_http_request_parse_valid(void)
{
	unsigned int i;
	buffer_t *payload_buffer = buffer_create_dynamic(default_pool, 1024);

	for (i = 0; i < valid_request_parse_test_count; i++) T_BEGIN {
		struct istream *input;
		struct ostream *output;
		const struct http_request_valid_parse_test *test;
		struct http_request_parser *parser;
		struct http_request request;
		enum http_request_parse_error error_code;
		const char *request_text, *payload, *error;
		unsigned int pos, request_text_len;
		int ret = 0;

		test = &valid_request_parse_tests[i];
		request_text = test->request;
		request_text_len = strlen(request_text);
		input = test_istream_create_data(request_text, request_text_len);
		parser = http_request_parser_init(input, NULL);

		test_begin(t_strdup_printf("http request valid [%d]", i));

		payload = NULL;
		for (pos = 0; pos <= request_text_len && ret == 0; pos++) {
			test_istream_set_size(input, pos);
			ret = http_request_parse_next
				(parser, FALSE, &request, &error_code, &error);
		}
		test_istream_set_size(input, request_text_len);
		while (ret > 0) {
			if (request.payload != NULL) {
				buffer_set_used_size(payload_buffer, 0);
				output = o_stream_create_buffer(payload_buffer);
				test_out("payload receive", 
					o_stream_send_istream(output, request.payload));
				o_stream_destroy(&output);
				payload = str_c(payload_buffer);
			} else {
				payload = NULL;
			}
			ret = http_request_parse_next
				(parser, FALSE, &request, &error_code, &error);
		}

		test_out_reason("parse success", ret == 0, error);
		
		if (ret == 0) {
			/* verify last request only */
			if (request.method == NULL || test->method == NULL) {
				test_out(t_strdup_printf("request->method = %s", request.method),
					request.method == test->method);
			} else {
				test_out(t_strdup_printf("request->method = %s", request.method),
					strcmp(request.method, test->method) == 0);
			}

			if (request.target_raw == NULL || test->target_raw == NULL) {
				test_out(t_strdup_printf
						("request->target_raw = %s", request.target_raw),
					request.target_raw == test->target_raw);
			} else {
				test_out(t_strdup_printf
						("request->target_raw = %s", request.target_raw),
					strcmp(request.target_raw, test->target_raw) == 0);
			}
			if (request.target.url == NULL) {
				test_out("request->target.url = (null)",
					test->target.url.host_name == NULL && !test->target.url.have_port);
			} else {
				if (request.target.url->host_name == NULL ||
					test->target.url.host_name == NULL) {
					test_out(t_strdup_printf("request->target.url->host_name = %s",
							request.target.url->host_name),
						request.target.url->host_name == test->target.url.host_name);
				} else {
					test_out(t_strdup_printf("request->target.url->host_name = %s",
							request.target.url->host_name),
						strcmp(request.target.url->host_name,
							test->target.url.host_name) == 0);
				}
				if (!request.target.url->have_port) {
					test_out("request->target.url->port = (unspecified)",
						request.target.url->have_port == test->target.url.have_port);
				} else {
					test_out(t_strdup_printf
						("request->target.url->port = %u", request.target.url->port),
						request.target.url->have_port == test->target.url.have_port &&
						request.target.url->port == test->target.url.port);
				}
				test_out(t_strdup_printf("request->target.url->have_ssl = %s",
					(request.target.url->have_ssl ? "yes" : "no")),
					request.target.url->have_ssl == test->target.url.have_ssl);
			}
			test_out(t_strdup_printf("request->target_format = %s",
					_request_target_format(request.target.format)),
					request.target.format == test->target.format);

			test_out(t_strdup_printf("request->version = %u.%u",
					request.version_major, request.version_minor),
					request.version_major == test->version_major &&
					request.version_minor == test->version_minor);
			test_out(t_strdup_printf("request->connection_close = %s",
					(request.connection_close ? "yes" : "no")),
					request.connection_close == test->connection_close);
			test_out(t_strdup_printf("request->expect_100_continue = %s",
					(request.expect_100_continue ? "yes" : "no")),
					request.expect_100_continue == test->expect_100_continue);
		
			if (payload == NULL || test->payload == NULL) {
				test_out(t_strdup_printf("request->payload = %s",
					str_sanitize(payload, 80)),
					payload == test->payload);
			} else {
				test_out(t_strdup_printf("request->payload = %s",
					str_sanitize(payload, 80)),
					strcmp(payload, test->payload) == 0);
			}
		}
		test_end();
		http_request_parser_deinit(&parser);
	} T_END;

	buffer_free(&payload_buffer);
}

/*
 * Test: invalid requests
 */

struct http_request_invalid_parse_test {
	const char *request;
	enum http_request_parse_error error_code;
};

static struct http_request_invalid_parse_test
invalid_request_parse_tests[] = {
	{ .request =
			"GET: / HTTP/1.1\r\n"
			"Host: example.com\r\n"
			"\r\n",
		.error_code = HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST
	},{ .request =
			"GET % HTTP/1.1\r\n"
			"Host: example.com\r\n"
			"\r\n",
		.error_code = HTTP_REQUEST_PARSE_ERROR_BAD_REQUEST
	},{ .request =
			"GET /frop\" HTTP/1.1\r\n"
			"Host: example.com\r\n"
			"\r\n",
		.error_code = HTTP_REQUEST_PARSE_ERROR_BAD_REQUEST
	},{ .request =
			"GET / HTCPCP/1.0\r\n"
			"Host: example.com\r\n"
			"\r\n",
		.error_code = HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST
	},{ .request =
			"GET / HTTP/1.0.1\r\n"
			"Host: example.com\r\n"
			"\r\n",
		.error_code = HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST
	},{ .request =
			"GET / HTTP/1.1\r\n"
			"Host: \"example.com\r\n"
			"\r\n",
		.error_code = HTTP_REQUEST_PARSE_ERROR_BAD_REQUEST
	},{ .request =
			"GET / HTTP/1.1\r\n"
			"\r\n",
		.error_code = HTTP_REQUEST_PARSE_ERROR_BAD_REQUEST
	},{ .request =
			"GET / HTTP/1.1\r\n"
			"Host: www.example.com\r\n"
			"Transfer-Encoding: gzip\r\n"
			"\r\n",
		.error_code = HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST
	},{ .request =
			"GET / HTTP/1.1\r\n"
			"Host: www.example.com\r\n"
			"Expect: payment\r\n"
			"\r\n",
		.error_code = HTTP_REQUEST_PARSE_ERROR_EXPECTATION_FAILED
	},{ .request =
			"GET / HTTP/1.1\r\n"
			"Host: www.example.com\r\n"
			"Transfer-Encoding: cuneiform, chunked\r\n"
			"\r\n",
		.error_code = HTTP_REQUEST_PARSE_ERROR_NOT_IMPLEMENTED
	}
	// FIXME: test request limits
};

static unsigned char invalid_request_with_nuls[] =
	"GET / HTTP/1.1\r\n"
	"Host: example.com\r\n"
	"Null: text\0server\r\n"
	"\r\n";

unsigned int invalid_request_parse_test_count =
	N_ELEMENTS(invalid_request_parse_tests);

static const char *
_request_parse_error(enum http_request_parse_error error)
{
	switch (error) {
	case HTTP_REQUEST_PARSE_ERROR_NONE:
		return "none?!";
	case HTTP_REQUEST_PARSE_ERROR_BROKEN_STREAM:
		return "broken stream";
	case HTTP_REQUEST_PARSE_ERROR_BROKEN_REQUEST:
		return "broken request";
	case HTTP_REQUEST_PARSE_ERROR_BAD_REQUEST:
		return "bad request";
	case HTTP_REQUEST_PARSE_ERROR_NOT_IMPLEMENTED:
		return "not implemented";
	case HTTP_REQUEST_PARSE_ERROR_EXPECTATION_FAILED:
		return "expectation failed";
	case HTTP_REQUEST_PARSE_ERROR_METHOD_TOO_LONG:
		return "method too long";
	case HTTP_REQUEST_PARSE_ERROR_TARGET_TOO_LONG:
		return "target too long";
	case HTTP_REQUEST_PARSE_ERROR_PAYLOAD_TOO_LARGE:
		return "payload too large";
	}
	return t_strdup_printf("<<UNKNOWN: %u>>", error);
}

static void test_http_request_parse_invalid(void)
{
	const struct http_request_invalid_parse_test *test;
	struct http_request_parser *parser;
	struct http_request request;
	enum http_request_parse_error error_code;
	const char *request_text, *error;
	struct istream *input;
	int ret;
	unsigned int i;

	for (i = 0; i < invalid_request_parse_test_count; i++) T_BEGIN {
		test = &invalid_request_parse_tests[i];
		request_text = test->request;
		input = i_stream_create_from_data(request_text, strlen(request_text));
		parser = http_request_parser_init(input, NULL);

		test_begin(t_strdup_printf("http request invalid [%d]", i));

		while ((ret=http_request_parse_next
			(parser, FALSE, &request, &error_code, &error)) > 0);

		test_out_reason("parse failure", ret < 0, error);
		if (ret < 0) {
			test_out(t_strdup_printf("parse error code = %s",
				_request_parse_error(error_code)), error_code == test->error_code);
		}
		test_end();
		http_request_parser_deinit(&parser);
	} T_END;

	/* parse failure guarantees http_request_header.size equals
	   strlen(http_request_header.value) */
	test_begin("http request with NULs");
	input = i_stream_create_from_data(invalid_request_with_nuls,
					  sizeof(invalid_request_with_nuls)-1);
	parser = http_request_parser_init(input, 0);
	while ((ret=http_request_parse_next
		(parser, FALSE, &request, &error_code, &error)) > 0);
	test_assert(ret < 0);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_http_request_parse_valid,
		test_http_request_parse_invalid,
		NULL
	};
	return test_run(test_functions);
}
