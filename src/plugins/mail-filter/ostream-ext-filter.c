/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "net.h"
#include "eacces-error.h"
#include "istream.h"
#include "ostream-private.h"
#include "ostream-ext-filter.h"

#include <unistd.h>

struct mail_filter_ostream {
	struct ostream_private ostream;

	int fd;
	struct istream *ext_in;
	struct ostream *ext_out;
	bool flushed;
};

static void
o_stream_mail_filter_close(struct iostream_private *stream, bool close_parent)
{
	struct mail_filter_ostream *mstream =
		(struct mail_filter_ostream *)stream;

	if (mstream->ext_in != NULL)
		i_stream_destroy(&mstream->ext_in);
	if (mstream->ext_out != NULL)
		o_stream_destroy(&mstream->ext_out);
	if (mstream->fd != -1) {
		if (close(mstream->fd) < 0)
			i_error("ext-filter: close() failed: %m");
		mstream->fd = -1;
	}
	if (close_parent)
		o_stream_close(mstream->ostream.parent);
}

static ssize_t
o_stream_mail_filter_sendv(struct ostream_private *stream,
			   const struct const_iovec *iov,
			   unsigned int iov_count)
{
	struct mail_filter_ostream *mstream =
		(struct mail_filter_ostream *)stream;
	ssize_t ret;

	if (mstream->ext_out == NULL) {
		/* connect failed */
		mstream->ostream.ostream.stream_errno = EIO;
		return -1;
	}

	/* send the data to the filter */
	ret = o_stream_sendv(mstream->ext_out, iov, iov_count);
	if (ret < 0) {
		stream->ostream.stream_errno =
			mstream->ext_out->stream_errno;
		return -1;
	}
	stream->ostream.offset += ret;
	return ret;
}

static int o_stream_mail_filter_flush(struct ostream_private *stream)
{
	struct mail_filter_ostream *mstream =
		(struct mail_filter_ostream *)stream;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	if (mstream->ext_out == NULL) {
		/* connect failed */
		return -1;
	}
	if (mstream->flushed)
		return 0;

	if (shutdown(mstream->fd, SHUT_WR) < 0)
		i_error("ext-filter: shutdown() failed: %m");

	while ((ret = i_stream_read_data(mstream->ext_in, &data, &size, 0)) > 0) {
		ret = o_stream_send(stream->parent, data, size);
		if (ret != (ssize_t)size) {
			i_assert(ret < 0);
			o_stream_copy_error_from_parent(stream);
			return -1;
		}
		i_stream_skip(mstream->ext_in, size);
	}
	i_assert(ret == -1);

	if (!i_stream_have_bytes_left(mstream->ext_in) &&
	    mstream->ext_in->v_offset == 0) {
		/* EOF without any input -> assume the script is repoting
		   failure. pretty ugly way, but currently there's no error
		   reporting channel. */
		stream->ostream.stream_errno = EIO;
		return -1;
	}
	if (mstream->ext_in->stream_errno != 0) {
		stream->ostream.stream_errno = mstream->ext_in->stream_errno;
		return -1;
	}

	ret = o_stream_flush(stream->parent);
	if (ret < 0)
		o_stream_copy_error_from_parent(stream);
	else
		mstream->flushed = TRUE;
	return ret;
}

static int filter_connect(struct mail_filter_ostream *mstream,
			  const char *socket_path, const char *args)
{
	const char **argv;
	string_t *str;
	int fd;

	argv = t_strsplit(args, " ");

	if ((fd = net_connect_unix_with_retries(socket_path, 1000)) < 0) {
		if (errno == EACCES) {
			i_error("ext-filter: %s",
				eacces_error_get("net_connect_unix",
						 socket_path));
		} else {
			i_error("ext-filter: net_connect_unix(%s) failed: %m",
				socket_path);
		}
		return -1;
	}
	net_set_nonblock(fd, FALSE);

	mstream->fd = fd;
	mstream->ext_in = i_stream_create_fd(fd, IO_BLOCK_SIZE, FALSE);
	mstream->ext_out = o_stream_create_fd(fd, 0, FALSE);

	str = t_str_new(256);
	str_append(str, "VERSION\tscript\t3\t0\nnoreply\n");
	for (; *argv != NULL; argv++) {
		str_append(str, *argv);
		str_append_c(str, '\n');
	}
	str_append_c(str, '\n');

	o_stream_send(mstream->ext_out, str_data(str), str_len(str));
	return 0;
}

struct ostream *
o_stream_create_ext_filter(struct ostream *output, const char *socket_path,
			   const char *args)
{
	struct mail_filter_ostream *mstream;

	mstream = i_new(struct mail_filter_ostream, 1);
	mstream->fd = -1;
	mstream->ostream.iostream.close = o_stream_mail_filter_close;
	mstream->ostream.sendv = o_stream_mail_filter_sendv;
	mstream->ostream.flush = o_stream_mail_filter_flush;

	(void)filter_connect(mstream, socket_path, args);

	return o_stream_create(&mstream->ostream, output, mstream->fd);
}
