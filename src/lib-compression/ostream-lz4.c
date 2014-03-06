/* Copyright (c) 2013-2014 Dovecot authors, see the included COPYING file */

#include "lib.h"

#ifdef HAVE_LZ4

#include "ostream-private.h"
#include "ostream-zlib.h"
#include "iostream-lz4.h"
#include <lz4.h>

#define CHUNK_SIZE OSTREAM_LZ4_CHUNK_SIZE

struct lz4_ostream {
	struct ostream_private ostream;

	unsigned char compressbuf[CHUNK_SIZE];
	unsigned int compressbuf_offset;

	/* chunk size, followed by compressed data */
	unsigned char outbuf[IOSTREAM_LZ4_CHUNK_PREFIX_LEN +
	                     LZ4_COMPRESSBOUND(CHUNK_SIZE)];
	unsigned int outbuf_offset, outbuf_used;
};

static void o_stream_lz4_close(struct iostream_private *stream,
			       bool close_parent)
{
	struct lz4_ostream *zstream = (struct lz4_ostream *)stream;

	(void)o_stream_flush(&zstream->ostream.ostream);
	if (close_parent)
		o_stream_close(zstream->ostream.parent);
}

static int o_stream_lz4_send_outbuf(struct lz4_ostream *zstream)
{
	ssize_t ret;
	size_t size;

	if (zstream->outbuf_used == 0)
		return 1;

	size = zstream->outbuf_used - zstream->outbuf_offset;
	i_assert(size > 0);
	ret = o_stream_send(zstream->ostream.parent,
			    zstream->outbuf + zstream->outbuf_offset, size);
	if (ret < 0) {
		o_stream_copy_error_from_parent(&zstream->ostream);
		return -1;
	}
	if ((size_t)ret != size) {
		zstream->outbuf_offset += ret;
		return 0;
	}
	zstream->outbuf_offset = 0;
	zstream->outbuf_used = 0;
	return 1;
}

static int o_stream_lz4_compress(struct lz4_ostream *zstream)
{
	uint32_t chunk_size;
	int ret;

	if (zstream->compressbuf_offset == 0)
		return 1;
	if ((ret = o_stream_lz4_send_outbuf(zstream)) <= 0)
		return ret;

	i_assert(zstream->outbuf_offset == 0);
	i_assert(zstream->outbuf_used == 0);

	ret = LZ4_compress((void *)zstream->compressbuf,
			   (void *)(zstream->outbuf +
			            IOSTREAM_LZ4_CHUNK_PREFIX_LEN),
			   zstream->compressbuf_offset);
	i_assert(ret > 0 && (unsigned int)ret <= sizeof(zstream->outbuf) -
	         IOSTREAM_LZ4_CHUNK_PREFIX_LEN);
	zstream->outbuf_used = IOSTREAM_LZ4_CHUNK_PREFIX_LEN + ret;
	chunk_size = zstream->outbuf_used - IOSTREAM_LZ4_CHUNK_PREFIX_LEN;
	zstream->outbuf[0] = (chunk_size & 0xff000000) >> 24;
	zstream->outbuf[1] = (chunk_size & 0x00ff0000) >> 16;
	zstream->outbuf[2] = (chunk_size & 0x0000ff00) >> 8;
	zstream->outbuf[3] = (chunk_size & 0x000000ff);
	zstream->compressbuf_offset = 0;
	return 1;
}

static ssize_t
o_stream_lz4_send_chunk(struct lz4_ostream *zstream,
			const void *data, size_t size)
{
	size_t max_size;
	ssize_t added_bytes = 0;
	int ret;

	i_assert(zstream->outbuf_used == 0);

	do {
		max_size = I_MIN(size, sizeof(zstream->compressbuf) -
				 zstream->compressbuf_offset);
		memcpy(zstream->compressbuf + zstream->compressbuf_offset,
		       data, max_size);
		zstream->compressbuf_offset += max_size;

		data = CONST_PTR_OFFSET(data, max_size);
		size -= max_size;
		added_bytes += max_size;

		if (zstream->compressbuf_offset == sizeof(zstream->compressbuf)) {
			ret = o_stream_lz4_compress(zstream);
			if (ret <= 0)
				return added_bytes != 0 ? added_bytes : ret;
		}
	} while (size > 0);

	return added_bytes;
}

static int o_stream_lz4_flush(struct ostream_private *stream)
{
	struct lz4_ostream *zstream = (struct lz4_ostream *)stream;
	int ret;

	if (o_stream_lz4_compress(zstream) < 0)
		return -1;
	if (o_stream_lz4_send_outbuf(zstream) < 0)
		return -1;

	ret = o_stream_flush(stream->parent);
	if (ret < 0)
		o_stream_copy_error_from_parent(stream);
	return ret;
}

static ssize_t
o_stream_lz4_sendv(struct ostream_private *stream,
		    const struct const_iovec *iov, unsigned int iov_count)
{
	struct lz4_ostream *zstream = (struct lz4_ostream *)stream;
	ssize_t ret, bytes = 0;
	unsigned int i;

	if ((ret = o_stream_lz4_send_outbuf(zstream)) <= 0) {
		/* error / we still couldn't flush existing data to
		   parent stream. */
		return ret;
	}

	for (i = 0; i < iov_count; i++) {
		ret = o_stream_lz4_send_chunk(zstream, iov[i].iov_base,
					      iov[i].iov_len);
		if (ret < 0)
			return -1;
		bytes += ret;
		if ((size_t)ret != iov[i].iov_len)
			break;
	}
	stream->ostream.offset += bytes;
	return bytes;
}

struct ostream *o_stream_create_lz4(struct ostream *output, int level)
{
	struct iostream_lz4_header *hdr;
	struct lz4_ostream *zstream;

	i_assert(level >= 1 && level <= 9);

	zstream = i_new(struct lz4_ostream, 1);
	zstream->ostream.sendv = o_stream_lz4_sendv;
	zstream->ostream.flush = o_stream_lz4_flush;
	zstream->ostream.iostream.close = o_stream_lz4_close;

	i_assert(sizeof(zstream->outbuf) >= sizeof(*hdr));
	hdr = (void *)zstream->outbuf;
	memcpy(hdr->magic, IOSTREAM_LZ4_MAGIC, sizeof(hdr->magic));
	hdr->max_uncompressed_chunk_size[0] =
		(OSTREAM_LZ4_CHUNK_SIZE & 0xff000000) >> 24;
	hdr->max_uncompressed_chunk_size[1] =
		(OSTREAM_LZ4_CHUNK_SIZE & 0x00ff0000) >> 16;
	hdr->max_uncompressed_chunk_size[2] =
		(OSTREAM_LZ4_CHUNK_SIZE & 0x0000ff00) >> 8;
	hdr->max_uncompressed_chunk_size[3] =
		(OSTREAM_LZ4_CHUNK_SIZE & 0x000000ff);
	zstream->outbuf_used = sizeof(*hdr);
	return o_stream_create(&zstream->ostream, output,
			       o_stream_get_fd(output));
}
#endif
