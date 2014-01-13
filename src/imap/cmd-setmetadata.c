/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "ioloop.h"
#include "istream.h"
#include "istream-seekable.h"
#include "ostream.h"
#include "str.h"
#include "imap-metadata.h"

#define METADATA_MAX_INMEM_SIZE (1024*128)

struct imap_setmetadata_context {
	struct client_command_context *cmd;
	struct imap_parser *parser;

	const char *key_prefix;

	struct mailbox *box;
	struct mailbox_transaction_context *trans;

	char *entry_name;
	uoff_t entry_value_len;
	struct istream *input;
	bool failed;
	bool cmd_error_sent;
	bool storage_failure;
};

static void cmd_setmetadata_deinit(struct imap_setmetadata_context *ctx)
{
	ctx->cmd->client->input_lock = NULL;
	imap_parser_unref(&ctx->parser);
	if (ctx->trans != NULL)
		mailbox_transaction_rollback(&ctx->trans);
	if (ctx->box != ctx->cmd->client->mailbox)
		mailbox_free(&ctx->box);
	i_free(ctx->entry_name);
}

static int
cmd_setmetadata_parse_entryvalue(struct imap_setmetadata_context *ctx,
				 const char **entry_r,
				 const struct imap_arg **value_r)
{
	const struct imap_arg *args;
	const char *name, *error;
	int ret;
	bool fatal;

	/* parse the entry name */
	ret = imap_parser_read_args(ctx->parser, 1,
				    IMAP_PARSE_FLAG_INSIDE_LIST, &args);
	if (ret >= 0) {
		if (ret == 0) {
			/* ')' found */
			*entry_r = NULL;
			return 1;
		}
		if (!imap_arg_get_astring(args, &name)) {
			client_send_command_error(ctx->cmd,
						  "Entry name isn't astring");
			return -1;
		}

		ret = imap_parser_read_args(ctx->parser, 2,
					    IMAP_PARSE_FLAG_INSIDE_LIST |
					    IMAP_PARSE_FLAG_LITERAL_SIZE |
					    IMAP_PARSE_FLAG_LITERAL8, &args);
	}
	if (ret < 0) {
		if (ret == -2)
			return 0;
		error = imap_parser_get_error(ctx->parser, &fatal);
		if (fatal) {
			client_disconnect_with_error(ctx->cmd->client, error);
			return -1;
		}
		client_send_command_error(ctx->cmd, error);
		return -1;
	}
	i_assert(!IMAP_ARG_IS_EOL(&args[1]));
	if (args[1].type == IMAP_ARG_LIST) {
		client_send_command_error(ctx->cmd, "Entry value can't be a list");
		return -1;
	}
	if (ctx->cmd_error_sent ||
	    !imap_metadata_verify_entry_name(ctx->cmd, name)) {
		ctx->cmd->param_error = FALSE;
		ctx->cmd->state = CLIENT_COMMAND_STATE_WAIT_INPUT;

		ctx->cmd_error_sent = TRUE;
		ctx->failed = TRUE;
		if (args[1].type == IMAP_ARG_LITERAL_SIZE) {
			/* client won't see "+ OK", so we can abort
			   immediately */
			ctx->cmd->client->input_skip_line = FALSE;
			return -1;
		}
	}

	/* entry names are case-insensitive. handle this by using only
	   lowercase names. */
	*entry_r = t_str_lcase(name);
	*value_r = &args[1];
	return 1;
}

static int
cmd_setmetadata_entry_read_stream(struct imap_setmetadata_context *ctx)
{
	const unsigned char *data;
	size_t size;
	enum mail_attribute_type type;
	const char *key;
	struct mail_attribute_value value;
	int ret;

	while ((ret = i_stream_read_data(ctx->input, &data, &size, 0)) > 0)
		i_stream_skip(ctx->input, size);
	if (ctx->input->v_offset == ctx->entry_value_len) {
		/* finished reading the value */
		i_stream_seek(ctx->input, 0);

		if (ctx->failed) {
			i_stream_unref(&ctx->input);
			return 1;
		}

		imap_metadata_entry2key(ctx->entry_name, ctx->key_prefix,
					&type, &key);
		memset(&value, 0, sizeof(value));
		value.value_stream = ctx->input;
		if (mailbox_attribute_set(ctx->trans, type, key, &value) < 0) {
			/* delay reporting the failure so we'll finish
			   reading the command input */
			ctx->storage_failure = TRUE;
			ctx->failed = TRUE;
		}
		i_stream_unref(&ctx->input);
		return 1;
	}
	if (ctx->input->eof) {
		/* client disconnected */
		return -1;
	}
	return 0;
}

static int
cmd_setmetadata_entry(struct imap_setmetadata_context *ctx,
		      const char *entry_name,
		      const struct imap_arg *entry_value)
{
	struct istream *inputs[2];
	enum mail_attribute_type type;
	const char *key;
	struct mail_attribute_value value;
	string_t *path;
	int ret;

	switch (entry_value->type) {
	case IMAP_ARG_NIL:
	case IMAP_ARG_ATOM:
	case IMAP_ARG_STRING:
		/* we have the value already */
		imap_metadata_entry2key(entry_name, ctx->key_prefix,
					&type, &key);
		if (ctx->failed)
			return 1;
		memset(&value, 0, sizeof(value));
		value.value = imap_arg_as_nstring(entry_value);
		ret = value.value == NULL ?
			mailbox_attribute_unset(ctx->trans, type, key) :
			mailbox_attribute_set(ctx->trans, type, key, &value);
		if (ret < 0) {
			/* delay reporting the failure so we'll finish
			   reading the command input */
			ctx->storage_failure = TRUE;
			ctx->failed = TRUE;
		}
		return 1;
	case IMAP_ARG_LITERAL_SIZE:
		o_stream_nsend(ctx->cmd->client->output, "+ OK\r\n", 6);
		o_stream_nflush(ctx->cmd->client->output);
		o_stream_uncork(ctx->cmd->client->output);
		o_stream_cork(ctx->cmd->client->output);
		/* fall through */
	case IMAP_ARG_LITERAL_SIZE_NONSYNC:
		i_free(ctx->entry_name);
		ctx->entry_name = i_strdup(entry_name);
		ctx->entry_value_len = imap_arg_as_literal_size(entry_value);

		inputs[0] = i_stream_create_limit(ctx->cmd->client->input,
						  ctx->entry_value_len);
		inputs[1] = NULL;

		path = t_str_new(128);
		mail_user_set_get_temp_prefix(path, ctx->cmd->client->user->set);
		ctx->input = i_stream_create_seekable_path(inputs,
					METADATA_MAX_INMEM_SIZE, str_c(path));
		i_stream_set_name(ctx->input, i_stream_get_name(inputs[0]));
		i_stream_unref(&inputs[0]);
		return cmd_setmetadata_entry_read_stream(ctx);
	case IMAP_ARG_LITERAL:
	case IMAP_ARG_LIST:
	case IMAP_ARG_EOL:
		break;
	}
	i_unreached();
}

static bool cmd_setmetadata_continue(struct client_command_context *cmd)
{
	struct imap_setmetadata_context *ctx = cmd->context;
	const char *entry;
	const struct imap_arg *value;
	int ret;

	if (cmd->cancel) {
		cmd_setmetadata_deinit(ctx);
		return TRUE;
	}

	if (ctx->input != NULL) {
		if ((ret = cmd_setmetadata_entry_read_stream(ctx)) == 0)
			return FALSE;
		if (ret < 0) {
			cmd_setmetadata_deinit(ctx);
			return TRUE;
		}
	}

	while ((ret = cmd_setmetadata_parse_entryvalue(ctx, &entry, &value)) > 0 &&
	       entry != NULL) {
		ret = ctx->failed ? 1 :
			cmd_setmetadata_entry(ctx, entry, value);
		imap_parser_reset(ctx->parser);
		if (ret <= 0)
			break;
	}
	if (ret == 0)
		return 0;

	if (ret < 0 || ctx->cmd_error_sent)
		/* already sent the error to client */ ;
	else if (ctx->storage_failure)
		client_send_box_error(cmd, ctx->box);
	else if (mailbox_transaction_commit(&ctx->trans) < 0)
		client_send_box_error(cmd, ctx->box);
	else
		client_send_tagline(cmd, "OK Setmetadata completed.");
	cmd_setmetadata_deinit(ctx);
	return TRUE;
}

bool cmd_setmetadata(struct client_command_context *cmd)
{
	struct imap_setmetadata_context *ctx;
	const struct imap_arg *args;
	const char *mailbox;
	struct mail_namespace *ns;
	int ret;

	ret = imap_parser_read_args(cmd->parser, 2,
				    IMAP_PARSE_FLAG_STOP_AT_LIST, &args);
	if (ret == -1) {
		client_send_command_error(cmd, NULL);
		return TRUE;
	}
	if (ret == -2)
		return FALSE;
	if (!imap_arg_get_astring(&args[0], &mailbox) ||
	    args[1].type != IMAP_ARG_LIST) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}

	if (!cmd->client->imap_metadata_enabled) {
		client_send_command_error(cmd, "METADATA disabled.");
		return TRUE;
	}

	ctx = p_new(cmd->pool, struct imap_setmetadata_context, 1);
	ctx->cmd = cmd;
	ctx->cmd->context = ctx;

	if (mailbox[0] == '\0') {
		/* server attribute */
		ctx->key_prefix = MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER;
		ns = mail_namespace_find_inbox(cmd->client->user->namespaces);
		mailbox = "INBOX";
	} else {
		ns = client_find_namespace(cmd, &mailbox);
		if (ns == NULL)
			return TRUE;
	}

	if (cmd->client->mailbox != NULL && !cmd->client->mailbox_examined &&
	    mailbox_equals(cmd->client->mailbox, ns, mailbox))
		ctx->box = cmd->client->mailbox;
	else {
		ctx->box = mailbox_alloc(ns->list, mailbox, 0);
		if (mailbox_open(ctx->box) < 0) {
			client_send_box_error(cmd, ctx->box);
			mailbox_free(&ctx->box);
			return TRUE;
		}
	}
	ctx->trans = mailbox_transaction_begin(ctx->box, 0);
	/* we support large literals, so read the values from client
	   asynchronously the same way as APPEND does. */
	cmd->client->input_lock = cmd;
	ctx->parser = imap_parser_create(cmd->client->input, cmd->client->output,
					 cmd->client->set->imap_max_line_length);
	o_stream_unset_flush_callback(cmd->client->output);

	cmd->func = cmd_setmetadata_continue;
	cmd->context = ctx;
	return cmd_setmetadata_continue(cmd);
}
