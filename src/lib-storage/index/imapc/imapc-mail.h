#ifndef IMAPC_MAIL_H
#define IMAPC_MAIL_H

#include "index-mail.h"

struct imap_arg;
struct imapc_untagged_reply;
struct imapc_mailbox;

struct imapc_mail {
	struct index_mail imail;

	enum mail_fetch_field fetching_fields;
	const char *const *fetching_headers;
	unsigned int fetch_count;

	int fd;
	buffer_t *body;
	bool body_fetched;
	bool header_list_fetched;
};

extern struct mail_vfuncs imapc_mail_vfuncs;

struct mail *
imapc_mail_alloc(struct mailbox_transaction_context *t,
		 enum mail_fetch_field wanted_fields,
		 struct mailbox_header_lookup_ctx *wanted_headers);
int imapc_mail_fetch(struct mail *mail, enum mail_fetch_field fields,
		     const char *const *headers);
bool imapc_mail_prefetch(struct mail *mail);
void imapc_mail_fetch_flush(struct imapc_mailbox *mbox);
void imapc_mail_init_stream(struct imapc_mail *mail, bool have_body);

void imapc_mail_fetch_update(struct imapc_mail *mail,
			     const struct imapc_untagged_reply *reply,
			     const struct imap_arg *args);
void imapc_mail_update_access_parts(struct index_mail *mail);
void imapc_mail_command_flush(struct imapc_mailbox *mbox);

#endif
