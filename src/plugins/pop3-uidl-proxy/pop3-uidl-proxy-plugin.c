/* Copyright (c) 2014 Roman Plessl, roman@plessl.info */
/* LICENSE is LGPL                                    */
/* see the included COPYING and COPYING.LGPL file     */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "istream-header-filter.h"
#include "sha1.h"
#include "mail-namespace.h"
#include "mail-search-build.h"
#include "mail-storage-private.h"
#include "pop3-uidl-proxy-plugin.h"

#define POP3_UIDL_PROXY_CONTEXT(obj) \
	MODULE_CONTEXT(obj, pop3_uidl_proxy_storage_module)

#define POP3_UIDL_PROXY_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, pop3_uidl_proxy_mail_module)

struct pop3_uidl_map {
	uint32_t pop3_seq;
	uint32_t imap_uid;

	/* UIDL */
	const char *pop3_uidl;
	/* LIST size */
	uoff_t size;
	/* sha1(TOP 0) - set only when needed */
	unsigned char hdr_sha1[SHA1_RESULTLEN];
	unsigned int hdr_sha1_set:1;
};

struct imap_msg_map {
	uint32_t uid, pop3_seq;
	uoff_t psize;
	const char *pop3_uidl;

	/* sha1(header) - set only when needed */
	unsigned char hdr_sha1[SHA1_RESULTLEN];
	unsigned int hdr_sha1_set:1;
};

struct pop3_uidl_proxy_mail_storage {
	union mail_storage_module_context module_ctx;

	const char *pop3_box_vname;
	ARRAY(struct pop3_uidl_map) pop3_uidl_map;

	unsigned int all_mailboxes:1;
	unsigned int pop3_all_hdr_sha1_set:1;
};

struct pop3_uidl_proxy_mailbox {
	union mailbox_module_context module_ctx;

	unsigned int uidl_synced:1;
	unsigned int uidl_sync_failed:1;
	unsigned int uidl_ordered:1;
};

static MODULE_CONTEXT_DEFINE_INIT(pop3_uidl_proxy_storage_module,
				  &mail_storage_module_register);

static MODULE_CONTEXT_DEFINE_INIT(pop3_uidl_proxy_mail_module,
				  &mail_module_register);

const char *pop3_uidl_proxy_plugin_version = DOVECOT_ABI_VERSION;

/* FIXME: Work in Progress */


static int pop3_uidl_proxy_get_special(struct mail *_mail, enum mail_fetch_field field, const char **value_r)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union  mail_module_context *mmail = POP3_UIDL_PROXY_MAIL_CONTEXT(mail);
	struct pop3_uidl_proxy_mailbox *mbox = POP3_UIDL_PROXY_CONTEXT(_mail->box);	

	struct pop3_uidl_map *map;
	
	char* msg = (char*)malloc(sizeof(char) * 10);
	strcpy(msg, "123456789\0");

	// i_debug("pop3_uidl_proxy_get_special");
	// i_debug("pop3_uidl_proxy_get_special field %u", field);

	if (field == MAIL_FETCH_UIDL_BACKEND ||
	    field == MAIL_FETCH_POP3_ORDER) {
		
		i_debug("pop3_uidl_proxy_get_special field %u matching", field);
		i_debug("pop3_uidl_proxy_get_special field %u value %s", field, msg);
				
		*value_r = msg;		
		return 0;

	}
	return mmail->super.get_special(_mail, field, value_r);
}

/* FIXME: BASIC FUNCTIONS */

static void pop3_uidl_proxy_mail_allocated(struct mail *_mail)
{
	struct pop3_uidl_proxy_mail_storage *mstorage =
		POP3_UIDL_PROXY_CONTEXT(_mail->box->storage);
	struct mail_private *mail = (struct mail_private *)_mail;
	struct mail_vfuncs *v = mail->vlast;
	union mail_module_context *mmail;
	struct mail_namespace *ns;

	i_debug("pop3_uidl_proxy_mail_allocated called");

	if (mstorage == NULL ||
	    (!mstorage->all_mailboxes && !_mail->box->inbox_user)) {
		/* assigns UIDLs only for INBOX */
		return;
	}

	i_debug("pop3_uidl_proxy_mail_allocated mstorage is not null");

	ns = mail_namespace_find(
		_mail->box->storage->user->namespaces,
		mstorage->pop3_box_vname);
	
	i_debug("pop3_uidl_proxy_mail_allocated ns %s", ns);

	if (ns == mailbox_get_namespace(_mail->box)) {
		/* we're accessing the pop3-migration namespace itself */
		return;
	}
	
	i_debug("pop3_uidl_proxy_mail_allocated ns ok");

	mmail = p_new(mail->pool, union mail_module_context, 1);
	mmail->super = *v;
	mail->vlast = &mmail->super;

	v->get_special = pop3_uidl_proxy_get_special;

	MODULE_CONTEXT_SET_SELF(mail, pop3_uidl_proxy_mail_module, mmail);
}

static void pop3_uidl_proxy_mailbox_allocated(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	struct pop3_uidl_proxy_mailbox *mbox;

	mbox = p_new(box->pool, struct pop3_uidl_proxy_mailbox, 1);
	mbox->module_ctx.super = *v;
	box->vlast = &mbox->module_ctx.super;

	MODULE_CONTEXT_SET(box, pop3_uidl_proxy_storage_module, mbox);
}

static void pop3_uidl_proxy_mail_storage_destroy(struct mail_storage *storage)
{
	struct pop3_uidl_proxy_mail_storage *mstorage =
		POP3_UIDL_PROXY_CONTEXT(storage);

	mstorage->module_ctx.super.destroy(storage);
}

static void pop3_uidl_proxy_mail_storage_created(struct mail_storage *storage)
{
	i_debug("pop3_uidl_proxy_mail_storage created");

	struct pop3_uidl_proxy_mail_storage *mstorage;
	struct mail_storage_vfuncs *v = storage->vlast;
	const char *pop3_box_vname;

	pop3_box_vname = mail_user_plugin_getenv(storage->user,
						 "pop3_uidl_proxy_mailbox");

	i_debug("pop3_uidl_proxy_mail_storage pop3_box_vname %s", pop3_box_vname);

	if (pop3_box_vname == NULL)
		return;

	mstorage = p_new(storage->pool, struct pop3_uidl_proxy_mail_storage, 1);
	mstorage->module_ctx.super = *v;
	storage->vlast = &mstorage->module_ctx.super;
	v->destroy = pop3_uidl_proxy_mail_storage_destroy;

	mstorage->pop3_box_vname = p_strdup(storage->pool, pop3_box_vname);
	mstorage->all_mailboxes =
		mail_user_plugin_getenv(storage->user,
					"pop3_uidl_proxy_all_mailboxes") != NULL;

	i_debug("pop3_uidl_proxy_mail_storage mstorage->all_mailboxes %s", mstorage->all_mailboxes);

	MODULE_CONTEXT_SET(storage, pop3_uidl_proxy_storage_module, mstorage);
}

/* END FIXME */


static struct mail_storage_hooks pop3_uidl_proxy_mail_storage_hooks = {
	.mail_allocated = pop3_uidl_proxy_mail_allocated,
	.mailbox_allocated = pop3_uidl_proxy_mailbox_allocated,
	.mail_storage_created = pop3_uidl_proxy_mail_storage_created
};

void pop3_uidl_proxy_plugin_init(struct module *module)
{
	i_debug("pop3 uidl plugin init started");
	mail_storage_hooks_add(module, &pop3_uidl_proxy_mail_storage_hooks);
}

void pop3_uidl_proxy_plugin_deinit(void)
{
	i_debug("pop3 uidl plugin deinit started");
	mail_storage_hooks_remove(&pop3_uidl_proxy_mail_storage_hooks);
}
