/* Copyright (c) 2014 Roman Plessl, roman@plessl.info
   LICENSE is LGPL 
   see the included COPYING and COPYING.LGPL file */
#include "lib.h"
#include "pop3-uidl-proxy-plugin.h"

const char *pop3_uidl_proxy_plugin_version = DOVECOT_ABI_VERSION;

static struct mail_storage_hooks pop3_uidl_proxy_mail_storage_hooks = {
	.mail_allocated = pop3_uidl_proxy_mail_allocated,
	.mailbox_allocated = pop3_uidl_proxy_mailbox_allocated,
	.mail_storage_created = pop3_uidl_proxy_mail_storage_created
};

void pop3_uidl_proxy_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &pop3_uidl_proxy_mail_storage_hooks);
}

void pop3_uidl_proxy_plugin_deinit(void)
{
	mail_storage_hooks_remove(&pop3_uidl_proxy_mail_storage_hooks);
}
