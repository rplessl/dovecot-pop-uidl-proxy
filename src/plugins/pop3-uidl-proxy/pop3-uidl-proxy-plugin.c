/* Copyright (c) 2014 Roman Plessl, roman@plessl.info */
/* LICENSE is LGPL                                    */
/* see the included COPYING and COPYING.LGPL file     */

#include <sqlite3.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "istream-header-filter.h"
#include "sha1.h"
#include "str.h"
#include "mail-namespace.h"
#include "mail-search-build.h"
#include "mail-storage-private.h"
// CLEANUP: not used at the moment
// #include "mail-user.h"

#include "pop3-uidl-proxy-plugin.h"

#define POP3_UIDL_PROXY_CONTEXT(obj) \
	MODULE_CONTEXT(obj, pop3_uidl_proxy_storage_module)

#define POP3_UIDL_PROXY_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, pop3_uidl_proxy_mail_module)

// CLEANUP: not used at the moment
// #define POP3_UIDL_PROXY_USER_CONTEXT(obj) \
//         MODULE_CONTEXT(obj, mail_uidl_proxy_user_module)


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
// CLEANUP: not used at the moment
// static MODULE_CONTEXT_DEFINE_INIT(pop3_uidl_proxy_user_module,
//					&mail_user_module_register);


const char *pop3_uidl_proxy_plugin_version = DOVECOT_ABI_VERSION;

/* FIXME: Work in Progress */

// static void
// sql_where_build(string_t *query)
// {
//         const char *const *sql_fields, *const *values;
//         unsigned int i, count, count2, exact_count;
                
//         str_append(query, " WHERE ");
//         str_append(query, "user = 'rplessl' ");
//         str_append(query, "AND ");
//         // str_printfa(query, " cuidl = '%s'", sql_escape_string(dict->db, values[i]));        
// }

static int pop3_map_read(struct mail_storage *storage, struct mailbox *pop3_box)
{
	struct pop3_uidl_proxy_mail_storage *mstorage =
		POP3_UIDL_PROXY_CONTEXT(storage);
	struct mailbox_transaction_context *t;
	struct mail_search_args *search_args;
	struct mail_search_context *ctx;
	struct mail *mail;
	struct pop3_uidl_map *map;
	const char *uidl;
	uoff_t size;
	int ret = 0;

	i_debug ("pop3_map_read start reached!");

	i_array_init(&mstorage->pop3_uidl_map, 128);

	if (mailbox_sync(pop3_box, 0) < 0) {
		i_error("pop3_uidl_proxy: Couldn't sync mailbox %s: %s",
			pop3_box->vname, mailbox_get_last_error(pop3_box, NULL));
		return -1;
	}

	t = mailbox_transaction_begin(pop3_box, 0);
	search_args = mail_search_build_init();
	mail_search_build_add_all(search_args);
	ctx = mailbox_search_init(t, search_args, NULL, MAIL_FETCH_VIRTUAL_SIZE, NULL);
	mail_search_args_unref(&search_args);

	while (mailbox_search_next(ctx, &mail)) {
		if (mail_get_virtual_size(mail, &size) < 0) {
			i_error("pop3_uidl_proxy: Failed to get size for msg %u: %s",
				mail->seq,
				mailbox_get_last_error(pop3_box, NULL));
			ret = -1;
			break;
		}
		if (mail_get_special(mail, MAIL_FETCH_UIDL_BACKEND, &uidl) < 0) {
			i_error("pop3_uidl_proxy: Failed to get UIDL for msg %u: %s",
				mail->seq,
				mailbox_get_last_error(pop3_box, NULL));
			ret = -1;
			break;
		}
		if (*uidl == '\0') {
			i_warning("pop3_uidl_proxy: UIDL for msg %u is empty",
				mail->seq);
			continue;
		}

		i_debug("pop3_uidl_proxy - pop3_map_read - UIDL = %s", uidl);

		map = array_append_space(&mstorage->pop3_uidl_map);
		map->pop3_seq = mail->seq;
		map->pop3_uidl = p_strdup(storage->pool, uidl);
		map->size = size;
	}

	if (mailbox_search_deinit(&ctx) < 0)
		ret = -1;
	(void)mailbox_transaction_commit(&t);
	return ret;
}


static struct mailbox *pop3_mailbox_alloc(struct mail_storage *storage)
{
	struct pop3_uidl_proxy_mail_storage *mstorage =
		POP3_UIDL_PROXY_CONTEXT(storage);
	struct mail_namespace *ns;

	ns = mail_namespace_find(storage->user->namespaces,
				 mstorage->pop3_box_vname);
	i_assert(ns != NULL);
	return mailbox_alloc(ns->list, 
				mstorage->pop3_box_vname,
			    MAILBOX_FLAG_READONLY | MAILBOX_FLAG_POP3_SESSION);
}

static int pop3_uidl_proxy_uidl_sync(struct mailbox *box)
{
	struct pop3_uidl_proxy_mailbox *mbox = 
		POP3_UIDL_PROXY_CONTEXT(box);
	struct pop3_uidl_proxy_mail_storage *mstorage =
		POP3_UIDL_PROXY_CONTEXT(box->storage);
	struct mailbox *pop3_box;
	const struct pop3_uidl_map *pop3_map;
	unsigned int i, count;
	uint32_t prev_uid;

	// if (mbox->uidl_synced)
	// 	return 0;

	pop3_box = pop3_mailbox_alloc(box->storage);
	/* the POP3 server isn't connected to yet. handle all IMAP traffic
	   first before connecting, so POP3 server won't disconnect us due to
	   idling. */
	if (pop3_map_read(box->storage, pop3_box) < 0) {
		mailbox_free(&pop3_box);
		return -1;
	}
	

	// /* see if the POP3 UIDL order is the same as IMAP UID order */
	mbox->uidl_ordered = TRUE;
	pop3_map = array_get(&mstorage->pop3_uidl_map, &count);
	prev_uid = 0;
	for (i = 0; i < count; i++) {
	 	if (pop3_map[i].imap_uid == 0)
	 		continue;

	 	if (prev_uid > pop3_map[i].imap_uid) {
	 		mbox->uidl_ordered = FALSE;
	 		break;
	 	}
	 	prev_uid = pop3_map[i].imap_uid;
	}

	mbox->uidl_synced = TRUE;
	mailbox_free(&pop3_box);
	return 0;
}


static int pop3_uidl_proxy_get_special(struct mail *_mail, enum mail_fetch_field field, const char **value_r)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union  mail_module_context *mmail = 
		POP3_UIDL_PROXY_MAIL_CONTEXT(mail);
	struct pop3_uidl_proxy_mailbox *mbox = 
		POP3_UIDL_PROXY_CONTEXT(_mail->box);	
	struct pop3_uidl_proxy_mail_storage *mstorage =
		POP3_UIDL_PROXY_CONTEXT(_mail->box->storage);

	struct pop3_uidl_map *pop3_map;	
	unsigned int i, count;
	const char *username; 

	/* sqlite handling */
	sqlite3 		*conn;
	sqlite3_stmt    *res;
	int     		error = 0;
	int     		rec_count = 0;
	const char      *errMSG;
	const char      *tail;
	const char      *dbfilename;
	const char		*dbpath;

	/* fetch POP3 username from enviroment - set by pop3c */
	username = getenv("POP3C_USERNAME");
	i_debug("pop3c_username taken from environment %s", username);

	/* open and handle sqlite database for user */
	// FIXME:
	// dbpath = mail_user_plugin_getenv(mbox,
	//					 "pop3_uidl_proxy_databases_path");
	dbpath = "/tmp/abc";
	if (dbpath == NULL)
		return -1;		
	
	// FIXME
	// sprintf(dbfilename, "%s/%s", dbpath, username);
	string_t *tdbfilename = t_str_new(256);
	str_append(tdbfilename, "/home/rplessl/opt/dovecot-2.2-build/var/lib/dovecot/uidl-proxy-databases");
	str_append(tdbfilename, "/");
	str_printfa(tdbfilename, "%s", username);
	str_append(tdbfilename, ".db");
	
	error = sqlite3_open(str_c(tdbfilename), &conn);
	if (error) {
		i_debug("Can not open database: %s", str_c(tdbfilename));
	} 
	else {
		i_debug("open database: %s", str_c(tdbfilename));
	}

	// CLEANUP: 
	// 		not used at the moment
	// error = sqlite3_exec(conn,
	// 	"UPDATE mapping SET zuidl=\'5055559999\' WHERE uidl_seq=3", 0, 0, 0);

	error = sqlite3_prepare_v2(conn,
		"SELECT uidl_seq,username,cuidl,zuidl FROM mapping ORDER BY uidl_seq",
		1000, &res, &tail);

	if (error != SQLITE_OK) {
		i_debug("We did not get any data from the SQLite DB!");
		sqlite3_finalize(res);
		sqlite3_close(conn);
	}

	/* Test Debug Output of the SQLite DB */
	while (sqlite3_step(res) == SQLITE_ROW) {
    	i_debug("%u",  sqlite3_column_int( res, 0));
		i_debug("%s",  sqlite3_column_text(res, 1));
		i_debug("%s",  sqlite3_column_text(res, 2));
		i_debug("%s",  sqlite3_column_text(res, 3));    	
		rec_count++;
	}
	i_debug("We received %d records in the mapping table", rec_count);


	// CLEANUP:
	// 		Lightly cleanup code here

	char* msg = (char*)malloc(sizeof(char) * 30);
	strcpy(msg, "123456789\0");

    if (field == MAIL_FETCH_UIDL_BACKEND ||
    	field == MAIL_FETCH_POP3_ORDER) {

    	pop3_uidl_proxy_uidl_sync(_mail->box);
	    pop3_map = array_get(&mstorage->pop3_uidl_map, &count);

	    // CLEANUP: 
	    //		Print pop3 map
	   	i_debug("count %u", count);
		for (i = 0; i < count; i++) {			   	
			i_debug("%u: pop3_map[%u].pop3_uidl: %s", i, i, pop3_map[i].pop3_uidl);
		}	
	    
	    for (i = 0; i < count; i++) {
			string_t *query = t_str_new(256);
			str_append(query, "SELECT cuidl FROM mapping ");                    
			str_append(query, "WHERE ");
			str_printfa(query, "zuidl = '%s'", pop3_map[i].pop3_uidl);   

			error = sqlite3_prepare_v2(conn, str_c(query), 1000, &res, &tail);

	    	// WORKING
	    	// error = sqlite3_prepare_v2(conn,
	    	// 	"SELECT cuidl FROM mapping WHERE zuidl = '262.AdilAtzDMypFIP1Snde,Q2u1aMkA2yjjZVCstCY5Fbc='", 1000, &res, &tail);

	 		// i_debug("pop3_uidl: %s", pop3_map[i].pop3_uidl);
 			
 			// sprintf(sqlquery, "SELECT cuidl FROM mapping WHERE zuidl = '%s'\0", );

			
			// error = sqlite3_prepare_v2(conn,
			//	sqlquery, 1000, &res, &tail);


	    	if (error != SQLITE_OK) {
	    		i_debug("We did not get any data!");
	    		// sqlite3_finalize(res);
	    		// sqlite3_close(conn);
	    	}

	    	while (sqlite3_step(res) == SQLITE_ROW) {
	    		i_debug("SQLite DB has a mapping");   			    			
	    		i_debug("%s", sqlite3_column_text(res, 0));   			    			
				strcpy(msg, (char*) sqlite3_column_text(res, 0));
	    		i_debug("pop3_uidl_proxy_get_special field %u value %s", field, msg);	    		
	    	}		
	    }	

	    i_debug("pop3_uidl_proxy_get_special field %u value %s", field, msg);

	    *value_r = msg;		
	    return 0;

	}

	sqlite3_finalize(res);
	sqlite3_close(conn);

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

	i_debug("pop3_uidl_proxy_mail_allocated mstorage is not NULL");

	ns = mail_namespace_find(
		_mail->box->storage->user->namespaces,
		mstorage->pop3_box_vname);
	
	i_debug("pop3_uidl_proxy_mail_allocated ns %s", ns);

	if (ns == mailbox_get_namespace(_mail->box)) {
		/* we're accessing the pop3-uidl-proxy namespace itself */
		return;
	}
	
	i_debug("pop3_uidl_proxy_mail_allocated ns OK");

	mmail = p_new(mail->pool, union mail_module_context, 1);
	mmail->super = *v;
	mail->vlast = &mmail->super;

	v->get_special = pop3_uidl_proxy_get_special;

	MODULE_CONTEXT_SET_SELF(mail, pop3_uidl_proxy_mail_module, mmail);
}

/* FIXME: Check done */

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

	if (array_is_created(&mstorage->pop3_uidl_map))
		array_free(&mstorage->pop3_uidl_map);

	mstorage->module_ctx.super.destroy(storage);
}

static void pop3_uidl_proxy_mail_storage_created(struct mail_storage *storage)
{
	struct pop3_uidl_proxy_mail_storage *mstorage;
	struct mail_storage_vfuncs *v = storage->vlast;
	const char *pop3_box_vname;

	i_debug("pop3_uidl_proxy_mail_storage created");

	pop3_box_vname = mail_user_plugin_getenv(storage->user,
						 "pop3_uidl_proxy_mailbox");
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

	i_debug("pop3_uidl_proxy_mail_storage mstorage->pop3_box_vname: %s", mstorage->pop3_box_vname);
	i_debug("pop3_uidl_proxy_mail_storage mstorage->all_mailboxes: %i",  mstorage->all_mailboxes);


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
