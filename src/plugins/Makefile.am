if BUILD_ZLIB_PLUGIN
ZLIB = zlib imap-zlib
endif

if BUILD_LUCENE
FTS_LUCENE = fts-lucene
endif

if BUILD_SOLR
FTS_SOLR = fts-solr
endif

SUBDIRS = \
	acl \
	imap-acl \
	autocreate \
	expire \
	fts \
	fts-squat \
	lazy-expunge \
	listescape \
	notify \
	mail-filter \
	mail-log \
	mailbox-alias \
	quota \
	imap-quota \
	pop3-migration \
	pop3-uidl-proxy \
	replication \
	snarf \
	stats \
	imap-stats \
	trash \
	virtual \
	$(ZLIB) \
	$(FTS_LUCENE) \
	$(FTS_SOLR)
