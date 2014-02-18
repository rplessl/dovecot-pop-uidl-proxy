AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	$(SQL_CFLAGS)

AM_LDFLAGS = \
	$(SQL_LIBS)

NOPLUGIN_LDFLAGS = 
lib05_pop3_uidl_proxy_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib05_pop3_uidl_proxy_plugin.la

lib05_pop3_uidl_proxy_plugin_la_SOURCES = \
	pop3-uidl-proxy-plugin.c

noinst_HEADERS = \
	pop3-uidl-proxy-plugin.h
