AM_CPPFLAGS = -g -Wall -Werror -Wno-macro-redefined -I$(top_builddir)/include
AM_CPPFLAGS += -DNAMEVER="@NAMEVER@" @XML_CFLAGS@ @OAUTH2_CFLAGS@
AM_CPPFLAGS += $(CODE_COVERAGE_CPPFLAGS)

lib_LTLIBRARIES = liboauth2_sts.la

liboauth2_sts_la_SOURCES = \
	sts.c \
	wstrust.c \
	ropc.c \
	cc.c \
	otx.c

liboauth2_sts_la_LIBADD =  @XML_LIBS@ @OAUTH2_LIBS@ $(CODE_COVERAGE_LIBS)

@CODE_COVERAGE_RULES@
