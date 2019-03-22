ACLOCAL_AMFLAGS=-I m4

EXTRA_DIST = autogen.sh ChangeLog README.md LICENSE DISCLAIMER


AM_CPPFLAGS = -g -Wall -Werror -Iinclude -Isrc
AM_CPPFLAGS += @OAUTH2_CFLAGS@ @XML_CFLAGS@
AM_CPPFLAGS += $(CODE_COVERAGE_CPPFLAGS) $(CODE_COVERAGE_CFLAGS)

AM_LDFLAGS = --coverage

LIBS += @OAUTH2_LIBS@ @XML_LIBS@
LIBS += $(CODE_COVERAGE_LIBS)

lib_LTLIBRARIES = liboauth2_sts.la

liboauth2_sts_la_SOURCES = \
	src/sts.c \
	src/wstrust.c \
	src/ropc.c \
	src/otx.c

if HAVE_CHECK

TESTS = check_liboauth2_sts
check_PROGRAMS = $(TESTS)

check_liboauth2_sts_SOURCES = \
	test/check_liboauth2_sts.c

check_liboauth2_sts_CFLAGS = $(AM_CFLAGS) @CHECK_CFLAGS@
check_liboauth2_sts_LDADD = @CHECK_LIBS@

endif


@CODE_COVERAGE_RULES@


clang-format:
	clang-format -style=file -i `find . -name *.[ch]`
