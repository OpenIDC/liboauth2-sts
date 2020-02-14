AC_INIT([liboauth2-sts],[0.0.0],[hans.zandbelt@zmartzone.eu])

AM_INIT_AUTOMAKE([foreign no-define subdir-objects])
AC_CONFIG_MACRO_DIRS([m4])

LT_INIT([dlopen])
AC_PROG_CC

AX_CODE_COVERAGE


PKG_CHECK_MODULES(XML, libxml-2.0 >= 2.4)
AC_SUBST(XML_CFLAGS)
AC_SUBST(XML_LIBS)

PKG_CHECK_MODULES(OAUTH2, liboauth2 >= 1.2.4)
AC_SUBST(OAUTH2_CFLAGS)
AC_SUBST(OAUTH2_LIBS)


PKG_CHECK_MODULES([CHECK],
        [check >= 0.9.4],
        [have_check="yes"],
        [   AC_MSG_WARN([Check not found; cannot run unit tests!]);
            [have_check="no"]
        ])
AM_CONDITIONAL(HAVE_CHECK, test x"$have_check" = "xyes")
AC_SUBST(CHECK_CFLAGS)
AC_SUBST(CHECK_LIBS)


# Create Makefile from Makefile.in
AC_CONFIG_FILES([
	Makefile
])
AC_OUTPUT
