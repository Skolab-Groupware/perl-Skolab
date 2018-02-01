AC_PREREQ(2.59)

m4_define(_VERSION,5.8.7)
AC_INIT([perl-kolab],[_VERSION],[kolab-devel@kolab.org])
AC_CONFIG_AUX_DIR(.)

AM_INIT_AUTOMAKE([gnu] [1.7] [dist-bzip2] [no-dist-gzip])
AC_PREFIX_DEFAULT([/usr])

common=dist_conf/common
AC_SUBST_FILE(common)

AC_ARG_WITH([dist],
  [AC_HELP_STRING([--with-dist=DIST],
     [distribution target (default: openpkg)])],
     [distribution=$srcdir/dist_conf/$withval],
   [distribution=$srcdir/dist_conf/kolab])

AS_IF([test -f $distribution],,
	AC_MSG_ERROR([incorrect value for --with-dist: $withval])
)
AC_SUBST_FILE(distribution)

AC_ARG_WITH([perllib],
  [AC_HELP_STRING([--with-perllib=PERLLIB],
     [perl library path])],
     [perllib=$withval],
   [perllib=`eval $(perl '-V:installvendorlib'); echo $installvendorlib`])
AC_SUBST(perllib)

# Checks for libraries.

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

# Build date for spec file
spec_build_date=`date '+%Y%m%d'`
AC_SUBST(spec_build_date)

AC_CONFIG_FILES([
Makefile
perl-kolab.spec
])

AC_OUTPUT

