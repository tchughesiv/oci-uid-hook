AC_INIT([OCI Uid Hook], 0.0.1)
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign -Wall -Werror subdir-objects])
AC_PROG_CC
AM_PROG_CC_C_O
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

PKG_CHECK_MODULES([YAJL], [yajl >= 2.0.0])
PKG_CHECK_MODULES([LIBMOUNT], [mount >= 2.23.0])

have_selinux=no
AC_ARG_ENABLE(selinux, AS_HELP_STRING([--disable-selinux], [disable optional SELINUX support]))
if test "x$enable_selinux" != "xno"; then
        PKG_CHECK_MODULES([SELINUX], [libselinux >= 2.0.0],
                [AC_DEFINE(HAVE_SELINUX, 1, [Define if SELinux is available])
                 have_selinux=yes
                 M4_DEFINES="$M4_DEFINES -DHAVE_SELINUX"],
                [have_selinux=no])
        if test "x$have_selinux" = xno -a "x$enable_selinux" = xyes; then
                AC_MSG_ERROR([*** SELinux support requested but libraries not found])
        fi
fi
AM_CONDITIONAL(HAVE_SELINUX, [test "$have_selinux" = "yes"])
AC_MSG_CHECKING([whether to disable argument checking])
AS_IF([test "x$enable_args" != "xno"], [AC_DEFINE([ARGS_CHECK], [1], [enable checking arguments])])

AC_CONFIG_FILES(Makefile)
AC_OUTPUT