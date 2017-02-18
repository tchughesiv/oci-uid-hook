libexec_PROGRAMS = oci-uid-hook
oci_uid_hook_SOURCES= src/uidhook.c
## need curl 7.40 or greater for this to work
#oci_uid_hook_SOURCES= src/uidhook.c src/docker.c

oci_uid_hook_CFLAGS = -Wall -Wextra -std=c99 $(YAJL_CFLAGS)
oci_uid_hook_LDADD = $(YAJL_LIBS)
oci_uid_hook_CFLAGS += $(SELINUX_CFLAGS)
oci_uid_hook_LDADD += $(SELINUX_LIBS)
oci_uid_hook_CFLAGS += $(LIBMOUNT_CFLAGS)
oci_uid_hook_LDADD += $(LIBMOUNT_LIBS)
oci_uid_hook_CFLAGS += $(LIBCURL_CFLAGS)
oci_uid_hook_LDADD += $(LIBCURL_LIBS)

dist_man_MANS = oci-uid-hook.1
EXTRA_DIST = README.md LICENSE

oci-uid-hook.1: doc/oci-uid-hook.1.md
	go-md2man -in doc/oci-uid-hook.1.md -out oci-uid-hook.1

dist: oci-uid-hook.spec 
	spectool -g oci-uid-hook.spec

rpm: dist
	rpmbuild --define "_sourcedir `pwd`" --define "_specdir `pwd`" \
	--define "_rpmdir `pwd`" --define "_srcrpmdir `pwd`" -ba oci-uid-hook.spec 

clean-local:
	-rm -f oci-uid-hook.1 *~
	-rm -f oci-uid-hook-*.tar.gz
	-rm -f oci-uid-hook-*.rpm