% OCI-UID-HOOK(1) oci-uid-hook
% February 2017

## NAME

oci-uid-hook - 

## SYNOPSIS

**oci-uid-hook**

## DESCRIPTION

`oci-uid-hook` is a OCI hook program. If you add it to the runc json data
as a hook, runc will execute the application after the container process is created but before it is executed, with a `prestart` flag.

You can disable this service by editing the /etc/oci-uid-hook.conf
file and setting the disabled field to true.

## EXAMPLES

## SEE ALSO

docker-run(1)

## HISTORY
February 2017, updated by Tommy Hughes <tohughes@redhat.com>