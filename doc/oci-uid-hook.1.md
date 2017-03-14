% OCI-UID-HOOK(1) oci-uid-hook
% March 2017

## NAME

oci-uid-hook - detects when an arbitrary uid is passed at container
runtime and modifies a container's /etc/passwd file (via bind mount)
so that the container's username is recognized as expected.

## SYNOPSIS

**oci-uid-hook**

## DESCRIPTION

`oci-uid-hook` is a OCI hook program. If you add it to the runc json
data as a hook, runc will execute the application after the container
process is created but before it is executed, with a `prestart` flag.

When enabled, a linux container's username will be recognized even
when using an arbitrary uid (-u, --user flags). This is especially
important in OpenShift, so that non-root / restricted scc deployments
become more seamless and the need for elevated OCP rights less common.

Uid Hook engages IF -

 - the specified 'uid' is different than the "User" defined in the image
 
 AND
 
 - the specified 'uid' is an integer

 AND

 - /etc/passwd does not already exist as a bind mount

 AND

 - the specified 'uid' does not already exist in /etc/passwd

You can disable this service by editing the /etc/oci-uid-hook.conf
file and setting the disabled field to true.

## EXAMPLES

## SEE ALSO

## HISTORY
March 2017, updated by Tommy Hughes <tohughes@redhat.com>