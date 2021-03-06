# OCI Uid Hook

### Status: pre-alpha

**WIP - not quite ready**

When enabled, a linux container's username will be recognized even when using an arbitrary uid (-u, --user flags). This is especially important in OpenShift, so that non-root / restricted scc deployments become more seamless and the need for elevated OCP rights less common.

The hook detects when an arbitrary uid is passed at container runtime and modifies a container's /etc/passwd file (via bind mount) so that username is recognized as expected.

### Hook engages IF -

 - the specified 'uid' is different than the "User" defined in the image
 
 AND
 
 - the specified 'uid' is an integer

 AND

 - /etc/passwd does not already exist as a bind mount

 AND

 - the specified 'uid' does not already exist in /etc/passwd
 
### Tested w/ the following on RHEL7.3 -

```json
"docker Version": 1.12.5
"runc version": 1.0.0-rc2
```

To build, install, clean-up:

### 
```shell
autoreconf -i
./configure --libexecdir=/usr/libexec/oci/hooks.d
make
make install
```
