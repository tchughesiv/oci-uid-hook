# oci-uid-hook
[![Go Report Card](https://goreportcard.com/badge/github.com/tchughesiv/oci-uid-hook)](https://goreportcard.com/badge/github.com/tchughesiv/oci-uid-hook)

### Status: pre-alpha

**WIP - not quite ready**

When enabled, a linux container's username will be recognized even when using an arbitrary uid (-u, --user flags). This is especially important in OpenShift, so that non-root / restricted scc deployments become more seamless and the need for elevated OCP rights less common.
Hook detects when an arbitrary uid is passed at container runtime and modifies a container's /etc/passwd file (via bind mount) so that username and group permissions continue to function as expected.

### Hook engages IF -
 - passed 'uid' is different than User defined in the image
 
 AND
 
 - said 'uid' is an integer

 AND

 - said 'uid' does not match an existing username in /etc/passwd

### Tested w/ -
```json
"runc version": 1.0.0-rc2
"ociVersion": 0.1.0
"docker Version": 1.12.5
"docker API version": 1.24
"go version": go1.7.5
```