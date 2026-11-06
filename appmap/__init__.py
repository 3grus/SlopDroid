"""appmap -- Stage 1: bridge SELinux reachability to exported-component attack surface.

Consumes the JSON report from `analyze.py reach` and, for the APKs in an unpacked tree
(or a directory searched recursively), enumerates exported components and the two attacker
channels from the source domain:

  * IPC channel  -- exported activity/service/receiver/provider an outside caller can invoke,
                    tagged by whether the hosting app runs in a reachable SELinux domain.
  * File channel -- components whose code references a path the source domain can WRITE
                    (per the reachability report), i.e. a shared-file ingestion point.

Manifest parsing (manifest.py) is pure and testable; the androguard loader is thin glue.
"""
