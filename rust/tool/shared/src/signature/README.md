# Signatures capabilities of Lanzaboote

Currently, lanzaboote can perform signatures of PE binaries based on local keypairs present on disk.

## Local keypairs

Storing your signature keys in the disk in some location we can read is the most trivial signature capability
we can offer.

You are responsible for securing them and ensuring they are not accessible by an attacker.

Signature happens via `sbsign` which will copy your input inside a temporary directory, sign it, read it and offers it to you again.

In the future, we may remove `sbsign` dependency to perform signature in-memory without any temporary directory.
