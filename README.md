# Qudini Security Primitives

Building blocks for security-oriented features.

Currently includes:

* Constant-time operations that help avoid timing attacks.
* Shredding of data, that zeros out and then uses a CSPRNG to fill space. (Works at the JVM level; no OS-level
  guarantees of proper data shredding is guaranteed.)
* A char sequences that pledges not to copy the underlying characters. Suitable for sequencing underlying char arrays to
  be shredded.
  
It also contains a passphrase class that:

* Uses constant-time operations for equality checking.
* Uses scrypt provided by [github.com/wg/scrypt](https://github.com/wg/scrypt) for hashing.
* Shreds unlying chars when done, with try-with-resources.
* Has factory methods that disallow user aliases in the passphrase, or require confirmations.