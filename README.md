# aloha: Alternative Library for Oblivious HTTP Applications

Aloha is a low-level Oblivious HTTP parsing/building library that
focus on performance. The crypto functionality is built on top of
[hpke] crate, while the bHTTP implementation leverages a chained
operation to avoid heap allocations.

Please see the crate documentation for details and examples.

[hpke]: https://github.com/rozbb/rust-hpke
