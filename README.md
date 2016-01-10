# Sandstorm Raw API Example App In Rust

This is an example [Sandstorm](https://sandstorm.io) application which uses the raw [Cap'n
Proto](https://capnproto.org)-based Sandstorm API to serve a web UI without an HTTP server.
The [original version](https://github.com/sandstorm-io/sandstorm-rawapi-example)
was written in C++.

# Running

Install [Rust](https://www.rust-lang.org/), [Cap'n Proto](https://capnproto.org/install.html),
and [Sandstorm](https://sandstorm.io/install). Then do:

```
$ cargo build --release
$ spk dev
```

