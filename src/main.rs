#[macro_use]
extern crate gj;
extern crate capnp;
extern crate capnp_rpc;

pub mod grain_capnp {
  include!(concat!(env!("OUT_DIR"), "/grain_capnp.rs"));
}

pub mod util_capnp {
  include!(concat!(env!("OUT_DIR"), "/util_capnp.rs"));
}

pub mod web_session_capnp {
  include!(concat!(env!("OUT_DIR"), "/web_session_capnp.rs"));
}

fn main() {

}
