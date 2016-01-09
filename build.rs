extern crate capnpc;

fn main() {
    ::capnpc::compile("schema",
                      &["schema/grain.capnp", "schema/util.capnp",
			"schema/web-session.capnp"]).unwrap();
}

