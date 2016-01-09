// Copyright (c) 2014-2016 Sandstorm Development Group, Inc.
// Licensed under the MIT License:
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

use gj::{Promise, EventLoop};
use gj::io::unix;
use capnp::Error;
use capnp_rpc::{RpcSystem, twoparty, rpc_twoparty_capnp};

use grain_capnp::{ui_view, ui_session};
use web_session_capnp::{web_session};

#[derive(Clone, Copy)]
pub struct UiView;

impl ui_view::Server for UiView {

}

pub struct WebSession {
    can_write: bool,
}

impl WebSession {
    pub fn new() -> WebSession {
        WebSession {
            can_write: true,
        }
    }
}

impl ui_session::Server for WebSession {}

impl web_session::Server for WebSession {
    fn get(&mut self,
           params: web_session::GetParams,
           mut results: web_session::GetResults)
	-> Promise<(), Error>
    {
	// HTTP GET request.
        let path = pry!(pry!(params.get()).get_path());
        //requireCanonicalPath(path);

        if path == "var" || path == "var/" {
            // Return a listing of the directory contents, one per line.
/*
            auto text = kj::strArray(listDirectory("var"), "\n");
            auto response = context.getResults().initContent();
            response.setMimeType("text/plain");
            response.getBody().setBytes(
                kj::arrayPtr(reinterpret_cast<byte*>(text.begin()), text.size()));*/
            Promise::ok(())
        } else if path.starts_with("var/") {
            // Serve all files under /var with type application/octet-stream since it comes from the
            // user. E.g. serving as "text/html" here would allow someone to trivially XSS other users
            // of the grain by PUTing malicious HTML content. (Such an attack wouldn't be a huge deal:
            // it would only allow the attacker to hijack another user's access to this grain, not to
            // Sandstorm in general, and if they attacker already has write access to upload the
            // malicious content, they have little to gain from hijacking another session.)
            //return readFile(path, context, "application/octet-stream");
            Promise::ok(())
        } else if path == ".can-write" {
            // Fetch "/.can-write" to determine if the user has write permission, so you can show them
            // a different UI if not.
/*            auto response = context.getResults().initContent();
            response.setMimeType("text/plain");
            response.getBody().setBytes(kj::str(canWrite).asBytes());*/
            Promise::ok(())
        } else if path == "" || path.ends_with("/") {
            // A directory. Serve "index.html".
            self.read_file(&format!("client/{}index.html", path), results, "text/html; charset=UTF-8")
        } else {
/*
            // Request for a static file. Look for it under "client/".
            auto filename = kj::str("client/", path);

            // Check if it's a directory.
            if (isDirectory(filename)) {
                // It is. Return redirect to add '/'.
                auto redirect = context.getResults().initRedirect();
                redirect.setIsPermanent(true);
                redirect.setSwitchToGet(true);
                redirect.setLocation(kj::str(path, '/'));
                return kj::READY_NOW;
            }

            // Regular file (or non-existent).
            return readFile(kj::mv(filename), context, inferContentType(path));*/
            Promise::ok(())
        }
    }
}

impl WebSession {
    fn read_file(&self,
                 filename: &str,
                 mut results: web_session::GetResults,
                 content_type: &str)
                 -> Promise<(), Error>
    {
        match ::std::fs::File::open(filename) {
            Ok(mut f) => {
                let size = pry!(f.metadata()).len();
                let mut content = results.get().init_content();
                content.set_status_code(web_session::response::SuccessCode::Ok);
                content.set_mime_type(content_type);
                let mut body = content.init_body().init_bytes(size as u32);
                pry!(::std::io::copy(&mut f, &mut body));
                Promise::ok(())
            }
            Err(ref e) if e.kind() == ::std::io::ErrorKind::NotFound => {
                let mut error = results.get().init_client_error();
                error.set_status_code(web_session::response::ClientErrorCode::NotFound);
                Promise::ok(())
            }
            Err(e) => {
                Promise::err(e.into())
            }
        }
    }
}

pub fn main() -> ::capnp::Result<()> {
    EventLoop::top_level(move |wait_scope| {
        // sandstorm launches us with a connection on file descriptor 3
	let stream = try!(unsafe { unix::Stream::from_raw_fd(3) });
        let (reader, writer) = stream.split();

        let client = ui_view::ToClient::new(UiView).from_server::<::capnp_rpc::Server>();
        let network =
            twoparty::VatNetwork::new(reader, writer,
                                      rpc_twoparty_capnp::Side::Client, Default::default());

	let _rpc_system = RpcSystem::new(Box::new(network), Some(client.client));
        Promise::never_done().wait(wait_scope)
    }).expect("top level error");
    Ok(())
}