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
use capnp::Error;
use capnp_rpc::{RpcSystem, twoparty, rpc_twoparty_capnp};

use grain_capnp::{session_context, user_info, ui_view, ui_session};
use web_session_capnp::{web_session};

pub struct WebSession {
    can_write: bool,
}

impl WebSession {
    pub fn new(user_info: user_info::Reader,
               _context: session_context::Client,
               _params: web_session::params::Reader)
               -> ::capnp::Result<WebSession>
    {
        // Permission #0 is "write". Check if bit 0 in the PermissionSet is set.
        let permissions = try!(user_info.get_permissions());
        let can_write = permissions.len() > 0 && permissions.get(0);

        Ok(WebSession {
            can_write: can_write,
        })

        // `UserInfo` is defined in `sandstorm/grain.capnp` and contains info like:
        // - A stable ID for the user, so you can correlate sessions from the same user.
        // - The user's display name, e.g. "Mark Miller", useful for identifying the user to other
        //   users.
        // - The user's permissions (seen above).

        // `WebSession::Params` is defined in `sandstorm/web-session.capnp` and contains info like:
        // - The hostname where the grain was mapped for this user. Every time a user opens a grain,
        //   it is mapped at a new random hostname for security reasons.
        // - The user's User-Agent and Accept-Languages headers.

        // `SessionContext` is defined in `sandstorm/grain.capnp` and implements callbacks for
        // sharing/access control and service publishing/discovery.
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
        pry!(self.require_canonical_path(path));

        if path == "var" || path == "var/" {
            // Return a listing of the directory contents, one per line.
            let mut entries = Vec::new();
            for entry in pry!(::std::fs::read_dir(path)) {
                let entry = pry!(entry);
                let name = entry.file_name().into_string().expect("bad file name");
                if (&name != ".") && (&name != "..") {
                    entries.push(name);
                }
            }
            let text = entries.join("\n");
            let mut response = results.get().init_content();
            response.set_mime_type("text/plain");
            response.init_body().set_bytes(text.as_bytes());
            Promise::ok(())
        } else if path.starts_with("var/") {
            // Serve all files under /var with type application/octet-stream since it comes from the
            // user. E.g. serving as "text/html" here would allow someone to trivially XSS other users
            // of the grain by PUTing malicious HTML content. (Such an attack wouldn't be a huge deal:
            // it would only allow the attacker to hijack another user's access to this grain, not to
            // Sandstorm in general, and if they attacker already has write access to upload the
            // malicious content, they have little to gain from hijacking another session.)
            self.read_file(path, results, "application/octet-stream")
        } else if path == ".can-write" {
            // Fetch "/.can-write" to determine if the user has write permission, so you can show them
            // a different UI if not.
            let mut response = results.get().init_content();
            response.set_mime_type("text/plain");
            response.init_body().set_bytes(&format!("{}", self.can_write).as_bytes());
            Promise::ok(())
        } else if path == "" || path.ends_with("/") {
            // A directory. Serve "index.html".
            self.read_file(&format!("client/{}index.html", path), results, "text/html; charset=UTF-8")
        } else {
            // Request for a static file. Look for it under "client/".
            let filename = format!("client/{}", path);

            // Check if it's a directory.
            if let Ok(true) = ::std::fs::metadata(&filename).map(|md| md.is_dir()) {
                // It is. Return redirect to add '/'.
                let mut redirect = results.get().init_redirect();
                redirect.set_is_permanent(true);
                redirect.set_switch_to_get(true);
                redirect.set_location(&format!("{}/", path));
                Promise::ok(())
            } else {
                // Regular file (or non-existent).
                self.read_file(&filename, results, self.infer_content_type(path))
            }
        }
    }

    fn put(&mut self,
           params: web_session::PutParams,
           mut results: web_session::PutResults)
	-> Promise<(), Error>
    {
        // HTTP PUT request.

        let params = pry!(params.get());
        let path = pry!(params.get_path());
        pry!(self.require_canonical_path(path));

        if !path.starts_with("var/") {
            return Promise::err(Error::failed("PUT only supported under /var.".to_string()));
        }

        if !self.can_write {
            results.get().init_client_error()
                .set_status_code(web_session::response::ClientErrorCode::Forbidden);
        } else {
            use std::io::Write;
            let temp_path = format!("{}.uploading", path);
            let data = pry!(pry!(params.get_content()).get_content());

            pry!(pry!(::std::fs::File::create(&temp_path)).write_all(data));

            pry!(::std::fs::rename(temp_path, path));
            results.get().init_no_content();
        }
        Promise::ok(())
    }

    fn delete(&mut self,
              params: web_session::DeleteParams,
              mut results: web_session::DeleteResults)
	-> Promise<(), Error>
    {
        // HTTP DELETE request.

        let path = pry!(pry!(params.get()).get_path());
        pry!(self.require_canonical_path(path));

        if !path.starts_with("var/") {
            return Promise::err(Error::failed("DELETE only supported under /var.".to_string()));
        }

        if !self.can_write {
            results.get().init_client_error()
                .set_status_code(web_session::response::ClientErrorCode::Forbidden);
            Promise::ok(())
        } else {
            if let Err(e) = ::std::fs::remove_file(path) {
                if e.kind() != ::std::io::ErrorKind::NotFound {
                    return Promise::err(e.into())
                }
            }
            results.get().init_no_content();
            Promise::ok(())
        }
    }
}

impl WebSession {
    fn require_canonical_path(&self, path: &str) -> Result<(), Error> {
        // Require that the path doesn't contain "." or ".." or consecutive slashes, to prevent path
        // injection attacks.
        //
        // Note that such attacks wouldn't actually accomplish much since everything outside /var
        // is a read-only filesystem anyway, containing the app package contents which are non-secret.

        for (idx, component) in path.split_terminator("/").enumerate() {
            if component == "." || component == ".." || (component == "" && idx > 0) {
                return Err(Error::failed(format!("non-canonical path: {:?}", path)));
            }
        }
        Ok(())
  }

    fn infer_content_type(&self, filename: &str) -> &'static str {
        if filename.ends_with(".html") {
            "text/html; charset=UTF-8"
        } else if filename.ends_with(".js") {
            "text/javascript; charset=UTF-8"
        } else if filename.ends_with(".css") {
            "text/css; charset=UTF-8"
        } else if filename.ends_with(".png") {
            "image/png"
        } else if filename.ends_with(".gif") {
            "image/gif"
        } else if filename.ends_with(".jpg") || filename.ends_with(".jpeg") {
            "image/jpeg"
        } else if filename.ends_with(".svg") {
            "image/svg+xml; charset=UTF-8"
        } else if filename.ends_with(".txt") {
            "text/plain; charset=UTF-8"
        } else {
            "application/octet-stream"
        }
    }

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

#[derive(Clone, Copy)]
pub struct UiView;

impl ui_view::Server for UiView {
    fn get_view_info(&mut self,
                     _params: ui_view::GetViewInfoParams,
                     mut results: ui_view::GetViewInfoResults)
                     -> Promise<(), Error>
    {
        let mut view_info = results.get();

        // Define a "write" permission, and then define roles "editor" and "viewer" where only "editor"
        // has the "write" permission. This will allow people to share read-only.
        {
            let perms = view_info.borrow().init_permissions(1);
            let mut write = perms.get(0);
            write.set_name("write");
            write.init_title().set_default_text("write");
        }

        let mut roles = view_info.init_roles(2);
        {
            let mut editor = roles.borrow().get(0);
            editor.borrow().init_title().set_default_text("editor");
            editor.borrow().init_verb_phrase().set_default_text("can edit");
            editor.init_permissions(1).set(0, true);   // has "write" permission
        }
        {
            let mut viewer = roles.get(1);
            viewer.borrow().init_title().set_default_text("viewer");
            viewer.borrow().init_verb_phrase().set_default_text("can view");
            viewer.init_permissions(1).set(0, false);  // does not have "write" permission
        }
        Promise::ok(())
    }


    fn new_session(&mut self,
                   params: ui_view::NewSessionParams,
                   mut results: ui_view::NewSessionResults)
                   -> Promise<(), Error>
    {
        use ::capnp::traits::HasTypeId;
        let params = pry!(params.get());

        if params.get_session_type() != web_session::Client::type_id() {
            return Promise::err(Error::failed("unsupported session type".to_string()));
        }

        let session = pry!(WebSession::new(pry!(params.get_user_info()),
                                           pry!(params.get_context()),
                                           pry!(params.get_session_params().get_as())));
        let client: web_session::Client =
            web_session::ToClient::new(session).from_server::<::capnp_rpc::Server>();

        // we need to do this dance to upcast.
        results.get().set_session(ui_session::Client { client : client.client});
        Promise::ok(())
    }
}

pub fn main() -> Result<(), Box<::std::error::Error>> {
    EventLoop::top_level(move |wait_scope| {
        let mut event_port = try!(::gjio::EventPort::new());
        let network = event_port.get_network();

        // sandstorm launches us with a connection on file descriptor 3
	    let stream = try!(unsafe { network.wrap_raw_socket_descriptor(3) });

        let client = ui_view::ToClient::new(UiView).from_server::<::capnp_rpc::Server>();
        let network =
            twoparty::VatNetwork::new(stream.clone(), stream,
                                      rpc_twoparty_capnp::Side::Client, Default::default());

	    let _rpc_system = RpcSystem::new(Box::new(network), Some(client.client));
        Promise::never_done().wait(wait_scope, &mut event_port)
    })
}
