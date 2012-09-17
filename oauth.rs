//
// rust-oauth/oauth.rs
//
// A simple Rust implementation of the OAuth 1.0 protocol. Based on python-oauth2, copyright (c)
// 2007-2010 Leah Culver, Joe Stump, Mark Paschal, Vic Fryzel.
//
// Copyright (c) 2012 Mozilla Foundation
//

extern mod nss;
extern mod std;

use nss::common::{Item, siBuffer};
use nss::pk11pub;
use nss::pkcs11t::{CKA_SIGN, CKM_SHA_1_HMAC};
use nss::secmodt::PK11_OriginUnwrap;

use mod std::net::url;
use std::base64::ToBase64;
use std::net::url::Url;
use std::sort::Sort;

use mod dvec;
use dvec::DVec;
use from_str::from_str;
use send_map::SendMap;
use send_map::linear::LinearMap;
use to_str::ToStr;

struct Token {
    key: &str,
    secret: &str
}

struct Consumer {
    key: &str,
    secret: &str
}

/**
 * Signature methods
 */

enum SignatureMethod {
    HmacSha1
}

impl SignatureMethod : ToStr {
    fn to_str() -> ~str {
        match self {
            HmacSha1 => ~"HMAC-SHA1"
        }
    }
}

/**
 * OAuth requests.
 */

struct Request {
    method: &str,
    url: &Url,
    parameters: &LinearMap<~str,~str>
}

impl Request {
    // The normalized URL excludes parameters, query, and fragment.
    fn normalized_url(&self) -> ~str {
        let url = self.url;

        // Exclude default port numbers.
        let mut opt_port = copy url.port;
        match opt_port {
            Some(copy port) => {
                // FIXME: Using a pattern guard here causes a segfault (Rust issue #3370).
                if (url.scheme == ~"http" && from_str(port) == Some(80)) ||
                   (url.scheme == ~"https" && from_str(port) == Some(443)) {
                    opt_port = None;
                }
            }
            None => {}
        }

        // FIXME: Combining these two statements into one causes a segfault.
        let url = url::Url(copy url.scheme, None, copy url.host, opt_port, copy url.path, ~[],
                           None);
        return url.to_str();
    }

    // Returns a string that contains the parameters that must be signed.
    fn normalized_parameters(&self) -> ~str {
        let items = DVec();
        for self.url.query.each |pair| {
            // FIXME: Causes LLVM assertion: let (ref key, ref value) = pair;
            if pair.first() != ~"oauth_signature" {
                items.push(copy pair);
            }
        }

        for self.parameters.each_ref |key, value| {
            if *key != ~"oauth_signature" {
                items.push((copy *key, copy *value));
            }
        }

        let mut items = dvec::unwrap(items);
        items.qsort();
        return url::query_to_str(items);
    }

    fn sign(&self, method: SignatureMethod, consumer: &Consumer, token: Option<&Token>) -> ~str {
        let signature = [
            url::encode_component(self.method),
            url::encode_component(self.normalized_url()),
            url::encode_component(self.normalized_parameters())
        ];

        let mut key = url::encode_component(consumer.secret) + "&";
        match token {
            None => {}
            Some(token) => key += url::encode_component(token.secret)
        }
        debug!("key text: %?", key);

        let raw = str::connect(signature, "&");
        debug!("raw text: %?", raw);

        let bytes;
        match method {
            HmacSha1 => bytes = self.sign_hmac_sha1(key, raw)
        }

        return bytes.to_base64();
    }

    fn sign_hmac_sha1(&self, key: &str, raw: &str) -> ~[u8] {
        // Call directly to NSS to perform the signing operation.
        //
        // This is basically writing C in Rust, so it's rather ugly. I could have written higher-
        // level APIs, but I don't trust myself not to make disastrous-from-a-security-perspective
        // design mistakes.

        // FIXME: What happens on double initialization?
        // FIXME: I sure hope this is threadsafe...
        nss::init_nodb(".").get();

        let mechanism = CKM_SHA_1_HMAC;
        let key_item = Item { sec_type: siBuffer, data: str::as_bytes_slice(key) };
        let slot = pk11pub::SlotInfo::best(mechanism);
        let operation = CKA_SIGN;
        let sym_key = slot.import_sym_key(mechanism, PK11_OriginUnwrap, operation, &key_item);
        let mut dest_item = Item { sec_type: siBuffer, data: &[] };
        let context = pk11pub::Context::new_with_sym_key(mechanism, operation, &sym_key,
                                                         &mut dest_item);
        context.digest_begin();
        context.digest_op(str::as_bytes_slice(raw));
        return result::unwrap(context.digest_final());
    }
}

fn main() {
    let token = Token { key: "tok-test-key", secret: "tok-test-secret" };
    let consumer = Consumer { key: "con-test-key", secret: "con-test-secret" };

    let mut params = LinearMap();
    (&mut params).insert(~"oauth_version", ~"1.0");
    (&mut params).insert(~"oauth_nonce", ~"1234");
    (&mut params).insert(~"oauth_timestamp", ~"5678");
    (&mut params).insert(~"user", ~"joestump");
    (&mut params).insert(~"photoid", ~"555555555555");
    (&mut params).insert(~"oauth_consumer_key", consumer.key.to_str());
    (&mut params).insert(~"oauth_token", token.key.to_str());
    (&mut params).insert(~"oauth_signature_method", HmacSha1.to_str());

    let url = option::unwrap(from_str("http://example.com/photos"));

    let signature = {
        let request = Request {
            method: "GET",
            url: &url,
            parameters: &params
        };

        request.sign(HmacSha1, &consumer, Some(&token))
    };

    (&mut params).insert(~"oauth_signature", signature);

    // FIXME: If you say params.each_ref here it segfaults!
    for (&params).each_ref |key, value| {
        io::println(fmt!("%s=%s", *key, *value));
    }
}

