//! The redirect endpoint on the loopback (RFC 8252 §7.3), which the browser
//! comes back to with the authorization code.

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

/// Waits for the provider's redirect to the loopback, and returns its code.
/// A request that isn't it, including one with another sign-in's `state`, is
/// answered and ignored: a page on another site can reach the loopback too.
pub async fn callback(listener: &TcpListener, state: &str) -> Result<String> {
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .context("the sign-in's loopback failed")?;
        let Some(target) = request_target(&mut stream).await else {
            continue;
        };
        let Some(query) = target.strip_prefix("/callback?") else {
            respond(&mut stream, "404 Not Found", "Not found.").await;
            continue;
        };
        let params: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        if params.get("state").map(String::as_str) != Some(state) {
            let message = "This isn't the sign-in cf-sts started.";
            respond(&mut stream, "400 Bad Request", message).await;
            continue;
        }
        if let Some(error) = params.get("error") {
            let description = params.get("error_description").map_or("", String::as_str);
            let message = "The sign-in failed. cf-sts says why.";
            respond(&mut stream, "200 OK", message).await;
            bail!("the provider refused the sign-in ({error}): {description}");
        }
        let Some(code) = params.get("code") else {
            respond(&mut stream, "400 Bad Request", "The sign-in had no code.").await;
            continue;
        };
        let message = "Signed in. You can close this tab.";
        respond(&mut stream, "200 OK", message).await;
        return Ok(code.clone());
    }
}

/// Returns the target of an HTTP `GET`, from its request line.
async fn request_target(stream: &mut TcpStream) -> Option<String> {
    let mut buf = vec![0; 8192];
    let mut read = 0;
    while !buf[..read].windows(4).any(|w| w == b"\r\n\r\n") && read < buf.len() {
        match stream.read(&mut buf[read..]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => read += n,
        }
    }
    let head = String::from_utf8_lossy(&buf[..read]);
    let mut line = head.lines().next()?.split(' ');
    match (line.next(), line.next()) {
        (Some("GET"), Some(target)) => Some(target.to_string()),
        _ => None,
    }
}

/// Answers the browser with a page saying `message`.
async fn respond(stream: &mut TcpStream, status: &str, message: &str) {
    let body = format!(
        "<!doctype html><title>cf-sts</title><p style=\"font-family:sans-serif\">{message}</p>\n"
    );
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\ncache-control: no-store\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    // The browser may be gone already: the sign-in still counts.
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ignores_requests_that_arent_this_sign_ins_redirect() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let waiting = tokio::spawn(async move { callback(&listener, "the-state").await });

        let client = reqwest::Client::new();
        let get = |path: &str| client.get(format!("{base}{path}")).send();
        assert_eq!(get("/favicon.ico").await.unwrap().status(), 404);
        let forged = get("/callback?code=forged&state=other").await.unwrap();
        assert_eq!(forged.status(), 400);
        let real = get("/callback?code=the-code&state=the-state")
            .await
            .unwrap();
        assert_eq!(real.status(), 200);

        assert_eq!(waiting.await.unwrap().unwrap(), "the-code");
    }
}
