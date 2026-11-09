use std::net::IpAddr;

use reqwest::{Response, Url};

pub(crate) fn is_secure_service_url(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    match url.scheme() {
        "https" => true,
        "http" => {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        }
        _ => false,
    }
}

pub(crate) async fn read_response_limited(
    mut response: Response,
    maximum: usize,
) -> Result<Option<Vec<u8>>, reqwest::Error> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Ok(None);
    }
    let initial_capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
        .min(maximum);
    let mut body = Vec::with_capacity(initial_capacity);
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > maximum.saturating_sub(body.len()) {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn plaintext_http_is_loopback_only() {
        for accepted in [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://127.2.3.4:8080",
            "http://[::1]:8080",
            "https://gateway.example.com",
        ] {
            assert!(is_secure_service_url(&Url::parse(accepted).unwrap()));
        }
        for rejected in [
            "http://example.com",
            "http://10.0.0.4:8080",
            "http://192.168.1.4:8080",
            "ftp://localhost/file",
        ] {
            assert!(!is_secure_service_url(&Url::parse(rejected).unwrap()));
        }
    }

    #[tokio::test]
    async fn chunked_response_is_rejected_as_soon_as_the_limit_is_crossed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nabcd\r\n4\r\nefgh\r\n0\r\n\r\n",
                )
                .unwrap();
        });
        let response = reqwest::get(format!("http://{address}")).await.unwrap();
        assert!(read_response_limited(response, 5).await.unwrap().is_none());
        server.join().unwrap();
    }
}
