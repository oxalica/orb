use std::io;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use futures_util::FutureExt;
use hyper::service::service_fn;
use hyper::{header, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use onedrive_api::{Auth, ClientCredential, Permission, Tenant, TokenResponse};
use reqwest::Url;
use rustix::fs::Access;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use super::{safe_write, Credential, CREDENTIAL_FILE_NAME, STATE_FILE_NAME, USER_AGENT};

const LOCALHOST: &str = "localhost";
const LOCALHOST_ADDR: &str = "localhost:0";

pub fn interactive_login(state_dir: PathBuf, client_id: String) -> Result<()> {
    // Fail fast on insufficient permission.
    std::fs::create_dir_all(&state_dir).context("failed to create directory")?;
    rustix::fs::access(
        &state_dir,
        Access::READ_OK | Access::WRITE_OK | Access::EXEC_OK | Access::EXISTS,
    )?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .https_only(true)
        .build()
        .context("failed to build reqwest client")?;
    let perm = Permission::new_read().write(true).offline_access(true);

    let localhost_addrs = LOCALHOST_ADDR
        .to_socket_addrs()
        .context("failed to resolve localhost")?
        .collect::<Vec<_>>();
    ensure!(!localhost_addrs.is_empty(), "no address for localhost");
    log::debug!("resolved localhost: {localhost_addrs:?}");

    let (auth, tokens) = rt.block_on(async {
        // Create one listener for each address, but with the same port.
        // This is necessary, or it happens that we are listening in `[::1]` but the browser
        // send requests to `127.0.0.1`.
        let listener = tokio::net::TcpListener::bind(localhost_addrs[0]).await?;
        let port = listener.local_addr()?.port();

        let redirect_uri = format!("http://{LOCALHOST}:{port}");
        let auth = Arc::new(Auth::new_with_client(
            client,
            client_id,
            perm,
            redirect_uri,
            Tenant::Consumers,
        ));

        let (tx, mut rx) = mpsc::channel(1);
        let auth2 = auth.clone();
        let handler_fn = move |req| {
            request_handler(req, auth2.clone(), tx.clone()).map(|(status, msg)| {
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .status(status)
                        .header(header::CONTENT_TYPE, "text/plain")
                        .body(msg)
                        .expect("no invalid headers"),
                )
            })
        };

        let spawn_server = |listener: tokio::net::TcpListener| {
            let handler_fn = handler_fn.clone();
            tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let handler_fn = handler_fn.clone();
                    tokio::spawn(async move {
                        if let Err(err) = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service_fn(handler_fn))
                            .await
                        {
                            log::error!("failed to serve connection: {err}");
                        }
                    });
                }
            });
        };
        spawn_server(listener);
        for addr in &localhost_addrs[1..] {
            spawn_server(tokio::net::TcpListener::bind((addr.ip(), port)).await?);
        }

        let auth_url = auth.code_auth_url();
        if let Err(err) = open::that_detached(auth_url.as_str()) {
            log::error!("failed to open URL in browser: {err}");
        }
        println!(
            "\
            A login page should be opened in your default browser. \
            Please continue login in that page. \
            If it is not opened automatically, please manually open this link:\n\
            {auth_url}\
            "
        );

        // Drop TX before waiting RX.
        drop(handler_fn);
        let resp = rx
            .recv()
            .await
            .context("local HTTP server exited unexpectedly")?;
        anyhow::Ok((auth, resp))
    })?;

    let cred = Credential {
        read_write: true,
        refresh_token: tokens.refresh_token.unwrap(), // Checked in handler.
        redirect_uri: auth.redirect_uri().to_owned(),
        client_id: auth.client_id().to_owned(),
    };

    let state_path = state_dir.join(STATE_FILE_NAME);
    if let Err(err) = std::fs::remove_file(state_path) {
        if err.kind() != io::ErrorKind::NotFound {
            // Not fatal.
            log::error!("failed to clear states: {err}");
        }
    }

    let cred_path = state_dir.join(CREDENTIAL_FILE_NAME);
    safe_write(&cred_path, &cred).context("failed to save credentials")?;

    println!("credential saved");
    Ok(())
}

async fn request_handler(
    req: Request<hyper::body::Incoming>,
    auth: Arc<Auth>,
    tx: mpsc::Sender<TokenResponse>,
    // ) -> Result<Response<String>, Infallible> {
) -> (StatusCode, String) {
    if req.method() != Method::GET {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            "Only GET is allowed.".into(),
        );
    }
    let Some(pseudo_uri) = req
        .uri()
        .query()
        .and_then(|query| Url::parse(&format!("pseudo:?{query}")).ok())
    else {
        return (StatusCode::BAD_REQUEST, "Invalid URL.".into());
    };
    let get = |key: &str| {
        pseudo_uri
            .query_pairs()
            .find_map(|(k, v)| (k == key).then_some(v))
    };

    let Some(code) = get("code") else {
        return if let Some(err) = get("error") {
            let err_msg = get("error_description").unwrap_or_default();
            (
                StatusCode::UNAUTHORIZED,
                format!("Login failed ({err}): {err_msg}"),
            )
        } else {
            (
                StatusCode::BAD_REQUEST,
                "Missing query parameter 'code' or 'error'.".into(),
            )
        };
    };

    match auth.login_with_code(&code, &ClientCredential::None).await {
        Ok(tokens) if tokens.refresh_token.is_some() => match tx.try_send(tokens) {
            Ok(()) | Err(TrySendError::Full(_)) => (
                StatusCode::OK,
                "Successfully logined. This page can be closed.".into(),
            ),
            Err(TrySendError::Closed(_)) => unreachable!(),
        },
        Ok(_) => (
            StatusCode::UNAUTHORIZED,
            "Missing refresh token in response.".into(),
        ),
        Err(err) => (
            StatusCode::UNAUTHORIZED,
            format!("Login with code failed: {err}"),
        ),
    }
}
