use super::pconfig::AuthService;
use super::radius;
use super::{
    Handle, AUTH_CONTROL_FILE, AVAILABLE_SERVICES_IDX, HTTP_CLIENT, PASSWORD, RT, UNTRUSTED_IP,
    USERNAME,
};
// use http;
use openvpn_plugin::EventResult;
use reqwest::{header::HeaderName, header::HeaderValue, StatusCode};
use serde::Serialize;
use std::collections::HashMap;
use std::ffi::CString;
use std::io::Error;
use std::sync::Arc;
// "auth_control_file": "/tmp/openvpn_acf_792c5faa96908c8d5e16f7f5b23099b2.tmp"
// 1 - success
// 0 - error
// "username": "user",
// "password": "1"
//
//
//
static HTTP_HEADER_AUTH_PROVIDER_ID: &'static str = "X-Auth-Provider";

enum AuthResponse {
    Radius(radius::RadiusResponseOpts),
    Other(OtherResponseOpts),
}

struct OtherResponseOpts();

pub fn start(h: &Handle, env: HashMap<CString, CString>) -> Result<EventResult, Error> {
    // slog::debug!(h.config.logger, "{:?}", env);

    let (username, password, auth_control_file) = get_auth_params(h, &env)?;
    let client_ip = get_client_ip(h, &env)?;
    let logger = h.config.logger.clone();
    let data = Post {
        u: username,
        p: password,
        client_ip: client_ip,
    };
    let http_client = HTTP_CLIENT.get().expect("Can not dereference http client");
    let ccd = h.ccd.clone();
    let auth_services = h.config.auth_service.clone();
    RT.spawn(async move {
        run_task(
            logger,
            http_client,
            auth_services,
            // addr,
            // api_key,
            data,
            auth_control_file,
            ccd,
        )
        .await;
    });

    Ok(EventResult::Deferred)
}

fn get_auth_params(
    h: &Handle,
    env: &HashMap<CString, CString>,
) -> Result<(String, String, String), Error> {
    let username: String = match env.get::<std::ffi::CString>(&USERNAME) {
        Some(v) => match v.to_str() {
            Ok(v2) => v2.to_string(),
            Err(e) => {
                slog::error!(
                    h.config.logger,
                    "Username contains invalid utf-8 data. {}",
                    e
                );
                return Err(Error::new(std::io::ErrorKind::InvalidData, ""));
            }
        },
        _ => {
            slog::error!(h.config.logger, "Can not find username in arguments");
            return Err(Error::new(std::io::ErrorKind::InvalidData, ""));
        }
    };
    let password: String = match env.get::<std::ffi::CString>(&PASSWORD) {
        Some(v) => match v.to_str() {
            Ok(v2) => v2.to_string(),
            Err(e) => {
                slog::error!(
                    h.config.logger,
                    "Password contains invalid utf-8 data. {}",
                    e
                );
                return Err(Error::new(std::io::ErrorKind::InvalidData, ""));
            }
        },
        _ => {
            slog::error!(h.config.logger, "Can not find password in arguments");
            return Err(Error::new(std::io::ErrorKind::InvalidData, ""));
        }
    };
    let auth_control_file: String = match env.get::<std::ffi::CString>(&AUTH_CONTROL_FILE) {
        Some(v) => match v.to_str() {
            Ok(v2) => v2.to_string(),
            Err(e) => {
                slog::error!(
                    h.config.logger,
                    "auth_control_file contains invalid utf-8 data. {}",
                    e
                );
                return Err(Error::new(std::io::ErrorKind::InvalidData, ""));
            }
        },
        _ => {
            slog::error!(
                h.config.logger,
                "Can not find auth_control_file in arguments"
            );
            return Err(Error::new(std::io::ErrorKind::InvalidData, ""));
        }
    };
    Ok((username, password, auth_control_file))
}

fn get_client_ip(h: &Handle, env: &HashMap<CString, CString>) -> Result<String, Error> {
    return match env.get::<std::ffi::CString>(&UNTRUSTED_IP) {
        Some(v) => match v.to_str() {
            Ok(v2) => Ok(v2.to_string()),
            Err(e) => {
                slog::error!(
                    h.config.logger,
                    "untrusted client ip contains invalid utf-8 data. {}",
                    e
                );
                return Err(Error::new(std::io::ErrorKind::InvalidData, ""));
            }
        },
        _ => {
            slog::error!(h.config.logger, "Can not find untrusted_ip in arguments");
            return Err(Error::new(std::io::ErrorKind::InvalidData, ""));
        }
    };
}

#[derive(Serialize, Debug, Clone)]
struct Post {
    u: String,
    p: String,
    client_ip: String,
}

async fn run_task(
    logger: slog::Logger,
    http_client: &reqwest::Client,
    auth_services: Arc<Vec<AuthService>>,
    // addr: String,
    // api_key: String,
    data: Post,
    auth_control_file: String,
    ccd: Option<String>,
) {
    let username = data.u.clone();
    let idx: usize;
    {
        let v = match AVAILABLE_SERVICES_IDX.read() {
            Ok(v1) => v1,
            Err(e) => {
                slog::error!(
                    logger,
                    "Can't obtain read lock on AVAILABLE_SERVICES_IDX. {}",
                    e
                );
                write_decline(logger, &auth_control_file, &username);
                return;
            }
        };
        if v.len() == 0 {
            slog::error!(logger, "There is no authentication services available. Can't authenticate user {}. Decline authentication", username);
            write_decline(logger, &auth_control_file, &username);
            return;
        }
        idx = v[0];
    }
    let addr = auth_services[idx].url.clone();
    let api_key = auth_services[idx].api_key.clone();

    let r = authenticate(
        logger.clone(),
        http_client,
        format!("{}/{}", addr, "auth"),
        api_key,
        data, // auth_control_file.clone(),
    )
    .await;
    if r.is_err() {
        write_decline(logger, &auth_control_file, &username);
        return;
    }
    match r.unwrap() {
        AuthResponse::Other(_v) => {
            write_success(logger, &auth_control_file, &username);
            return;
        }
        AuthResponse::Radius(v) => {
            if ccd.is_some() {
                radius::write_to_ccd(logger.clone(), ccd, &username, v);
            }
            write_success(logger, &auth_control_file, &username);
            return;
        }
    }
}

async fn authenticate(
    logger: slog::Logger,
    http_client: &reqwest::Client,
    addr: String,
    api_key: String,
    data: Post,
    // auth_control_file: String,
) -> Result<AuthResponse, std::io::Error> {
    let x_api_key = HeaderName::from_bytes(b"X-Api-Key").unwrap();
    let req = http_client
        .request(reqwest::Method::POST, addr.as_str())
        .header(x_api_key, api_key)
        .json(&data);
    // let r = http_client.post(addr.as_str()).json(&data).send().await;
    let r = req.send().await;
    let resp = match r {
        Err(e) => {
            slog::error!(logger, "{}", e);
            let err = std::io::Error::new(std::io::ErrorKind::Other, "");
            return Err(err);
        }
        Ok(v) => v,
    };

    if resp.status() != StatusCode::OK {
        slog::debug!(
            logger,
            "User {} authentication failed. Pass: {} ",
            data.u,
            data.p
        );
        slog::debug!(logger, "Response {:?}", resp);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, ""));
    }
    let headers = resp.headers();
    let id = headers.get(HTTP_HEADER_AUTH_PROVIDER_ID);
    if id.is_none() {
        slog::error!(
            logger,
            "Header {} is missing. Can not identify auth provider. Can not authenticate user {}",
            HTTP_HEADER_AUTH_PROVIDER_ID,
            &data.u,
        );
        return Err(std::io::Error::new(std::io::ErrorKind::Other, ""));
    }

    let default_hv = HeaderValue::from_static("");

    let id: String = id
        .unwrap_or_else(|| &default_hv)
        .to_str()
        .unwrap_or_else(|_x| "")
        .to_lowercase();

    slog::debug!(logger, "{}", &id);
    match id.as_str() {
        "other" => {
            if resp.status() == StatusCode::OK {
                return Ok(AuthResponse::Other(OtherResponseOpts()));
            }
        }
        "ldap" => {
            if resp.status() == StatusCode::OK {
                return Ok(AuthResponse::Other(OtherResponseOpts()));
            }
        }
        "radius" => {
            match resp.json::<radius::RadiusResponseOpts>().await {
                Ok(v) => {
                    return Ok(AuthResponse::Radius(v));
                }
                Err(e) => {
                    slog::warn!(logger, "{}", e,);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    ));
                }
            };

            // let radius_opts = radius::
            // return Ok
        }
        _ => {
            slog::error!(
                logger,
                "Could't match header value {:?} to auth provider id",
                id
            );
            return Err(std::io::Error::new(std::io::ErrorKind::Other, ""));
        }
    }
    return Err(std::io::Error::new(std::io::ErrorKind::Other, ""));
}

fn write_success(logger: slog::Logger, auth_control_file: &String, username: &String) {
    let r = std::fs::write(&auth_control_file, &"1");
    if r.is_err() {
        slog::error!(
            logger,
            "Authentication of user {} succeded, but can not write to auth_control_file {}",
            username,
            auth_control_file
        );
    }
}

fn write_decline(logger: slog::Logger, auth_control_file: &String, username: &String) {
    let r = std::fs::write(auth_control_file, &"0");
    if r.is_err() {
        slog::error!(
            logger,
            "Authentication of user {} failed. Can not write to auth_control_file {}",
            username,
            auth_control_file
        );
    }
}

// #[cfg(test)]
// mod test {//     use super::*;
//     use once_cell::sync::OnceCell;
//     use reqwest;
//     use reqwest::header;
//     use slog;
//     use slog::o;
//     use slog::Drain;
//     use slog_async;
//     use slog_term;
//
//     static HTTP_CLIENT2: OnceCell<reqwest::Client> = OnceCell::new();
//     #[tokio::test(threaded_scheduler)]
//     async fn test_auth_call() {
//         let decorator = slog_term::TermDecorator::new().build();
//         let drain = slog_term::FullFormat::new(decorator).build().fuse();
//         let drain = slog_async::Async::new(drain).build().fuse();
//
//         let lgr = slog::Logger::root(drain, o!());
//
//         let mut headers = header::HeaderMap::new();
//         headers.insert("X-Api-key", header::HeaderValue::from_static("123456789"));
//
//         let http_client = reqwest::ClientBuilder::new()
//             .timeout(std::time::Duration::from_secs(15))
//             .default_headers(headers)
//             .danger_accept_invalid_certs(true)
//             .build()
//             .unwrap();
//         HTTP_CLIENT2.set(http_client).unwrap();
//         let addr: String = String::from("http://127.0.0.1:11245/auth");
//         let data = Post {
//             u: String::from("user"),
//             p: String::from("1"),
//         };
//
//         // let r = authenticate(lgr.clone(), &http_client, addr, data).await;
//
//         let mut i = 0;
//         // let tasks: Vec<_> = Vec::new();
//
//         while i < 1 {
//             let addr2 = addr.clone();
//             let data2 = data.clone();
//             let lgr2 = lgr.clone();
//             run_task(addr2, data2, lgr2);
//             i = i + 1;
//         }
//         // match r {
//         //     Ok(v) => match v {
//         //         AuthResponse::Radius(v1) => {
//         //             slog::debug!(lgr, "auth response radius");
//         //             slog::debug!(lgr, "{:?}", v1);
//         //         }
//         //         _ => {
//         //             slog::debug!(lgr, "auth response other");
//         //         }
//         //     },
//         //     Err(e) => {
//         //         slog::error!(lgr, "{:?}", e);
//         //     }
//         // };
//         tokio::time::delay_for(std::time::Duration::from_secs(20)).await;
//     }
//
//     // fn run_task(
//     //     addr: String,
//     //     data: Post,
//     //     lgr: slog::Logger,
//     //     // http_client: &'static reqwest::Client,
//     // ) {
//     //     let http_client = HTTP_CLIENT2.get().unwrap();
//     //     tokio::spawn(async move {
//     //         authenticate(lgr, &http_client, addr, data).await;
//     //     });
//     // }
// }
