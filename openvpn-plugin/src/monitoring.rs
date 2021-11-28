use super::{pconfig, AVAILABLE_SERVICES_IDX};
// use super::HTTP_CLIENT;
use reqwest;
use reqwest::{header::HeaderName, header::HeaderValue, StatusCode};
use serde::Deserialize;
use std::sync::Arc;
use tokio;
use tokio::sync::oneshot;
// use tokio::task::JoinHandle;
// use futures::future::join_all;
use tokio::time::{delay_for, Duration};

pub struct MonitoringConfig {
    pub connect_timeout_sec: i64,
    pub response_timeout_sec: i64,
    pub check_interval_sec: i64,
    pub services: Arc<Vec<pconfig::AuthService>>,
    pub rx: oneshot::Receiver<bool>,
    pub logger: slog::Logger,
}

#[derive(Deserialize, Debug)]
pub struct StatusResponse {
    status_id: i64,
    status_text: String,
    msg: Option<String>,
}

pub async fn start_monitoring_task(c: MonitoringConfig) {
    let http_client = reqwest::ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(c.connect_timeout_sec as u64))
        .timeout(std::time::Duration::from_secs(
            // c.response_timeout_sec as u64,
            10,
        ))
        // .default_headers(headers)
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let d = Duration::from_secs(c.check_interval_sec as u64);
    let mut rx = c.rx;
    let x_api_key_name = HeaderName::from_bytes(b"X-Api-Key").unwrap();

    // let mut tasks: Vec<JoinHandle<Result<(), ()>>> = vec![];
    let mut auth_services: Vec<usize> = vec![];

    // let req = http_client
    //     .request(reqwest::Method::GET, addr.as_str())
    //     .header(x_api_key_name, api_key);
    // // let r = http_client.post(addr.as_str()).json(&data).send().await;
    // let r = req.send().await;
    // let resp = match r {
    //     Err(e) => {
    //
    //
    //         slog::error!(c.logger, "{}", e);
    //         let err = std::io::Error::new(std::io::ErrorKind::Other, "");
    //         return;
    //     }
    //     Ok(v) => v,
    // };
    let len = c.services.len();
    loop {
        auth_services.truncate(0);

        // let mut i: usize = 0;

        for i in 0..len {
            let svc = &c.services[i];
            let url = format!(
                "{}{}",
                svc.url,
                svc.monitoring_path
                    .clone()
                    .unwrap_or_else(|| "/".to_string())
            );
            slog::debug!(
                c.logger,
                "Send monitoring request to service {} and url {}",
                &svc.name,
                &url
            );

            let req = http_client
                .request(reqwest::Method::GET, url.as_str())
                .header(
                    &x_api_key_name,
                    svc.monitoring_api_key
                        .clone()
                        .unwrap_or_else(|| "api_key_is_none".to_string()),
                );

            match req.send().await {
                Ok(v) => {
                    slog::debug!(
                        c.logger,
                        "Received monitoring response from service {} and url {} with status {}",
                        &svc.name,
                        &url,
                        v.status(),
                    );
                    if v.status() == 404 || v.status() == 403 {
                        slog::error!(c.logger, "Got response {}. Check monitoring path in config files and monitoring user/password", v.status());
                    } else {
                        let resp = v.json::<StatusResponse>().await;
                        match resp {
                            Ok(v2) => {
                                if v2.status_id != 3 {
                                    auth_services.push(i);
                                }
                            }
                            Err(err2) => {
                                slog::error!(c.logger, "{}", err2);
                            }
                        };
                    }
                }
                Err(err) => slog::error!(c.logger, "{}", err),
            };
            // i = i + 1;
        }

        {
            // let mut v = AVAILABLE_SERVICES_IDX.write();
            match AVAILABLE_SERVICES_IDX.write() {
                Ok(mut v) => {
                    *v = auth_services.clone();
                }
                Err(e) => {
                    slog::error!(c.logger, "{}", e);
                }
            };
            // *v = auth_services.clone();
        }

        tokio::select! {
            _val = &mut rx =>{ break;}
            _= delay_for(d)=>{}
        }
    }
}
