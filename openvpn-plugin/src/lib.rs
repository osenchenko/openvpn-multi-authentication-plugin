#[macro_use]
extern crate lazy_static;
extern crate slog;
use once_cell::sync::{Lazy, OnceCell};
use openvpn_plugin::{openvpn_plugin, EventResult, EventType};
use reqwest;
use reqwest::header;
use std::collections::HashMap;
use std::ffi::CString;
use std::io::Error;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::RwLock;
// use std::time::Duration;
use tokio::runtime;
use tokio::sync::oneshot;
mod auth;
mod license;
mod logging;
mod monitoring;
mod pconfig;
mod radius;
use std::io::{prelude::*, BufReader};

lazy_static! {
    static ref RT: runtime::Runtime = {
        match runtime::Runtime::new() {
            Ok(v) => v,
            Err(e) => {
                println!("Can not start runtime. Exiting");
                println!("{}", e);
                panic!();
            }
        }
    };
    static ref USERNAME: std::ffi::CString = match std::ffi::CString::new("username") {
        Ok(v) => v,
        Err(e) => {
            println!("Can not initialize constants. {}", e);
            panic!();
        }
    };
    static ref PASSWORD: std::ffi::CString = match std::ffi::CString::new("password") {
        Ok(v) => v,
        Err(e) => {
            println!("Can not initialize constants. {}", e);
            panic!();
        }
    };
    static ref UNTRUSTED_IP: std::ffi::CString = match std::ffi::CString::new("untrusted_ip") {
        Ok(v) => v,
        Err(e) => {
            println!("Can not initialize constants. {}", e);
            panic!();
        }
    };
    static ref OPENVPN_CONFIG: std::ffi::CString = match std::ffi::CString::new("config") {
        Ok(v) => v,
        Err(e) => {
            println!("Can not initialize constants. {}", e);
            panic!();
        }
    };
    static ref AUTH_CONTROL_FILE: std::ffi::CString =
        match std::ffi::CString::new("auth_control_file") {
            Ok(v) => v,
            Err(e) => {
                println!("Can not initialize constants. {}", e);
                panic!();
            }
        };
}

pub const PLUGIN_LOG_NAME: &'static str = "auth-plugin";

static HTTP_CLIENT: OnceCell<reqwest::Client> = OnceCell::new();

static CLOSE_MONITORING_TASK_TX: OnceCell<oneshot::Sender<bool>> = OnceCell::new();

static AVAILABLE_SERVICES_IDX: Lazy<Arc<RwLock<Vec<usize>>>> =
    Lazy::new(|| Arc::new(RwLock::new(vec![])));

#[derive(Debug)]
pub struct Handle {
    // Fields needed for the plugin to keep state between callbacks
    pub connections_counter: AtomicU64,
    pub config: pconfig::PluginConfig,
    pub ccd: Option<String>,
}

fn openvpn_open(
    args: Vec<CString>,
    env: HashMap<CString, CString>,
) -> Result<(Vec<EventType>, Handle), Error> {
    // Listen to only the `Up` event, which will be fired when a tunnel has been established.
    let events = vec![
        EventType::ClientConnectV2,
        EventType::ClientDisconnect,
        EventType::AuthUserPassVerify,
    ];

    let c = pconfig::get_config(args)?;

    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::HeaderName::from_bytes(b"X-Api-Key").unwrap(),
        header::HeaderValue::from_str(c.auth_service[0].api_key.as_str()).unwrap(),
    );

    let mut http_client = reqwest::ClientBuilder::new()
        .connect_timeout(std::time::Duration::from_secs(c.connect_timeout_sec as u64))
        .timeout(std::time::Duration::from_secs(
            c.response_timeout_sec as u64,
        ));

    if c.verify_cert {
        slog::debug!(c.logger, "enable verify_cert");
        http_client = http_client.danger_accept_invalid_certs(false);
    } else {
        slog::debug!(c.logger, "disable verify_cert");
        http_client = http_client.danger_accept_invalid_certs(true);
    }
    // .default_headers(headers)
    // http_client = http_client.build();

    let http_client = match http_client.build() {
        Ok(v) => v,
        Err(e) => {
            slog::error!(c.logger, "{}", e);
            return Err(Error::new(std::io::ErrorKind::Other, ""));
        }
    };

    match HTTP_CLIENT.set(http_client) {
        Ok(_v) => {}
        Err(_e) => {
            let msg = "Unable to initialize http client";
            // println!("{}. {}", msg, e);
            slog::error!(c.logger, "{}", msg);
            return Err(Error::new(std::io::ErrorKind::Other, ""));
        }
    };

    let ovpn_config = match env.get::<std::ffi::CString>(&OPENVPN_CONFIG) {
        Some(v) => match v.to_str() {
            Ok(v2) => Some(v2.to_string()),
            Err(e) => {
                slog::error!(c.logger, "Error getting config file path. {}", e);
                None
            }
        },
        None => None,
    };

    let mut ccd: Option<String> = None;

    if ovpn_config.is_some() {
        ccd = find_ccd(ovpn_config, c.logger.clone());
    }

    // let mut close_monitoring_task_tx: Option<oneshot::Sender<bool>> = None;
    // match CLOSE_MONITORING_TASK_TX.set(None) {
    //     Ok(_v) => {}
    //     Err(e) => {
    //         let msg = "Unable to initialize channel";
    //         // println!("{}. {}", msg, e);
    //         slog::error!(c.logger, "[auth-plugin] {} . {:?}", msg, e);
    //         return Err(Error::new(std::io::ErrorKind::Other, msg));
    //     }
    // };
    {
        let mut auth_services: Vec<usize> = vec![];
        for i in 0..c.auth_service.len() {
            auth_services.push(i);
        }

        match AVAILABLE_SERVICES_IDX.write() {
            Ok(mut v) => {
                *v = auth_services.clone();
            }
            Err(e) => {
                slog::error!(c.logger, "{}", e);
                return Err(Error::new(std::io::ErrorKind::Other, ""));
            }
        };
    }

    //TODO:
    if c.monitoring_enable {
        let (tx, rx) = oneshot::channel::<bool>();

        match CLOSE_MONITORING_TASK_TX.set(tx) {
            Ok(_v) => {}
            Err(e) => {
                let msg = "Unable to set command channel";
                // println!("{}. {}", msg, e);
                slog::error!(c.logger, "[auth-plugin] {}. {:?}", msg, e);
                return Err(Error::new(std::io::ErrorKind::Other, ""));
            }
        };
        let mc = monitoring::MonitoringConfig {
            connect_timeout_sec: c.connect_timeout_sec,
            response_timeout_sec: c.response_timeout_sec,
            services: c.auth_service.clone(),
            rx,
            logger: c.logger.clone(),
            check_interval_sec: c.check_interval_sec.unwrap(),
        };
        // let http_client = HTTP_CLIENT.get().expect("Can not dereference http client");
        RT.spawn(async move {
            monitoring::start_monitoring_task(mc).await;
        });
    }
    let handle = Handle {
        connections_counter: AtomicU64::new(0),
        config: c,
        ccd,
        // close_monitoring_task_tx,
    };

    slog::info!(handle.config.logger, "Auth plugin started");
    slog::debug!(handle.config.logger, "Handle {:?}", &handle);

    slog::debug!(handle.config.logger, "Environment {:?}", env);
    Ok((events, handle))
}

fn openvpn_close(handle: Handle) {
    // RT.shutdown_timeout(Duration::from_secs(1));
    slog::info!(handle.config.logger, "Auth plugin stopped");
}

fn openvpn_event(
    event: EventType,
    _args: Vec<CString>,
    env: HashMap<CString, CString>,
    handle: &mut Handle,
) -> Result<EventResult, Error> {
    /* Process the event */

    match event {
        EventType::ClientConnectV2 => {
            handle.connections_counter.fetch_add(1, Ordering::Relaxed);
        }
        EventType::ClientDisconnect => {
            handle.connections_counter.fetch_sub(1, Ordering::Relaxed);
        }
        EventType::AuthUserPassVerify => {
            return auth::start(handle, env);
        }
        _ => {}
    }
    // If the processing worked fine and/or the request the callback represents should be
    // accepted, return EventResult::Success. See EventResult docs for more info.
    Ok(EventResult::Success)
}

openvpn_plugin!(
    crate::openvpn_open,
    crate::openvpn_close,
    crate::openvpn_event,
    Handle
);

//find client config dir option
fn find_ccd(cfg: Option<String>, lgr: slog::Logger) -> Option<String> {
    if cfg.is_none() {
        return None;
    }

    let f = match std::fs::File::open(cfg.unwrap()) {
        Ok(v) => v,
        Err(e) => {
            slog::error!(lgr, "{}", e);
            return None;
        }
    };

    let r = BufReader::new(f);

    for line in r.lines() {
        match line {
            Ok(v) => {
                if v.starts_with("client-config-dir") {
                    match v.strip_prefix("client-config-dir ") {
                        Some(v) => return Some(v.trim_start().trim_end().to_string()),
                        None => return None,
                    };
                    // return Some(v);
                }
            }
            Err(_e) => {}
        };
    }

    None
}
