use super::logging;
use super::PLUGIN_LOG_NAME;
use config;
use std::ffi::CString;
use std::io::Error;
use std::sync::Arc;
const AUTH_SERVICE: &'static str = "auth_service";

const LOG_FILE: &'static str = "log.file";
const LOG_LEVEL: &'static str = "log.level";
const VERIFY_CERT: &'static str = "https_verify_cert";
const MONITORING_ENABLE: &'static str = "monitoring.enable";
const MONITORING_CHECK_INTERVAL_SEC: &'static str = "monitoring.check_interval_sec";
const CONNECT_TIMEOUT_SEC: &'static str = "auth.connect_timeout_sec";
const RESPONSE_TIMEOUT_SEC: &'static str = "auth.response_timeout_sec";

#[derive(Debug, Clone)]
pub struct AuthService {
    pub name: String,
    pub url: String,
    pub api_key: String,
    pub monitoring_path: Option<String>,
    pub monitoring_api_key: Option<String>,
}

#[derive(Debug)]
pub struct PluginConfig {
    pub verify_cert: bool,
    pub logger: slog::Logger,
    pub auth_service: Arc<Vec<AuthService>>,
    //openvpn_client_config_dir. See openvpn config manuals.
    // pub openvpn_ccd: Option<String>,
    pub connect_timeout_sec: i64,
    pub response_timeout_sec: i64,
    pub monitoring_enable: bool,
    pub check_interval_sec: Option<i64>,
}

pub fn get_config(args: Vec<CString>) -> Result<PluginConfig, Error> {
    if args.len() != 3 {
        println!("[{}] Command line parameters are missing", PLUGIN_LOG_NAME);
        return Err(Error::new(
            std::io::ErrorKind::InvalidInput,
            "Command line parameters are missing",
        ));
    }

    let config_arg = match args[1].to_str() {
        Ok(v) => v,
        Err(e) => {
            println!(
                "[{}] Command line parameter name --config is missing. {}",
                PLUGIN_LOG_NAME, e
            );
            return Err(Error::new(std::io::ErrorKind::InvalidInput, ""));
        }
    };

    let config_path = match config_arg {
        "--config" => {
            let v = match args[2].to_str() {
                Ok(v) => v,
                Err(e) => {
                    println!("{}", e);
                    return Err(Error::new(std::io::ErrorKind::InvalidInput, ""));
                }
            };
            v
        }
        _ => {
            println!(
                "[{}] Command line parameter name --config is missing.",
                PLUGIN_LOG_NAME
            );
            return Err(Error::new(std::io::ErrorKind::InvalidInput, ""));
        }
    };

    let mut s = config::Config::default();

    match s.merge(config::File::with_name(config_path)) {
        Ok(_v) => {}
        Err(e) => {
            println!("[{}] {}", PLUGIN_LOG_NAME, e);
            return Err(Error::new(std::io::ErrorKind::NotFound, ""));
        }
    };

    let verify_cert = match s.get_bool(VERIFY_CERT) {
        Ok(v) => v,
        Err(e) => {
            println!(
                "[{}]. Error getting verify_cert value. Error: {}",
                PLUGIN_LOG_NAME, e
            );
            return Err(Error::new(std::io::ErrorKind::InvalidInput, ""));
        }
    };
    let auth_service = match s.get_array(AUTH_SERVICE) {
        Ok(v) => v,
        Err(e) => {
            println!("[{}] {}", PLUGIN_LOG_NAME, e);
            return Err(Error::new(std::io::ErrorKind::InvalidInput, ""));
        }
    };

    let monitoring_enable = match s.get_bool(MONITORING_ENABLE) {
        Ok(v) => v,
        Err(e) => {
            println!(
                "[{}]. Error getting monitoring enable value. Error: {}",
                PLUGIN_LOG_NAME, e
            );
            return Err(Error::new(std::io::ErrorKind::InvalidInput, ""));
        }
    };
    // let auth_service: Vec<String> = match auth_service.into_iter().map(|v| v.into_str()).collect() {
    //     Ok(v) => v,
    //     Err(e) => {
    //         println!("[{}] {}", PLUGIN_LOG_NAME, e);
    //         return Err(Error::new(std::io::ErrorKind::InvalidInput, ""));
    //     }
    // };
    let mut check_interval_sec: Option<i64> = None;
    if monitoring_enable {
        check_interval_sec = match s.get_int(MONITORING_CHECK_INTERVAL_SEC) {
            Ok(v) => Some(v),
            Err(e) => {
                println!(
                    "[{}]. Error getting monitoring enable value. Error: {}",
                    PLUGIN_LOG_NAME, e
                );
                return Err(Error::new(std::io::ErrorKind::InvalidInput, ""));
            }
        }
    }

    let auth_service: Vec<AuthService> = auth_service
        .into_iter()
        .map(|x| {
            let v = x.into_table().unwrap();
            let v2 = v.get("monitoring").unwrap();
            let monitoring = v2.clone().into_table().unwrap();

            let v2 = monitoring.get("path");
            let p_str = match v2 {
                Some(v4) => Some(v4.to_string()),
                None => None,
            };

            let api_key = monitoring.get("api_key");

            let m_api_key = match api_key {
                Some(v3) => Some(v3.to_string()),
                None => None,
            };

            AuthService {
                name: v
                    .get("name")
                    .expect("Expect 'name' in auth_service array element")
                    .to_string(),
                url: v
                    .get("url")
                    .expect("Expect 'url' in auth_service array element")
                    .to_string(),
                api_key: v
                    .get("api_key")
                    .expect("Expect 'api_key' in auth_service array element")
                    .to_string(),
                monitoring_path: p_str,
                monitoring_api_key: m_api_key,
            }
        })
        .collect();

    let log_file = match s.get_str(LOG_FILE) {
        Ok(v) => v,
        Err(e) => {
            println!("[{}] {}", PLUGIN_LOG_NAME, e);
            return Err(Error::new(std::io::ErrorKind::InvalidInput, ""));
        }
    };

    let log_level = match s.get_str(LOG_LEVEL) {
        Ok(v) => v,
        Err(e) => {
            println!("[{}] {}", PLUGIN_LOG_NAME, e);
            return Err(Error::new(std::io::ErrorKind::InvalidInput, ""));
        }
    };

    // let openvpn_ccd = match s.get_str(OPENVPN_CCD) {
    //     Ok(v) => Some(v),
    //     Err(e) => {
    //         println!(
    //             "[{}] [Warning] Configuration parameter {} not found. {}",
    //             OPENVPN_CCD, PLUGIN_LOG_NAME, e
    //         );
    //         None
    //         // return Err(Error::new(std::io::ErrorKind::InvalidInput, ""));
    //     }
    // };

    let connect_timeout_sec = match s.get_int(CONNECT_TIMEOUT_SEC) {
        Ok(v) => v,
        Err(e) => {
            println!("[{}] {}", PLUGIN_LOG_NAME, e);
            return Err(Error::new(std::io::ErrorKind::InvalidInput, ""));
        }
    };
    let response_timeout_sec = match s.get_int(RESPONSE_TIMEOUT_SEC) {
        Ok(v) => v,
        Err(e) => {
            println!("[{}] {}", PLUGIN_LOG_NAME, e);
            return Err(Error::new(std::io::ErrorKind::InvalidInput, ""));
        }
    };

    if monitoring_enable {
        for v in &auth_service {
            if v.monitoring_api_key.is_none() || v.monitoring_api_key.is_none() {
                println!("[{}] When monitoring is enabled in every auth_service must be set monitoring api_key and monitoring path", PLUGIN_LOG_NAME);
                return Err(Error::new(std::io::ErrorKind::InvalidInput, ""));
            }
        }
    }

    let logger = logging::create_logger(log_file, log_level)?;

    Ok(PluginConfig {
        verify_cert,
        logger,
        auth_service: Arc::new(auth_service),
        // openvpn_ccd,
        connect_timeout_sec,
        response_timeout_sec,
        monitoring_enable,
        check_interval_sec,
    })
}
