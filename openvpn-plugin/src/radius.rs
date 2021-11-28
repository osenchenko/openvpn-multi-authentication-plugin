use serde::Deserialize;

// static DNS_SERVERS: &'static str = "dns-servers";
// static HTTP_HEADER_AUTH_PROVIDER_ID: &'static str = "routes";
// static HTTP_HEADER_AUTH_PROVIDER_ID: &'static str = "framed_ip";
// static HTTP_HEADER_AUTH_PROVIDER_ID: &'static str = "framed-mask";

#[derive(Deserialize, Debug)]
pub struct RadiusResponseOpts {
    pub dns_servers: Option<Vec<String>>,
    pub routes: Option<Vec<String>>,
    pub ip: Option<String>,
    pub netmask: Option<String>,
}

// pub fn parse_opt
//
pub fn write_to_ccd(
    logger: slog::Logger,
    ccd: Option<String>,
    username: &String,
    opts: RadiusResponseOpts,
) {
    let topology = "topology subnet";
    slog::debug!(logger, "{:?}", &opts);
    if opts.ip.is_some() && opts.netmask.is_some() {
        let ipconfig = format!(
            "ifconfig-push {} {}",
            opts.ip.unwrap_or(String::from("")),
            opts.netmask.unwrap_or(String::from(""))
        );
        let contents = format!("{}\n{}", topology, ipconfig);
        let mut fname = ccd.unwrap_or_else(|| String::from("/tmp/"));
        if fname.ends_with("/") {
            fname = format!("{}{}", fname, username);
        } else {
            fname = format!("{}/{}", fname, username);
        }
        match std::fs::write(&fname, &contents) {
            Ok(_v) => {}
            Err(e) => {
                slog::error!(logger, "Can't write to {}. {}", &fname, e);
            }
        };
    }
}
