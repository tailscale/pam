use log::LevelFilter;
use std::net::{IpAddr, SocketAddr};
use syslog::{BasicLogger, Facility, Formatter3164};
use tailscale::WhoisResponse;

pub mod tailscale;

#[derive(serde::Deserialize)]
pub struct Config {
    pub user: String,
    pub rhost: IpAddr,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("unknown IP {0}")]
    UnknownIP(IpAddr),

    #[error("bad HTTP status: {0}")]
    HTTPStatus(#[from] tailscale::StatusError),

    #[error("curl error: {0}")]
    Curl(#[from] curl::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("url parse error: {0}")]
    URLParse(#[from] url::ParseError),
}

pub type Result<T = ()> = std::result::Result<T, Error>;

pub fn syslog() {
    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: "pam_tailscale".into(),
        pid: 0,
    };

    match syslog::unix(formatter) {
        Err(e) => println!("impossible to connect to syslog: {:?}", e),
        Ok(writer) => {
            if let Err(_) = log::set_boxed_logger(Box::new(BasicLogger::new(writer)))
                .map(|()| log::set_max_level(LevelFilter::Info))
            {}
        }
    }
}

pub fn auth(cfg: Config) -> Result<WhoisResponse> {
    let addr = SocketAddr::new(cfg.rhost, 0);

    let _status = tailscale::Status::get()?;

    let result = tailscale::WhoisResponse::get(addr).map_err(|err| {
        log::error!("can't get whois response: {}", err);
        Error::UnknownIP(addr.ip())
    })?;

    Ok(result)
}
