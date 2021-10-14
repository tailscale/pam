use log::LevelFilter;
use std::net::IpAddr;
use syslog::{BasicLogger, Facility, Formatter3164};

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
}

pub type Result<T = ()> = std::result::Result<T, Error>;

fn syslog() {
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

pub fn auth(cfg: Config) -> Result {
    syslog();
    let mut status = tailscale::Status::get()?;

    // It's probably okay to trust yourself
    status
        .peer
        .insert(status.myself.public_key.clone(), status.myself.clone());

    for (_, peer) in &status.peer {
        for ip in &peer.tailscale_ips {
            if &cfg.rhost == ip {
                if let Some(user) = status.get_peer_user(peer.user_id) {
                    log::info!("{} is authing as {}", user.login_name, cfg.user);
                    return Ok(());
                }
            }
        }
    }

    Err(Error::UnknownIP(cfg.rhost))
}
