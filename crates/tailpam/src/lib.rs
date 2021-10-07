use std::net::IpAddr;

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

pub fn auth(cfg: Config) -> Result {
    let mut status = tailscale::Status::get()?;

    // It's probably okay to trust yourself
    status
        .peer
        .insert(status.myself.public_key.clone(), status.myself.clone());

    for (_, peer) in &status.peer {
        for ip in &peer.tailscale_ips {
            if &cfg.rhost == ip {
                if let Some(user) = status.get_peer_user(peer.user_id) {
                    eprintln!("{} is authing as {}", user.login_name, cfg.user);
                    return Ok(());
                }
            }
        }
    }

    Err(Error::UnknownIP(cfg.rhost))
}
