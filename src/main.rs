use std::{error::Error, fmt, net::IpAddr, process};

mod tailscale;

#[derive(serde::Deserialize)]
pub struct Config {
    pub user: String,
    pub rhost: IpAddr,
}

fn main() {
    match do_auth() {
        Ok(_) => process::exit(0),
        Err(why) => {
            eprintln!("error doing auth: {}", why);
            process::exit(1)
        }
    }
}

fn do_auth() -> anyhow::Result<()> {
    let cfg: Config = envy::prefixed("PAM_").from_env()?;
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

    Err(UnknownIP {
        ip: cfg.rhost.to_string(),
    }
    .into())
}

#[derive(Debug)]
struct UnknownIP {
    ip: String,
}

impl fmt::Display for UnknownIP {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unknown IP {}", self.ip)
    }
}

impl Error for UnknownIP {}
