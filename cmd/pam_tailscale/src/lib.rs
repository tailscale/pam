mod pam;

use std::convert::TryInto;
use std::net::IpAddr;

pub use pam::{callbacks::*, set_user};
use pam::{get_rhost, get_user, PamResultCode};

pub fn authenticate(
    pamh: pam::PamHandleT,
    _args: Vec<String>,
    _silent: bool,
) -> pam::PamResult<()> {
    tailpam::syslog();

    let user = get_user(pamh)?;
    let rhost = get_rhost(pamh)?;
    let raw_host: String = rhost
        .try_into()
        .map_err(|_| pam::PamResultCode::PAM_AUTH_ERR)?;
    let mut rhost: Result<IpAddr, std::io::Error> = raw_host
        .parse()
        .map_err(|x| std::io::Error::new(std::io::ErrorKind::Other, x))
        .into();
    if rhost.is_err() {
        rhost = dns_lookup::lookup_host(&raw_host).map(|x| x[0]).into();
    }
    let rhost: IpAddr = rhost.map_err(|why| {
        log::error!("error getting rhost: {}", why);
        pam::PamResultCode::PAM_AUTH_ERR
    })?;

    let cfg = tailpam::Config { user, rhost };

    match tailpam::auth(cfg) {
        Ok(who) => {
            pam::info(
                pamh,
                format!(
                    "Welcome {}, you were authenticated using your Tailscale identity.\n\n",
                    who.user_profile.display_name
                ),
            )?;
            Ok(())
        }
        Err(why) => {
            log::error!("can't auth: {}", why);
            Err(PamResultCode::PAM_AUTH_ERR)
        }
    }
}
