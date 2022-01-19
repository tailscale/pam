mod pam;

use std::convert::TryInto;
use std::net::IpAddr;

pub use pam::{callbacks::*, set_user};
use pam::{get_rhost, get_user, PamResultCode};

macro_rules! pam_try {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => {
                ::log::error!("{:?}", e);
                return e;
            }
        }
    };
    ($e:expr, $err:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => {
                ::log::error!("{:?}", e);
                return $err;
            }
        }
    };
}

pub fn authenticate(pamh: pam::PamHandleT, _args: Vec<String>, _silent: bool) -> PamResultCode {
    tailpam::syslog();

    let user = pam_try!(get_user(pamh));
    let rhost = pam_try!(get_rhost(pamh));
    let raw_host: String = pam_try!(rhost.try_into(), PamResultCode::PAM_AUTH_ERR);
    let mut rhost: Result<IpAddr, std::io::Error> = raw_host
        .parse()
        .map_err(|x| std::io::Error::new(std::io::ErrorKind::Other, x))
        .into();
    if rhost.is_err() {
        rhost = dns_lookup::lookup_host(&raw_host).map(|x| x[0]).into();
    }
    let rhost: IpAddr = pam_try!(rhost, PamResultCode::PAM_AUTHTOK_ERR);

    let cfg = tailpam::Config { user, rhost };

    match tailpam::auth(cfg) {
        Ok(who) => {
            pam::info(
                pamh,
                format!(
                    "Welcome {}, you were authenticated using your Tailscale identity.\n\n",
                    who.user_profile.display_name
                ),
            )
            .unwrap();
            PamResultCode::PAM_SUCCESS
        }
        Err(why) => {
            log::error!("can't auth: {}", why);
            PamResultCode::PAM_AUTH_ERR
        }
    }
}
