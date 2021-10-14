mod pam;

use std::convert::TryInto;
use std::net::IpAddr;

pub use pam::{callbacks::*, set_user};
use pam::{get_rhost, get_user, PamResultCode};

macro_rules! pam_try {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
    ($e:expr, $err:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => {
                println!("Error: {}", e);
                return $err;
            }
        }
    };
}

pub fn acct_mgmt(pamh: pam::PamHandleT, _args: Vec<String>, _silent: bool) -> PamResultCode {
    let user = pam_try!(get_user(pamh));
    let rhost = pam_try!(get_rhost(pamh));
    let rhost: String = pam_try!(rhost.try_into(), PamResultCode::PAM_AUTH_ERR);
    let rhost: IpAddr = pam_try!(rhost.parse(), PamResultCode::PAM_AUTHTOK_ERR);

    let cfg = tailpam::Config { user, rhost };

    match tailpam::auth(cfg) {
        Ok(_) => PamResultCode::PAM_SUCCESS,
        Err(why) => {
            println!("can't auth: {}", why);
            PamResultCode::PAM_AUTH_ERR
        }
    }
}
