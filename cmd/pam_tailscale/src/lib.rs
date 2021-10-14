#[macro_use]
extern crate log;

mod pam;

use std::convert::TryInto;
use std::net::IpAddr;
use syslog::{Facility, Formatter3164};

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

fn main() {
    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: "myprogram".into(),
        pid: 0,
    };

    match syslog::unix(formatter) {
        Err(e) => println!("impossible to connect to syslog: {:?}", e),
        Ok(mut writer) => {
            writer
                .err("hello world")
                .expect("could not write error message");
        }
    }
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
