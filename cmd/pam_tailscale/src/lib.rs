#[macro_use]
extern crate pam;

use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};
use std::collections::HashMap;
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr};

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

struct PamTailscale;
pam_hooks!(PamTailscale);

impl PamHooks for PamTailscale {
    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let args: Vec<_> = args
            .iter()
            .map(|s| s.to_string_lossy().to_owned())
            .collect();
        let _args: HashMap<&str, &str> = args
            .iter()
            .map(|s| {
                let mut parts = s.splitn(2, "=");
                (parts.next().unwrap(), parts.next().unwrap_or(""))
            })
            .collect();

        let user = pam_try!(pamh.get_user(None));

        let cfg = tailpam::Config {
            user,
            rhost: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        };

        match tailpam::auth(cfg) {
            Ok(_) => PamResultCode::PAM_SUCCESS,
            Err(why) => {
                println!("can't auth: {}", why);
                PamResultCode::PAM_AUTH_ERR
            }
        }
    }

    fn sm_setcred(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}
