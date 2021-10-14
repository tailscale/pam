use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr;

pub type PamHandleT = *const c_uint;
pub type PamFlags = c_uint;
pub type PamResult<T> = Result<T, PamResultCode>;

pub const PAM_SILENT: PamFlags = 0x8000;

/// Gets the username that is currently authenticating out of the pam handle.
///
/// # Safety
///
/// This casts the string directly from C space into Rust space. It relies on
/// PAM doing things properly. Invalid UTF-8 will be pruned from the result.
pub fn get_user(pamh: PamHandleT) -> PamResult<String> {
    get_item(pamh, PamItemType::PAM_USER).map(|u| unsafe {
        CStr::from_ptr(u as *const i8)
            .to_string_lossy()
            .into_owned()
    })
}

/// Gets the remote host out of the pam handle.
///
/// # Safety
///
/// This casts the string directly from C space into Rust space. It relies on
/// PAM doing things properly. Invalid UTF-8 will be pruned from the result.
pub fn get_rhost(pamh: PamHandleT) -> PamResult<String> {
    get_item(pamh, PamItemType::PAM_RHOST).map(|u| unsafe {
        CStr::from_ptr(u as *const i8)
            .to_string_lossy()
            .into_owned()
    })
}

pub fn set_user(pamh: PamHandleT, username: String) -> PamResult<()> {
    let user_string = CString::new(username).unwrap();
    let byte_string = user_string.as_bytes_with_nul();
    set_item(
        pamh,
        PamItemType::PAM_USER,
        byte_string.as_ptr() as *const c_void,
    )
}

fn set_item(pamh: PamHandleT, item_type: PamItemType, item: *const c_void) -> PamResult<()> {
    let r = unsafe { pam_set_item(pamh, item_type, item) };
    match r {
        PamResultCode::PAM_SUCCESS => Ok(()),
        _ => Err(r),
    }
}

fn get_item(pamh: PamHandleT, item_type: PamItemType) -> PamResult<*const c_void> {
    let mut raw_item: *const c_void = ptr::null();
    let r = unsafe { pam_get_item(pamh, item_type, &mut raw_item) };
    if raw_item.is_null() {
        Err(r)
    } else {
        Ok(raw_item)
    }
}

fn extract_argv(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    (0..argc)
        .map(|o| unsafe {
            CStr::from_ptr(*argv.offset(o as isize) as *const c_char)
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

#[test]
fn test_extract_argv() {
    let argc: c_int = 3;
    let one = CString::new("one").unwrap();
    let two = CString::new("two").unwrap();
    let three = CString::new("three").unwrap();

    let argv: *const *const c_char = [one.as_ptr(), two.as_ptr(), three.as_ptr()].as_ptr();
    let expected = vec![
        String::from("one"),
        String::from("two"),
        String::from("three"),
    ];
    assert_eq!(extract_argv(argc, argv), expected);
}

#[link(name = "pam")]
extern "C" {
    fn pam_set_item(pamh: PamHandleT, item_type: PamItemType, item: *const c_void)
        -> PamResultCode;
    fn pam_get_item(
        pamh: PamHandleT,
        item_type: PamItemType,
        item: *mut *const c_void,
    ) -> PamResultCode;
}

#[allow(non_camel_case_types, dead_code)]
#[derive(Debug)]
#[repr(C)]
pub enum PamItemType {
    PAM_SERVICE = 1,
    PAM_USER = 2,
    PAM_TTY = 3,
    PAM_RHOST = 4,
    PAM_CONV = 5,
    PAM_AUTHTOK = 6,
    PAM_OLDAUTHTOK = 7,
    PAM_RUSER = 8,
    PAM_USER_PROMPT = 9,
    PAM_FAIL_DELAY = 10,
    PAM_XDISPLAY = 11,
    PAM_XAUTHDATA = 12,
    PAM_AUTHTOK_TYPE = 13,
}

#[allow(non_camel_case_types, dead_code)]
#[derive(Debug)]
#[repr(C)]
pub enum PamResultCode {
    PAM_SUCCESS = 0,
    PAM_OPEN_ERR = 1,
    PAM_SYMBOL_ERR = 2,
    PAM_SERVICE_ERR = 3,
    PAM_SYSTEM_ERR = 4,
    PAM_BUF_ERR = 5,
    PAM_PERM_DENIED = 6,
    PAM_AUTH_ERR = 7,
    PAM_CRED_INSUFFICIENT = 8,
    PAM_AUTHINFO_UNAVAIL = 9,
    PAM_USER_UNKNOWN = 10,
    PAM_MAXTRIES = 11,
    PAM_NEW_AUTHTOK_REQD = 12,
    PAM_ACCT_EXPIRED = 13,
    PAM_SESSION_ERR = 14,
    PAM_CRED_UNAVAIL = 15,
    PAM_CRED_EXPIRED = 16,
    PAM_CRED_ERR = 17,
    PAM_NO_MODULE_DATA = 18,
    PAM_CONV_ERR = 19,
    PAM_AUTHTOK_ERR = 20,
    PAM_AUTHTOK_RECOVERY_ERR = 21,
    PAM_AUTHTOK_LOCK_BUSY = 22,
    PAM_AUTHTOK_DISABLE_AGING = 23,
    PAM_TRY_AGAIN = 24,
    PAM_IGNORE = 25,
    PAM_ABORT = 26,
    PAM_AUTHTOK_EXPIRED = 27,
    PAM_MODULE_UNKNOWN = 28,
    PAM_BAD_ITEM = 29,
    PAM_CONV_AGAIN = 30,
    PAM_INCOMPLETE = 31,
}

pub mod callbacks {
    use super::super::authenticate;
    use super::*;

    #[no_mangle]
    pub extern "C" fn pam_sm_acct_mgmt(
        _: PamHandleT,
        _: PamFlags,
        _: c_int,
        _: *const *const c_char,
    ) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    #[no_mangle]
    pub extern "C" fn pam_sm_authenticate(
        pamh: PamHandleT,
        flags: PamFlags,
        argc: c_int,
        argv: *const *const c_char,
    ) -> PamResultCode {
        let args = extract_argv(argc, argv);
        let silent = (flags & PAM_SILENT) != 0;
        authenticate(pamh, args, silent)
    }

    #[no_mangle]
    pub extern "C" fn pam_sm_chauthtok(
        _: PamHandleT,
        _: PamFlags,
        _: c_int,
        _: *const *const c_char,
    ) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    #[no_mangle]
    pub extern "C" fn pam_sm_close_session(
        _: PamHandleT,
        _: PamFlags,
        _: c_int,
        _: *const *const c_char,
    ) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    #[no_mangle]
    pub extern "C" fn pam_sm_open_session(
        _: PamHandleT,
        _: PamFlags,
        _: c_int,
        _: *const *const c_char,
    ) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    #[no_mangle]
    pub extern "C" fn pam_sm_setcred(
        _: PamHandleT,
        _: PamFlags,
        _: c_int,
        _: *const *const c_char,
    ) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }
}
