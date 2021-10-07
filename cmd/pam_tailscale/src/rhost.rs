use pam::constants::{PamItemType, PAM_RHOST};
use pam::module::PamItem;
use std::convert::TryInto;
use std::ffi::CStr;
use std::os::raw::c_char;

/// A wrapper struct to try and coerce C into giving us the right type.
pub struct RHost(*const c_char);

impl TryInto<String> for &RHost {
    type Error = String;

    fn try_into(self) -> Result<String, Self::Error> {
        let c_str: &CStr = unsafe { CStr::from_ptr(self.0) };
        let str_slice: &str = c_str.to_str().map_err(|why| format!("{}", why))?;
        let str_buf: String = str_slice.to_owned();
        Ok(str_buf)
    }
}

impl PamItem for RHost {
    fn item_type() -> PamItemType {
        PAM_RHOST
    }
}
