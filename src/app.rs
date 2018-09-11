use std::env;

pub const APP_NAME: &str = "firestarter";
pub const APP_NAME_UPPER: &str = "FIRESTARTER";

pub fn get_app_name() -> String {
    match env::var("FIRESTARTER_APP_NAME") {
        Ok(val) => val,
        Err(_) => APP_NAME.to_owned()
    }
}
