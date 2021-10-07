use std::process;
use tailpam::{auth, Config};

fn main() {
    let cfg: Config = envy::prefixed("PAM_").from_env().unwrap();

    match auth(cfg) {
        Ok(_) => process::exit(0),
        Err(why) => {
            eprintln!("error doing auth: {}", why);
            process::exit(1)
        }
    }
}
