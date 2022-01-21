# Experimental Tailscale PAM Module

This is a very very experimental Tailscale
[PAM](https://en.wikipedia.org/wiki/Linux_PAM) module that allows you to SSH
using your Tailscale credentials. This is a response to
[tailscale/tailscale#3006](https://github.com/tailscale/tailscale/issues/3006).

# <big> DO NOT USE THIS IN PRODUCTION YET </big>

This code is unaudited, not fully tested and is not known to be secure. This is
currently a proof of concept and is not made with the intent to be used yet.

Enjoy this preview into the future of auth.

## Installation Instructions

1. Install Rust through your favorite method (most of the time you can probably
   get away with using [rustup](https://rustup.rs/))
1. On Ubuntu run this command: `sudo apt-get install build-essential git libpam0g-dev`
1. Clone this repo and run `cargo build --release`
1. Copy `./target/release/libpam_tailscale.so` to
   `/lib/security/pam_tailscale.so` (or wherever your distro of choice puts
   these things)
1. Add the following to the base login path for your distro's PAM configuration:
   `auth    sufficient      pam_tailscale.so`
1. SSH into your machine as normal
