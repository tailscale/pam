# Experimental Tailscale PAM Module

[![status: experimental](https://img.shields.io/badge/status-experimental-blue)](https://tailscale.com/kb/1167/release-stages/#experimental)

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
   get away with using [rustup](https://rustup.rs/)).
1. On Ubuntu run this command: `sudo apt-get install build-essential git
   libpam0g-dev`. On other distributions you will need to figure this out on
   your own.
1. Install `cargo-deb`: `cargo install cargo-deb`..
1. Build the debian package: `cargo-deb -p pam_tailscale`.
1. Install it on your target host.
1. Enable sshd ChallengeResponseAuthentication with this magic sed command:
   `sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config`.
1. Reload your sshd config: `systemctl reload sshd`.
1. SSH into your new machine!
