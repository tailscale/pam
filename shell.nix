{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    rustc
    cargo
    rustfmt
    rust-analyzer
    rls

    # system deps
    pkg-config
  ];

  PAM_USER = "xe";
  PAM_RHOST = "100.127.23.80";
}
