{ pkgs ? import <nixpkgs> { }, lib ? pkgs.lib, rustPlatform ? pkgs.rustPlatform
}:

rustPlatform.buildRustPackage {
  pname = "tailpam";
  version = "devel";

  src = ./.;

  buildInputs = with pkgs; [ pkg-config pam ];
  doCheck = false;

  cargoSha256 = "092asql8l6396hhz8dd167lzn5h59d1wyz1z6yil787dvg21gv4z";
}
