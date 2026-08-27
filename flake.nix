{
  description = "yk-piv-age-keygen dev shell";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            python314
            uv
            pcsclite
            pkg-config
            swig
            yubikey-manager
          ];
          shellHook = ''
            export PKG_CONFIG_PATH="${pkgs.pcsclite}/lib/pkgconfig:$PKG_CONFIG_PATH"
            export LDFLAGS="-L${pkgs.pcsclite}/lib"
            export CFLAGS="-I${pkgs.pcsclite}/include"
            export LD_LIBRARY_PATH="${pkgs.pcsclite}/lib:$LD_LIBRARY_PATH"
          '';
        };
      }
    );
}
