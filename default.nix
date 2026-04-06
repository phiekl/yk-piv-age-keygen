{
  pkgs ? import <nixpkgs> {},
  yubikey-manager ? pkgs.yubikey-manager,
  python3Packages ? pkgs.python3Packages,
  buildPythonPackage ? python3Packages.buildPythonPackage,
  uv-build ? python3Packages.uv-build,
  cryptography ? python3Packages.cryptography,

  ...
}: let project = (builtins.fromTOML (builtins.readFile ./pyproject.toml)).project; in
buildPythonPackage rec {
  pname = "yk-piv-age-keygen";
  inherit (project) version;


  pyproject = true;

  build-system = [uv-build];

  dependencies = [yubikey-manager cryptography];

  src = ./.;

  postPatch = ''
    substituteInPlace pyproject.toml \
      --replace-fail "uv_build>=0.9.26,<0.10.0" "uv_build>=0.9.2" \
      --replace-fail "cryptography==43.0.0" "cryptography>=43.0.0"
  '';
}