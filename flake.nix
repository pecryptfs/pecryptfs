{
  description = "Somewhat Python incomplete reimplementation of eCryptfs";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    nix.inputs.nixpkgs.follows = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nix, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in rec {
        packages = flake-utils.lib.flattenTree {
          pecryptfs = pkgs.python3Packages.buildPythonPackage rec {
            pname = "pecryptfs";
            version = "0.1.0";
            src = nixpkgs.lib.cleanSource ./.;
            nativeBuildInputs = with pkgs.python3.pkgs; [
            ];
            propagatedBuildInputs = with pkgs.python3.pkgs; [
              pycrypto
            ];
           };
        };
        defaultPackage = packages.pecryptfs;
      });
}
