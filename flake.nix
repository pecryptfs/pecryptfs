{
  description = "Somewhat Python incomplete reimplementation of eCryptfs";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        pythonPackages = pkgs.python310Packages;
      in rec {
        packages = flake-utils.lib.flattenTree rec {
          pecryptfs = pythonPackages.buildPythonPackage rec {
            pname = "pecryptfs";
            version = "0.1.0";
            src = nixpkgs.lib.cleanSource ./.;
            propagatedBuildInputs = with pythonPackages; [
              pycrypto
            ];
            checkInputs = (with pkgs; [
              pyright
            ]) ++ (with pythonPackages; [
              flake8
              mypy
              pylint
              types-setuptools
            ]);
            checkPhase = ''
              runHook preCheck
              flake8 pecryptfs tests
              # pyright pecryptfs tests
              # mypy pecryptfs tests
              # pylint pecryptfs tests
              python3 -m unittest discover -v -s tests/
              runHook postCheck
            '';
          };
          default = pecryptfs;
        };
      }
    );
}
