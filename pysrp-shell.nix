{ ghc ? (import ./dev.nix).compiler-nix-name }:
let
  pkgs    = import ./h8x.nix;
  project = import ./default.nix { inherit ghc; };
  python  = pkgs.python3.withPackages (ps: [ ps.srp ]);
in
  project.shellFor {
    withHaddock = false;
    withHoogle  = false;
    tools       = { cabal = "latest"; };
    buildInputs = [ python ];
    exactDeps   = true;
  }
