{
  description = "A portable configured shell environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    {
      flake-parts,
      nixpkgs,
      ...
    }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem =
        { system, ... }:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          packages = {
            default = (
              pkgs.symlinkJoin {
                name = "clix";
                buildInputs = [ pkgs.makeWrapper ];
                paths = with pkgs; [
                  fish
                  nushell
                  tmux
                  tmuxPlugins.better-mouse-mode
                  bat
                  broot
                  tree
                  pstree
                ];
                postBuild = ''
                  wrapProgram $out/bin/bat --add-flags "--theme 1337 --style header"
                  wrapProgram $out/bin/fish --add-flags "--init-command 'fish_config theme choose Bay\ Cruise'" 
                  wrapProgram $out/bin/tmux --add-flags "-f ${./config/tmux.conf} -L clix"
                '';
              }
            );
          };
        };
    };
}
