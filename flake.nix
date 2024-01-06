{
  description = "Secure Boot for NixOS";

  inputs = {
    nixpkgs.url = "github:RaitoBezarius/nixpkgs/initrd-secrets";

    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";

    pre-commit-hooks-nix = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
      inputs.flake-compat.follows = "flake-compat";
    };

    # We only have this input to pass it to other dependencies and
    # avoid having multiple versions in our dependencies.
    flake-utils.url = "github:numtide/flake-utils";

    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };

    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = inputs@{ self, nixpkgs, crane, rust-overlay, flake-parts, ... }:
    let
      # Systems supported in CI
      supportedSystems = [ "x86_64-linux" ];
      fixupFlakes = outputs: nixpkgs.lib.updateManyAttrsByPath [
        # Apply post-flakeparts massaging for limited supported systems, e.g. systems for which
        # we don't have KVM support and cannot test in CI, but we still can meaningfully
        # build packages.
        {
          path = [ "checks" ];
          update = nixpkgs.lib.filterAttrs (name: _: builtins.elem name supportedSystems);
        }
      ]
        outputs;
    in
    fixupFlakes (flake-parts.lib.mkFlake { inherit inputs; } ({ moduleWithSystem, ... }: {
      imports = [
        # Derive the output overlay automatically from all packages that we define.
        inputs.flake-parts.flakeModules.easyOverlay

        # Formatting and quality checks.
        inputs.pre-commit-hooks-nix.flakeModule
      ];

      flake.nixosModules.lanzaboote = moduleWithSystem (
        perSystem@{ config }:
        { ... }: {
          imports = [
            ./nix/modules/lanzaboote.nix
          ];

          boot.lanzaboote.package = perSystem.config.packages.tool;
        }
      );

      flake.nixosModules.lanzasignd = moduleWithSystem (
        perSystem@{ config }:
        { ... }: {
          imports = [
            ./nix/modules/lanzasignd.nix
          ];

          services.lanzasignd.package = perSystem.config.packages.lanzasignd;
        }
      );

      flake.nixosModules.uki = moduleWithSystem (
        perSystem@{ config }:
        { lib, ... }: {
          imports = [
            ./nix/modules/uki.nix
          ];

          boot.loader.uki.stub = lib.mkDefault "${perSystem.config.packages.fatStub}/bin/lanzaboote_stub.efi";
        }
      );

      systems = [
        "x86_64-linux"

        # Not actively tested, but may work:
        "aarch64-linux"
      ];

      perSystem = { config, system, pkgs, ... }:
        let
          rustTarget = "${pkgs.stdenv.hostPlatform.qemuArch}-unknown-uefi";
          pkgs = import nixpkgs {
            system = system;
            overlays = [
              rust-overlay.overlays.default
            ];
          };

          inherit (pkgs) lib;

          uefi-rust-stable = pkgs.rust-bin.fromRustupToolchainFile ./rust/uefi/rust-toolchain.toml;
          craneLib = crane.lib.${system}.overrideToolchain uefi-rust-stable;

          # Build attributes for a Rust application.
          buildRustApp = lib.makeOverridable (
            { pname
            , src
            , target ? null
            , doCheck ? true
              # By default, it builds the default members of the workspace.
            , packages ? null
            , extraArgs ? { }
            }:
            let
              commonArgs = {
                inherit pname;
                inherit src;
                CARGO_BUILD_TARGET = target;
                inherit doCheck;

                # Workaround for https://github.com/ipetkov/crane/issues/262.
                dummyrs = pkgs.writeText "dummy.rs" ''
                  #![allow(unused)]

                  #![cfg_attr(
                    any(target_os = "none", target_os = "uefi"),
                    no_std,
                    no_main,
                  )]

                  #[cfg_attr(any(target_os = "none", target_os = "uefi"), panic_handler)]
                  fn panic(_info: &::core::panic::PanicInfo<'_>) -> ! {
                      loop {}
                  }

                  #[cfg_attr(any(target_os = "none", target_os = "uefi"), export_name = "efi_main")]
                  fn main() {}
                '';

                cargoExtraArgs = (extraArgs.cargoExtraArgs or "") + (if packages != null then (lib.concatStringsSep " " (map (p: "--package ${p}") packages)) else "");
              } // builtins.removeAttrs extraArgs [ "cargoExtraArgs" ];

              cargoArtifacts = craneLib.buildDepsOnly commonArgs;
            in
            {
              package = craneLib.buildPackage (commonArgs // {
                inherit cargoArtifacts;
              });

              clippy = craneLib.cargoClippy (commonArgs // {
                inherit cargoArtifacts;
                cargoClippyExtraArgs = "-- --deny warnings";
              });

              rustfmt = craneLib.cargoFmt (commonArgs // { inherit cargoArtifacts; });
            }
          );

          stubCrane = buildRustApp {
            pname = "lanzaboote-stub";
            src = craneLib.cleanCargoSource ./rust/uefi;
            target = rustTarget;
            doCheck = false;
          };

          fatStubCrane = stubCrane.override {
            extraArgs = {
              cargoExtraArgs = "--no-default-features --features fat";
            };
          };

          lanzasigndCrane = buildRustApp {
            pname = "lanzasignd";
            src = craneLib.cleanCargoSource ./rust/tool;
            doCheck = false;
            packages = [ "lanzasignd" ];
          };

          lanzasignd = lanzasigndCrane.package;
          stub = stubCrane.package;
          fatStub = fatStubCrane.package;

          # TODO: when we will have more backends
          # let's generalize this properly.
          toolCrane = buildRustApp {
            pname = "lzbt-systemd";
            src = ./rust/tool;
            extraArgs = {
              TEST_SYSTEMD = pkgs.systemd;
              nativeCheckInputs = with pkgs; [
                binutils-unwrapped
                sbsigntool
              ];
            };
          };

          tool = toolCrane.package;

          wrappedTool = pkgs.runCommand "lzbt"
            {
              nativeBuildInputs = [ pkgs.makeWrapper ];
            } ''
            mkdir -p $out/bin

            # Clean PATH to only contain what we need to do objcopy. Also
            # tell lanzatool where to find our UEFI binaries.
            makeWrapper ${tool}/bin/lzbt-systemd $out/bin/lzbt \
              --set PATH ${lib.makeBinPath [ pkgs.binutils-unwrapped pkgs.sbsigntool ]} \
              --set LANZABOOTE_STUB ${stub}/bin/lanzaboote_stub.efi
          '';
        in
        {
          packages = {
            inherit stub fatStub lanzasignd;
            tool = wrappedTool;
            lzbt = wrappedTool;
          };

          overlayAttrs = {
            inherit (config.packages) tool lanzasignd;
          };

          checks =
            let
              nixosLib = import (pkgs.path + "/nixos/lib") { };
              lanzaLib = import ./nix/tests/lib.nix {
                inherit pkgs;
                lanzabooteModule = self.nixosModules.lanzaboote;
              };
              runTest = module: nixosLib.runTest {
                imports = [ module ];
                hostPkgs = pkgs;
              };
            in
            {
              toolClippy = toolCrane.clippy;
              stubClippy = stubCrane.clippy;
              fatStubClippy = fatStubCrane.clippy;
              toolFmt = toolCrane.rustfmt;
              stubFmt = stubCrane.rustfmt;
            } // (import ./nix/tests/lanzaboote.nix {
              inherit pkgs lanzaLib;
              lanzabooteModule = self.nixosModules.lanzaboote;
            }) // (import ./nix/tests/stub.nix {
              inherit pkgs runTest;
              ukiModule = self.nixosModules.uki;
            }) // (import ./nix/tests/remote-signing.nix {
              inherit pkgs lanzaLib;
              lanzasigndModule = self.nixosModules.lanzasignd;
            });

          pre-commit = {
            check.enable = true;

            settings.hooks = {
              nixpkgs-fmt.enable = true;
              typos.enable = true;
            };
          };

          devShells.default = pkgs.mkShell {
            shellHook = ''
              ${config.pre-commit.installationScript}
            '';

            packages = [
              pkgs.nixpkgs-fmt
              pkgs.statix
              pkgs.cargo-release
              pkgs.cargo-machete

              # This is a special script to print out all the offsets
              # related to OVMF debug binaries.
              # To use it, you should obtain a debug log (serial console or the 0x402 port)
              # It contains various offsets necessary to relocate all the offsets.
              # Then, you need a OVMF tree, you can bring yours or put it in the Nix one.
              # Once you are done, you can pipe the result of that script in /tmp/gdb-script or something like that.
              # You can source it with gdb, then you should use `set substitute-paths /build/edk2... /nix/store/...edk2/...`
              # to rewire the EDK2 source tree to the Nix store.
              # Usage: `print-debug-script-for-ovmf $location_of_ovmf_debug_output $location_of_edk2_debug_outputs_in_nix_store > /tmp/gdbscript`
              (pkgs.writeScriptBin "print-debug-script-for-ovmf"
                (
                  let
                    pePythonEnv = pkgs.python3.withPackages (ps: with ps; [ pefile ]);
                  in
                  ''
                    #!${pkgs.stdenv.shell}
                    LOG=''${1:-build/debug.log}
                    BUILD=''${2}
                    SEARCHPATHS="''${BUILD}"

                    cat ''${LOG} | grep Loading | grep -i efi | while read LINE; do
                      BASE="`echo ''${LINE} | cut -d " " -f4`"
                      NAME="`echo ''${LINE} | cut -d " " -f6 | tr -d "[:cntrl:]"`"
                      EFIFILE="`find ''${SEARCHPATHS} -name ''${NAME} -maxdepth 1 -type f`"
                      ADDR="`${pePythonEnv}/bin/python3 contrib/extract_text_va.py ''${EFIFILE} 2>/dev/null`"
                      [ ! -z "$ADDR" ] && TEXT="`${pkgs.python3}/bin/python -c "print(hex(''${BASE} + ''${ADDR}))"`"
                      SYMS="`echo ''${NAME} | sed -e "s/\.efi/\.debug/g"`"
                      SYMFILE="`find ''${SEARCHPATHS} -name ''${SYMS} -maxdepth 1 -type f`"
                      [ ! -z "$ADDR" ] && echo "add-symbol-file ''${SYMFILE} ''${TEXT}"
                    done
                  ''
                )
              )

              # Convenience for test fixtures in nix/tests.
              pkgs.openssl
              (pkgs.sbctl.override { databasePath = "pki"; })

              # Needed for `cargo test` in rust/tool. We also need
              # TEST_SYSTEMD below for that.
              pkgs.sbsigntool
            ];

            inputsFrom = [
              config.packages.stub
              config.packages.tool
            ];

            TEST_SYSTEMD = pkgs.systemd;
          };
        };
    }));
}
