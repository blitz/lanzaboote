{ pkgs, lanzabooteModule }:
let
  inherit (pkgs) lib system;
  defaultTimeout = 5 * 60; # = 5 minutes
in
{
  mkSecureBootTest = { name, machine ? { }, useSecureBoot ? true, useTPM2 ? false, readEfiVariables ? false, testScript, extraNodes ? { } }:
    let
      tpmSocketPath = "/tmp/swtpm-sock";
      tpmDeviceModels = {
        x86_64-linux = "tpm-tis";
        aarch64-linux = "tpm-tis-device";
      };
      # Should go to nixpkgs.
      efiVariablesHelpers = ''
        import struct

        SD_LOADER_GUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
        def read_raw_variable(var: str) -> bytes:
            attr_var = machine.succeed(f"cat /sys/firmware/efi/efivars/{var}-{SD_LOADER_GUID}").encode('raw_unicode_escape')
            _ = attr_var[:4] # First 4 bytes are attributes according to https://www.kernel.org/doc/html/latest/filesystems/efivarfs.html
            value = attr_var[4:]
            return value
        def read_string_variable(var: str, encoding='utf-16-le') -> str:
            return read_raw_variable(var).decode(encoding).rstrip('\x00')
        # By default, it will read a 4 byte value, read `struct` docs to change the format.
        def assert_variable_uint(var: str, expected: int, format: str = 'I'):
            with subtest(f"Is `{var}` set to {expected} (uint)"):
              value, = struct.unpack(f'<{format}', read_raw_variable(var))
              assert value == expected, f"Unexpected variable value in `{var}`, expected: `{expected}`, actual: `{value}`"
        def assert_variable_string(var: str, expected: str, encoding='utf-16-le'):
            with subtest(f"Is `{var}` correctly set"):
                value = read_string_variable(var, encoding)
                assert value == expected, f"Unexpected variable value in `{var}`, expected: `{expected.encode(encoding)!r}`, actual: `{value.encode(encoding)!r}`"
        def assert_variable_string_contains(var: str, expected_substring: str):
            with subtest(f"Do `{var}` contain expected substrings"):
                value = read_string_variable(var).strip()
                assert expected_substring in value, f"Did not find expected substring in `{var}`, expected substring: `{expected_substring}`, actual value: `{value}`"
      '';
      tpm2Initialization = ''
        import subprocess
        from tempfile import TemporaryDirectory

        # From systemd-initrd-luks-tpm2.nix
        class Tpm:
            def __init__(self):
                self.state_dir = TemporaryDirectory()
                self.start()

            def start(self):
                self.proc = subprocess.Popen(["${pkgs.swtpm}/bin/swtpm",
                    "socket",
                    "--tpmstate", f"dir={self.state_dir.name}",
                    "--ctrl", "type=unixio,path=${tpmSocketPath}",
                    "--tpm2",
                    ])

                # Check whether starting swtpm failed
                try:
                    exit_code = self.proc.wait(timeout=0.2)
                    if exit_code is not None and exit_code != 0:
                        raise Exception("failed to start swtpm")
                except subprocess.TimeoutExpired:
                    pass

            """Check whether the swtpm process exited due to an error"""
            def check(self):
                exit_code = self.proc.poll()
                if exit_code is not None and exit_code != 0:
                  raise Exception("swtpm process died")

        tpm = Tpm()

        @polling_condition
        def swtpm_running():
          tpm.check()
      '';
    in
    pkgs.nixosTest {
      inherit name;
      globalTimeout = defaultTimeout;

      testScript = { ... }@args:
        let
          testScript' = if lib.isFunction testScript then testScript args else testScript;
        in
        ''
          ${lib.optionalString useTPM2 tpm2Initialization}
          ${lib.optionalString readEfiVariables efiVariablesHelpers}
          ${testScript'}
        '';


      nodes = extraNodes // {
        machine = { lib, ... }: {
          imports = [
            lanzabooteModule
            machine
          ];

          virtualisation = {
            useBootLoader = true;
            useEFIBoot = true;

            # We actually only want to enable features in OVMF, but at
            # the moment edk2 202308 is also broken. So we downgrade it
            # here as well. How painful!
            #
            # See #240.
            efi.OVMF =
              let
                edk2Version = "202305";
                edk2Src = pkgs.fetchFromGitHub {
                  owner = "tianocore";
                  repo = "edk2";
                  rev = "edk2-stable${edk2Version}";
                  fetchSubmodules = true;
                  hash = "sha256-htOvV43Hw5K05g0SF3po69HncLyma3BtgpqYSdzRG4s=";
                };

                edk2 = pkgs.edk2.overrideAttrs (old: rec {
                  version = edk2Version;
                  src = edk2Src;
                });
              in
              (pkgs.OVMF.override {
                secureBoot = useSecureBoot;
                tpmSupport = useTPM2; # This is needed otherwise OVMF won't initialize the TPM2 protocol.

                edk2 = edk2;
              }).overrideAttrs (old: {
                src = edk2Src;
              });

            qemu.options = lib.mkIf useTPM2 [
              "-chardev socket,id=chrtpm,path=${tpmSocketPath}"
              "-tpmdev emulator,id=tpm_dev_0,chardev=chrtpm"
              "-device ${tpmDeviceModels.${system}},tpmdev=tpm_dev_0"
            ];

            inherit useSecureBoot;
          };

          boot.initrd.availableKernelModules = lib.mkIf useTPM2 [ "tpm_tis" ];

          boot.loader.efi = {
            canTouchEfiVariables = true;
          };
          boot.lanzaboote = {
            enable = true;
            enrollKeys = lib.mkDefault true;
            pkiBundle = ./fixtures/uefi-keys;
          };
        };
      };
    };

}
