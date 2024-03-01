{ pkgs
, lanzabooteModule
}:

let
  inherit (pkgs) lib system runCommand;
  defaultTimeout = 5 * 60; # = 5 minutes

  inherit (pkgs.stdenv.hostPlatform) efiArch;
  efiArchUppercased = lib.toUpper efiArch;

  mkSecureBootTest = { name, machine ? { }, useSecureBoot ? true, useTPM2 ? false, readEfiVariables ? false, testScript }:
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

      testScript = ''
        ${lib.optionalString useTPM2 tpm2Initialization}
        ${lib.optionalString readEfiVariables efiVariablesHelpers}

        def is_guest_induced_reset(event):
            return event['event'] == 'SHUTDOWN' and event.get('data', {}).get('reason') == 'guest-reset'

        machine.start()
        if machine.qmp_client is None:
          import sys; sys.exit(1)

        # We expect a shutdown for guest-reset reasons.
        print('Waiting for a guest-reset...')
        machine.wait_for_qmp_event(is_guest_induced_reset)
        print('Shutdown detected.')

        machine.booted = False
        machine.start()
        ${testScript}
      '';

      nodes.machine = { pkgs, lib, ... }: {
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
          # Under aarch64, various things goes wrong...
          settings.secure-boot-enroll = lib.mkIf pkgs.hostPlatform.isAarch64 "force";
          safeAutoEnroll =
            let
              signVariable = varName:
                let
                  GUID = ./fixtures/uefi-keys/GUID;
                  publicKey = ./fixtures/uefi-keys/keys/${varName}/${varName}.pem;
                  privateKey = ./fixtures/uefi-keys/keys/${varName}/${varName}.key;
                in
                runCommand "sign-${varName}-via-snakeoil-pki"
                  {
                    nativeBuildInputs = [ pkgs.efitools ];
                  } ''
                  cert-to-efi-sig-list -g ${GUID} ${publicKey} ${varName}.esl
                  sign-efi-sig-list -t "$(date --date '@1' '+%Y-%m-%d %H:%M:%S')" \
                    -k ${privateKey} -c ${publicKey} ${varName} ${varName}.esl ${varName}.auth

                  mv ${varName}.auth $out
                '';
            in
            {
              db = signVariable "db";
              KEK = signVariable "KEK";
              PK = signVariable "PK";
            };
          pkiBundle = ./fixtures/uefi-keys;
        };
      };
    };

  # Execute a boot test that has an intentionally broken secure boot
  # chain. This test is expected to fail with Secure Boot and should
  # succeed without.
  #
  # Takes a set `path` consisting of a `src` and a `dst` attribute. The file at
  # `src` is copied to `dst` inside th VM. Optionally append some random data
  # ("crap") to the end of the file at `dst`. This is useful to easily change
  # the hash of a file and produce a hash mismatch when booting the stub.
  mkHashMismatchTest = { name, appendCrapGlob, useSecureBoot ? true }: mkSecureBootTest {
    inherit name;
    inherit useSecureBoot;

    testScript = ''
      machine.start()
      machine.succeed("echo some_garbage_to_change_the_hash | tee -a ${appendCrapGlob} > /dev/null")
      machine.succeed("sync")
      machine.crash()
      machine.start()
    '' + (if useSecureBoot then ''
      machine.wait_for_console_text("hash does not match")
    '' else ''
      # Just check that the system came up.
      print(machine.succeed("bootctl", timeout=120))
    '');
  };

  # The initrd is not directly signed. Its hash is embedded into
  # lanzaboote. To make integrity verification fail, we actually have
  # to modify the initrd. Appending crap to the end is a harmless way
  # that would make the kernel still accept it.
  mkModifiedInitrdTest = { name, useSecureBoot }: mkHashMismatchTest {
    inherit name useSecureBoot;
    appendCrapGlob = "/boot/EFI/nixos/initrd-*.efi";
  };

  mkModifiedKernelTest = { name, useSecureBoot }: mkHashMismatchTest {
    inherit name useSecureBoot;
    appendCrapGlob = "/boot/EFI/nixos/kernel-*.efi";
  };

in
{
  # TODO: user mode: OK
  # TODO: how to get in: {deployed, audited} mode ?
  basic = mkSecureBootTest {
    name = "lanzaboote";
    testScript = ''
      assert "Secure Boot: enabled (user)" in machine.succeed("bootctl status")

      # We want systemd to recognize our PE binaries as true UKIs. systemd has
      # become more picky in the past, so make sure.
      assert "Kernel Type: uki" in machine.succeed("bootctl kernel-inspect /boot/EFI/Linux/nixos-generation-1-*.efi")
    '';
  };

  systemd-initrd = mkSecureBootTest {
    name = "lanzaboote-systemd-initrd";
    machine = { ... }: {
      boot.initrd.systemd.enable = true;
    };
    testScript = ''
      assert "Secure Boot: enabled (user)" in machine.succeed("bootctl status")
    '';
  };

  # Test that a secret is appended to the initrd during installation. Smilar to
  # the initrd-secrets test in Nixpkgs:
  # https://github.com/NixOS/nixpkgs/blob/master/nixos/tests/initrd-secrets.nix
  initrd-secrets =
    let
      secret = (pkgs.writeText "oh-so-secure" "uhh-ooh-uhh-security");
    in
    mkSecureBootTest {
      name = "lanzaboote-initrd-secrets";
      machine = { ... }: {
        boot.initrd.secrets = {
          "/test" = secret;
        };
        boot.initrd.postMountCommands = ''
          cp /test /mnt-root/secret-from-initramfs
        '';
      };
      testScript = ''
        machine.wait_for_unit("multi-user.target")

        machine.succeed("cmp ${secret} /secret-from-initramfs")
        assert "Secure Boot: enabled (user)" in machine.succeed("bootctl status")
      '';
    };

  # Test that the secrets configured to be appended to the initrd get updated
  # when installing a new generation even if the initrd itself (i.e. its store
  # path) does not change.
  #
  # An unfortunate result of this NixOS feature is that updating the secrets
  # without creating a new initrd might break previous generations. Verify that
  # a new initrd (which is supposed to only differ by the secrets) is created
  # in this case.
  #
  # This tests uses a specialisation to imitate a newer generation. This works
  # because `lzbt` installs the specialisation of a generation AFTER installing
  # the generation itself (thus making the specialisation "newer").
  initrd-secrets-update =
    let
      originalSecret = (pkgs.writeText "oh-so-secure" "uhh-ooh-uhh-security");
      newSecret = (pkgs.writeText "newly-secure" "so-much-better-now");
    in
    mkSecureBootTest {
      name = "lanzaboote-initrd-secrets-update";
      machine = { pkgs, lib, ... }: {
        boot.initrd.secrets = {
          "/test" = lib.mkDefault originalSecret;
        };
        boot.initrd.postMountCommands = ''
          cp /test /mnt-root/secret-from-initramfs
        '';

        specialisation.variant.configuration = {
          boot.initrd.secrets = {
            "/test" = newSecret;
          };
        };
      };
      testScript = ''
        machine.wait_for_unit("multi-user.target")

        # Assert that only three boot files exists (a single kernel and a two
        # initrds).
        assert int(machine.succeed("ls -1 /boot/EFI/nixos | wc -l")) == 3

        # It is expected that the initrd contains the original secret.
        machine.succeed("cmp ${originalSecret} /secret-from-initramfs")

        machine.succeed("bootctl set-default nixos-generation-1-specialisation-variant-\*.efi")
        machine.succeed("sync")
        machine.crash()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        # It is expected that the initrd of the specialisation contains the new secret.
        machine.succeed("cmp ${newSecret} /secret-from-initramfs")
      '';
    };

  modified-initrd-doesnt-boot-with-secure-boot = mkModifiedInitrdTest {
    name = "modified-initrd-doesnt-boot-with-secure-boot";
    useSecureBoot = true;
  };

  modified-initrd-boots-without-secure-boot = mkModifiedInitrdTest {
    name = "modified-initrd-boots-without-secure-boot";
    useSecureBoot = false;
  };

  modified-kernel-doesnt-boot-with-secure-boot = mkModifiedKernelTest {
    name = "modified-kernel-doesnt-boot-with-secure-boot";
    useSecureBoot = true;
  };

  modified-kernel-boots-without-secure-boot = mkModifiedKernelTest {
    name = "modified-kernel-boots-without-secure-boot";
    useSecureBoot = false;
  };

  specialisation-works = mkSecureBootTest {
    name = "specialisation-still-boot-under-secureboot";
    machine = { pkgs, ... }: {
      specialisation.variant.configuration = {
        environment.systemPackages = [
          pkgs.efibootmgr
        ];
      };
    };
    testScript = ''
      print(machine.succeed("ls -lah /boot/EFI/Linux"))
      # TODO: make it more reliable to find this filename, i.e. read it from somewhere?
      machine.succeed("bootctl set-default nixos-generation-1-specialisation-variant-\*.efi")
      machine.succeed("sync")
      machine.fail("efibootmgr")
      machine.crash()
      machine.start()
      print(machine.succeed("bootctl"))
      # Only the specialisation contains the efibootmgr binary.
      machine.succeed("efibootmgr")
    '';
  };

  # We test if we can install Lanzaboote without Bootspec support.
  synthesis =
    if pkgs.hostPlatform.isAarch64 then
    # FIXME: currently broken on aarch64
    #> mkfs.fat 4.2 (2021-01-31)
    #> setting up /etc...
    #> Enrolling keys to EFI variables...✓
    #> Enrolled keys to the EFI variables!
    #> Installing Lanzaboote to "/boot"...
    #> No bootable generations found! Aborting to avoid unbootable system. Please check for Lanzaboote updates!
    #> [ 2.788390] reboot: Power down
      pkgs.hello
    else
      mkSecureBootTest {
        name = "lanzaboote-synthesis";
        machine = { lib, ... }: {
          boot.bootspec.enable = lib.mkForce false;
        };
        testScript = ''
          assert "Secure Boot: enabled (user)" in machine.succeed("bootctl status")
        '';
      };

  systemd-boot-loader-config = mkSecureBootTest {
    name = "lanzaboote-systemd-boot-loader-config";
    machine = {
      boot.loader.timeout = 0;
      boot.loader.systemd-boot.consoleMode = "auto";
    };
    testScript = ''
      actual_loader_config = machine.succeed("cat /boot/loader/loader.conf").split("\n")
      expected_loader_config = ["timeout 0", "console-mode auto"]

      assert all(cfg in actual_loader_config for cfg in expected_loader_config), \
        f"Expected: {expected_loader_config} is not included in actual config: '{actual_loader_config}'"
    '';
  };

  export-efi-variables = mkSecureBootTest {
    name = "lanzaboote-exports-efi-variables";
    machine.environment.systemPackages = [ pkgs.efibootmgr ];
    readEfiVariables = true;
    testScript = ''
      # We will choose to boot directly on the stub.
      # To perform this trick, we will boot first with systemd-boot.
      # Then, we will add a new boot entry in EFI with higher priority
      # pointing to our stub.
      # Finally, we will reboot.
      # We will also assert that systemd-boot is not running
      # by checking for the sd-boot's specific EFI variables.
      # By construction, nixos-generation-1.efi is the stub we are interested in.
      # TODO: this should work -- machine.succeed("efibootmgr -d /dev/vda -c -l \\EFI\\Linux\\nixos-generation-1.efi") -- efivars are not persisted
      # across reboots atm?
      # cheat code no 1
      machine.succeed("cp /boot/EFI/Linux/nixos-generation-1-*.efi /boot/EFI/BOOT/BOOT${efiArchUppercased}.EFI")
      machine.succeed("cp /boot/EFI/Linux/nixos-generation-1-*.efi /boot/EFI/systemd/systemd-boot${efiArch}.efi")

      # Let's reboot.
      machine.succeed("sync")
      machine.crash()
      machine.start()

      # This is the sd-boot EFI variable indicator, we should not have it at this point.
      print(machine.execute("bootctl")[1]) # Check if there's incorrect value in the output.
      machine.succeed(
          "test -e /sys/firmware/efi/efivars/LoaderEntrySelected-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f && false || true"
      )

      expected_variables = ["LoaderDevicePartUUID",
        "LoaderImageIdentifier",
        "LoaderFirmwareInfo",
        "LoaderFirmwareType",
        "StubInfo",
        "StubFeatures"
      ]

      # Debug all systemd loader specification GUID EFI variables loaded by the current environment.
      print(machine.succeed(f"ls /sys/firmware/efi/efivars/*-{SD_LOADER_GUID}"))
      with subtest("Check if supported variables are exported"):
          for expected_var in expected_variables:
              machine.succeed(f"test -e /sys/firmware/efi/efivars/{expected_var}-{SD_LOADER_GUID}")

      with subtest("Is `StubInfo` correctly set"):
          assert "lanzastub" in read_string_variable("StubInfo"), "Unexpected stub information, provenance is not lanzaboote project!"

      assert_variable_string("LoaderImageIdentifier", "\\EFI\\BOOT\\BOOT${efiArchUppercased}.EFI")
      # TODO: exploit QEMU test infrastructure to pass the good value all the time.
      assert_variable_string("LoaderDevicePartUUID", "1c06f03b-704e-4657-b9cd-681a087a2fdc")
      # OVMF tests are using EDK II tree.
      assert_variable_string_contains("LoaderFirmwareInfo", "EDK II")
      assert_variable_string_contains("LoaderFirmwareType", "UEFI")

      with subtest("Is `StubFeatures` non-zero"):
          assert struct.unpack('<Q', read_raw_variable("StubFeatures")) != 0
    '';
  };

  tpm2-export-efi-variables = mkSecureBootTest {
    name = "lanzaboote-tpm2-exports-efi-variables";
    useTPM2 = true;
    readEfiVariables = true;
    testScript = ''
      # TODO: the other variables are not yet supported.
      expected_variables = [
        "StubPcrKernelImage"
      ]

      # Debug all systemd loader specification GUID EFI variables loaded by the current environment.
      print(machine.succeed(f"ls /sys/firmware/efi/efivars/*-{SD_LOADER_GUID}"))
      with subtest("Check if supported variables are exported"):
          for expected_var in expected_variables:
            machine.succeed(f"test -e /sys/firmware/efi/efivars/{expected_var}-{SD_LOADER_GUID}")

      # "Static" parts of the UKI is measured in PCR11
      assert_variable_uint("StubPcrKernelImage", 11)
    '';
  };

}
