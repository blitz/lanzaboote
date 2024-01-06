{ pkgs, lanzasigndModule, lanzaLib }:
let
  inherit (lanzaLib) mkSecureBootTest;
  inherit (pkgs) lib;
  mkRemoteSigningTest = { name, machine ? { }, useSecureBoot ? true, useTPM2 ? false, testScript }:
    mkSecureBootTest {
      inherit name useSecureBoot useTPM2;
      testScript = { nodes, ... }:
        let
          remoteClientSystem = "${nodes.machine.system.build.toplevel}/specialisation/remote";
        in
        ''
          server.start()
          machine.start(allow_reboot=True)
          server.wait_for_unit("lanzasignd.service")
          server.wait_for_open_port(9999)
          # Perform a switch to the remote configuration
          # and contact the server to get the right bootables.
          with subtest("Activation will request for remote signing"):
              machine.fail("hello")
              machine.succeed(
                "${remoteClientSystem}/bin/switch-to-configuration boot >&2"
              )
          with subtest("Reboot into remote signed generation is successful"):
              machine.succeed("bootctl set-default nixos-generation-1-specialisation-remote-\*.efi")
              machine.reboot()
              machine.wait_for_unit("multi-user.target")
              machine.succeed("hello")
          ${testScript}
        '';
      machine = {
        imports = [
          machine
        ];

        specialisation.remote.configuration = {
          boot.lanzaboote = {
            # We disable explicitly local signing because `mkSecureBootTest` will set
            # `pkiBundle` which will set local signing to true by default.
            localSigning.enable = lib.mkForce false;
            # Keys were already enrolled by the local setup.
            enrollKeys = lib.mkForce false;
            remoteSigning = {
              enable = true;
              serverUrl = "http://server:9999";
            };
          };
          environment.systemPackages = [ pkgs.hello ];
        };
      };
      extraNodes.server = { nodes, ... }: {
        imports = [
          lanzasigndModule
        ];

        services.lanzasignd = {
          enable = true;
          pkiBundle = ./fixtures/uefi-keys;
          openFirewall = true;
        };

        system.extraDependencies = [
          # Trust `machine` store paths!
          nodes.machine.system.build.toplevel
        ];
      };
    };
in
{
  remote-signing-basic = mkRemoteSigningTest {
    name = "remote-signing-basic";
    testScript = ''
      assert "Secure Boot: enabled (user)" in machine.succeed("bootctl status")
    '';
  };

  # TODO: attack the signing server
  # send a fake store path
  # send ...
}
