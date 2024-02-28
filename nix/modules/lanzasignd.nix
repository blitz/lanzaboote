{ lib, config, pkgs, ... }:
let
  inherit (lib) mkOption mkEnableOption mkPackageOptionMD types mkIf;
  cfg = config.services.lanzasignd;
  policyFile = (pkgs.formats.json { }).generate "lanzasignd-policy.json" {
    allowedKernelCmdlineItems = cfg.policy.allowedCommandLineItems;
  };
in
{
  options.services.lanzasignd = {
    enable = mkEnableOption "lanzasignd, a Secure Boot remote signing server for NixOS";

    package = mkPackageOptionMD pkgs "lanzasignd" { };

    port = mkOption {
      type = types.port;
      default = 9999;
      description = "Port to run lanzasignd on";
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = "Open the firewall for the port lanzasignd is running on";
    };

    policy = {
      allowedCommandLineItems = mkOption {
        type = types.nullOr (types.listOf types.str);
        default = null;
        example = [ "quiet" "init=some init script" ];
      };
    };

    pkiBundle = mkOption {
      type = types.nullOr types.path;
      description = "PKI bundle containing db, PK, KEK";
    };

    publicKeyFile = mkOption {
      type = types.path;
      default = "${cfg.pkiBundle}/keys/db/db.pem";
      description = "Public key to sign your boot files";
    };

    privateKeyFile = mkOption {
      type = types.path;
      default = "${cfg.pkiBundle}/keys/db/db.key";
      description = "Private key to sign your boot files";
    };

  };

  config = mkIf cfg.enable {
    systemd.services.lanzasignd = {
      description = "Sign on demand bootables files compatible with Lanzaboote scheme";
      wants = [ "network.target" ];
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig.Type = "simple";
      path = [
        pkgs.binutils
        pkgs.sbsigntool
      ];
      script = ''
        ${cfg.package}/bin/lanzasignd -vvv serve \
          --policy-file ${policyFile} \
          --public-key ${cfg.publicKeyFile} \
          --private-key ${cfg.privateKeyFile} \
          --port ${toString cfg.port}
      '';
    };

    networking.firewall.allowedTCPPorts = mkIf cfg.openFirewall [ cfg.port ];
  };
}
