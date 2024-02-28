{ lib, config, pkgs, ... }:
with lib;
let
  cfg = config.boot.lanzaboote;

  sbctlWithPki = pkgs.sbctl.override {
    databasePath = "/tmp/pki";
  };

  loaderSettingsFormat = pkgs.formats.keyValue {
    mkKeyValue = k: v: if v == null then "" else
    lib.generators.mkKeyValueDefault { } " " k v;
  };

  loaderConfigFile = loaderSettingsFormat.generate "loader.conf" cfg.settings;

  configurationLimit = if cfg.configurationLimit == null then 0 else cfg.configurationLimit;
in
{
  options.boot.lanzaboote = {
    enable = mkEnableOption "Enable the LANZABOOTE";

    enrollKeys = mkEnableOption "Automatic enrollment of the keys using sbctl";

    configurationLimit = mkOption {
      default = config.boot.loader.systemd-boot.configurationLimit;
      defaultText = "config.boot.loader.systemd-boot.configurationLimit";
      example = 120;
      type = types.nullOr types.int;
      description = lib.mdDoc ''
        Maximum number of latest generations in the boot menu.
        Useful to prevent boot partition running out of disk space.

        `null` means no limit i.e. all generations
        that were not garbage collected yet.
      '';
    };

    localSigning = {
      enable = mkEnableOption "local signing" // { default = cfg.pkiBundle != null; defaultText = lib.literalExpression "cfg.pkiBundle != null"; };
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

    remoteSigning = {
      enable = mkEnableOption "remote signing";
      serverUrl = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Remote signing server to contact to ask for signatures";
      };
    };

    pkiBundle = mkOption {
      type = types.nullOr types.path;
      description = "PKI bundle containing db, PK, KEK";
    };

    package = mkOption {
      type = types.package;
      default = pkgs.lzbt;
      defaultText = "pkgs.lzbt";
      description = "Lanzaboote tool (lzbt) package";
    };

    settings = mkOption rec {
      type = types.submodule {
        freeformType = loaderSettingsFormat.type;
      };

      apply = recursiveUpdate default;

      default = {
        timeout = config.boot.loader.timeout;
        console-mode = config.boot.loader.systemd-boot.consoleMode;
        editor = config.boot.loader.systemd-boot.editor;
        default = "nixos-*";
      };

      defaultText = ''
        {
          timeout = config.boot.loader.timeout;
          console-mode = config.boot.loader.systemd-boot.consoleMode;
          editor = config.boot.loader.systemd-boot.editor;
          default = "nixos-*";
        }
      '';

      example = literalExpression ''
        {
          editor = null; # null value removes line from the loader.conf
          beep = true;
          default = "@saved";
          timeout = 10;
        }
      '';

      description = ''
        Configuration for the `systemd-boot`

        See `loader.conf(5)` for supported values.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = !(cfg.localSigning.enable && cfg.remoteSigning.enable);
        message = ''
          You cannot enable local and remote signing at the same time, pick either of the strategy.

          Did you set `pkiBundle` and forgot to set `localSigning.enable` to false?
        '';
      }
    ];
    boot.bootspec = {
      enable = true;
    };
    boot.loader.supportsInitrdSecrets = true;
    boot.loader.external = {
      enable = true;
      installHook =
        let
          lzbtArgs = [
            "install"
            "--system"
            config.boot.kernelPackages.stdenv.hostPlatform.system
            "--systemd"
            config.systemd.package
            "--systemd-boot-loader-config"
            loaderConfigFile
          ] ++ lib.optionals cfg.localSigning.enable [
            "--public-key"
            cfg.localSigning.publicKeyFile
            "--private-key"
            cfg.localSigning.privateKeyFile
          ] ++ lib.optionals cfg.remoteSigning.enable [
            "--remote-signing-server-url"
            cfg.remoteSigning.serverUrl
          ] ++ [
            "--configuration-limit"
            (toString configurationLimit)
            config.boot.loader.efi.efiSysMountPoint
            "/nix/var/nix/profiles/system-*-link"
          ];
        in
        pkgs.writeShellScript "bootinstall" ''
          ${optionalString cfg.enrollKeys ''
            mkdir -p /tmp/pki
            cp -r ${cfg.pkiBundle}/* /tmp/pki
            ${sbctlWithPki}/bin/sbctl enroll-keys --yes-this-might-brick-my-machine
          ''}

          ${cfg.package}/bin/lzbt ${concatStringsSep " " lzbtArgs}
        '';
    };

    systemd.services.fwupd = lib.mkIf config.services.fwupd.enable {
      # Tell fwupd to load its efi files from /run
      environment.FWUPD_EFIAPPDIR = "/run/fwupd-efi";
    };

    systemd.services.fwupd-efi = lib.mkIf config.services.fwupd.enable {
      description = "Sign fwupd EFI app";
      # Exist with the lifetime of the fwupd service
      wantedBy = [ "fwupd.service" ];
      partOf = [ "fwupd.service" ];
      before = [ "fwupd.service" ];
      # Create runtime directory for signed efi app
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        RuntimeDirectory = "fwupd-efi";
      };
      # Place the fwupd efi files in /run and sign them
      script = ''
        ln -sf ${config.services.fwupd.package.fwupd-efi}/libexec/fwupd/efi/fwupd*.efi /run/fwupd-efi/
        ${pkgs.sbsigntool}/bin/sbsign --key '${cfg.privateKeyFile}' --cert '${cfg.publicKeyFile}' /run/fwupd-efi/fwupd*.efi
      '';
    };

    services.fwupd.uefiCapsuleSettings = lib.mkIf config.services.fwupd.enable {
      DisableShimForSecureBoot = true;
    };
  };
}
