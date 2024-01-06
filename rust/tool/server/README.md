# Lanzaboote Remote Signature Server (`lanzasignd`)

`lanzasignd` is a model of how to offer a remote signature server which
will serve the only two things of importance:

- the lanzaboote stub
- a potential first stage bootloader, e.g. systemd-boot

Instead of sending any binary on the wire which is wasteful, we can exploit the Nix store model here
and send store paths that are expected to be realizable on the signing server.

Furthermore, this serves as a good enough way to protect the user against sending tampered stubs.

## Theory of operations

`lanzasignd` is expected to run as a hardened daemon with a potential access to the private key material
or an already authenticated socket to perform signing operations.

No authentication or authorization is built-in as this is out of scope, it is recommended to run the daemon
behind a reverse proxy with authentication or authorization or in a trusted network via a VPN.

No rate-limit is applied to protect against denial of service, PRs are welcome to figure out a reasonable solution on that,
otherwise rate-limits can be applied at the system level.

## Endpoints

- `POST /sign-stub`: assembles a signed stub based on the stub parameters sent, 200 OK with a signed binary as body, 400 with a plaintext error if failed.
- `POST /sign-store-path`: assembles a signed binary based on the store path sent, 200 OK with a signed binary as body, 400 with a plaintext error if failed.
- `GET /verify`: verify that the binary sent is signed according to the current keyring, returns a JSON `{ signed: bool, valid_according_to_secureboot_policy: bool }`, a signed binary can be invalid for the current Secure Boot policy, the two attributes represents this fact.

## Operating it

`lanzasignd` has hard requirements on possessing a Nix store.

```nix
  services.lanzasignd = {
     enable = true;
     port = 9999;
     settings = {
      kernel-cmdline-allowed = [ "..." ];
     };
  };
```
