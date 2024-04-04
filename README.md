# OneDrive as a block device

:warning: This project is in alpha stage.

## Audience

If you are not sure whether this project fits your need, then it does not. You
are probably looking for
[OneDrive Online](https://onedrive.live.com/) or sync and FUSE implementations
like [rclone](https://github.com/rclone/rclone).

This project may be helpful for :penguin: *real nerds* :penguin: who enjoy
wacky block device stacking, intend to leverage block level encryption or their
existing BTRFS backup infrastructure, or explore fresh new bugs in BTRFS zoned
mode, with the cost of *everything*.

## Installation

System requirements:

- Linux >= 5.19 is required for io-uring with `IORING_SETUP_SQE128` support.

- Kernel driver `ublk_drv` and zoned block device support should be enabled.
  Most distributions like Arch Linux and NixOS unstable meet these requirements
  by default. You can check your system by:

  ```console
  $ zgrep -E 'CONFIG_BLK_DEV_UBLK|CONFIG_BLK_DEV_ZONED' /proc/config.gz
  CONFIG_BLK_DEV_ZONED=y
  CONFIG_BLK_DEV_UBLK=m
  ```
  If you see the same result, your kernel is probably supported.

- You may need to run `sudo modprobe ublk_drv` manually to load the driver
  first. This is not required for running orb in the shipped systemd service or
  via NixOS module, which does this automatically.

### Nix/NixOS (flake)

This project is packaged in Nix flake. Here's the simplified output graph:
```
├───nixosModules
│   ├───default: Alias to `orb`.
│   └───orb: The NixOS module.
└───packages
    ├───x86_64-linux
    │   ├───default: Alias to `orb`.
    │   ├───orb: The main program with systemd units.
    │   ├───btrfs-progs-fix-zoned-bgt: btrfs-progs with block-group-tree+zoned issue fixed.
    │   ├───cryptsetup-format-zoned: workaround script for cryptsetup-luksFormat on zoned devices.
    │   └───ublk-chown-unprivileged: The optional utility for unprivileged ublk.
    [..more Linux platforms are supported..]
```

<details>

<summary>Example configurations</summary>

To use the orb service, add the flake input `github:oxalica/orb`, and import
its NixOS modules.
```nix
# Example flake.nix for demostration. Please edit your own one to add changes.
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.orb.url = "github:oxalica/orb";

  outputs = { nixpkgs, orb, ... }: {
    nixosConfigurations.your-system = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = with nixosModules; [
        orb.nixosModules.orb
        ./path/to/your/configuration.nix
      ];
    };
  };
}
```

Now you can use the module in your `configuration.nix`:
```nix
{ ... }:
{
  services.orb.instances = {
    # The instance name. It coresponds to the systemd service
    # `orb@my-device.service`. By default it will not be automatically started.
    "my-device".settings = {
        # Required device id. It's recommended to start at 80.
        # This creates block device `/dev/ublkb80`.
        ublk.id = 80; 
        # Other settings and their defaults can be seen in
        # ./contrib/config-onedrive.example.toml
        device = {
          dev_size = "1TiB";
          zone_size = "256MiB";
          min_chunk_size = "1MiB";
          max_chunk_size = "256MiB";
        };
        backend.onedrive.remote_dir = "/orb";
    };
  };

  # If you want to mount the block device, you can create systemd mounts.
  # This is an example.
  systemd.mounts = [
    {
      type = "btrfs";
      # Fill in your filesystem UUID after mkfs.
      what = "/dev/disk/by-uuid/11111111-2222-3333-4444-555555555555";
      where = "/mnt/my-mount-point";
      # Do not forget dependencies.
      requires = [ "orb@my-device.service" ];
      after = [ "orb@my-device.service" ];
      # It's recommended to set `noatime` and `commit=300` to reduce write
      # frequency and amplification, but longer `commit` time risks rollbacking
      # more data on network issues if not `sync`ed. It will not break
      # filesystem consistency though. Set at your own risk.
      options = "noatime,commit=300,compress=zstd:7";
    }
  ];
}
```

Note that the service can only work after login and setup first. See the
following sections for details.

</details>

### Other Linux distributions

You need following dependencies to be installed with your package manager:
- Rust >= 1.76
- pkg-config
- openssl

Build command: `cargo build --release`

[`contrib/orb@.example.service`](./contrib/orb@.example.service)
is the example template systemd service to install.
The instance configurations locate at `/etc/orb/<name>.toml`, whose format is
documented in
[`./contrib/config-onedrive.example.toml`](./contrib/config-onedrive.example.toml).
Once configured and logined (see the next section), run
`systemctl start orb@<name>.service` to start the service.

## First time login

The service configuration does not contain the login credential. It must be
interactively setup for the first time, and then the service will rotate the
credentials automatically unless the user revokes the permission, or after a
long offline time (seems to be >1month, but is determined by Microsoft).

1.  First, you need to know this project (orb) is an third party program which
    access your files on Microsoft OneDrive on behalf of you, to provide block
    device interface as a service. Your files and/or data on your Microsoft
    OneDrive may be lost due to program bugs or other reasons. We provide no
    warranties. By following the login steps below, you understood and want to
    use orb at your own risk.

2.  We cannot provide an "official App/Client ID" without risking impersonated
    because this project is open sourced and free to distribute. So you need to
    [register your own App on Microsoft
    Azure](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade).

    In the registration page, 
    - In "Supported account types" section, select "Personal Microsoft accounts
      only". Other accounts are currently unsupported.
    - In "Redirect URI (optional)" section, select "Public client/native
      (mobile & desktop)", and enter the following URI:
      ```text
      http://localhost
      ```
      It must be this exactly (it's `http` not `https`), or you may fail the
      next step.

    Then click "Register", it will jump to the registered App information page
    if success. In "Essential" section, copy the UUID in the "Application
    (client) ID" field. This is the Client ID to be used in the next step.
    Note that one App can be used in multiple accounts, for multiple times. You
    do not need to register more than one App in almost any cases.

3.  Login with this command with root permission with arguments filled:
    ```console
    # orb login --systemd <instance> --client-id <the-client-uuid-from-the-last-step>
    ```
    `<instance>` is the instance name of your systemd service (for example, you
    setup `/etc/orb/foo.toml`, then `foo` is the instance name) or in NixOS
    module setting `services.orb.instances.<instance>`.

    It will prompt a URL, and you need to open it in your browser and following
    the interactive login steps to login into your Microsoft account with
    OneDrive.

    The credential will be saved under `/var/lib/orb/<instance>`, owned by
    root, and cannot be accessed by non-root users. It will be rotated by the
    service, and please never copy or save it outside the local machine. If you
    need to login to the same account on two machines, login twice.

    :warning:
    You must not serve the same remote directory simultaneously in multiple
    instances (or machines), or it will cause data race and your data will be
    corrupted. orb will try its best to detect and prevent such racing serving.

4.  On success, the web page will redirect to a mostly empty page with only one line:
    ```text
    Successfully logined. This page can be closed.
    ```

    The command should exit normally with credential saved. Now you are ready
    to start the orb service.
   
## Use the emulated block device

Once your logined and started the service successfully, you are ready to use it.
Usually you need to create an filesystem on the emulated block device, and this
is almost the same as the setup for your fresh hard disks, with a few
exceptions:

- The emulated device is under `/dev/ublkb<ID>` where `ID` is specified in
  your configuration `ublk.id`.

- The device is a
  [zoned device](https://zonedstorage.io/docs/introduction/zoned-storage)
  (aka. ZBC/ZBD/ZNS, host managed SMR disks) due to API restrictions and
  performance reasons. Only a few filesystems and/or device mappers support it,
  eg. dm-crypt, F2FS and BTRFS.

- It has a high latency and low throughput depend on your network. Doing
  active works on it should be avoided. It can be used, for example, for
  backup purpose.

- :warning: Since the block device is emulated, you must ensure to `umount` the
  filesystem on it before shutting down the backing device service
  (`orb@<instance>.service`), or you will lose your last written data. This
  could be enforced by systemd mounts with a `BindsTo=` dependency.

### Caveats on deletion and space usage

Due to the limitation of OneDrive API, permanently deletion cannot be done via
API. You may need to regularily "Empty recycle bin" on [OneDrive
online](https://onedrive.live.com) to free the capacity occupied.

:warning: You MUST not "Restore" any files under the directory managed by the
orb service (`backend.onedrive.remote_dir`). Otherwise, it may break filesystem
consistency and your data may be lost.

### Example: setup encryption via LUKS/dm-crypt

<details>
<summary>
Details
</summary>

:warning: Of course, this will destroy all of your data on the emulated device,
aka. the remote directory in OneDrive holding the data.

Unforunately cryptsetup does not support formatting zoned devices currently
(see [this issue](https://gitlab.com/cryptsetup/cryptsetup/-/issues/877)),
though dm-crypt supports it. We need some extra steps for formatting, and then
it can be opened and/or closed in the normal way.

For convenience, there is a script under
[`./contrib/cryptsetup-format-zoned.sh`](./contrib/cryptsetup-format-zoned.sh)
to mimic `cryptsetup luksFormat` as a workaround. Run:
```console
# ./contrib/cryptsetup-format-zoned.sh /dev/ublkb<ID> # Use a a password.
OR
# ./contrib/cryptsetup-format-zoned.sh /dev/ublkb<ID> /path/to/key/file # Use a key file.
```

Alternatively, you can run the script via flake package:
```console
$ nix shell github:oxalica/orb#cryptsetup-format-zoned -c sudo cryptsetup-format-zoned /dev/ublkb<ID>
```

After formatting the block device, you can open and/or close it in the normal
way:
```console
# cryptsetup luksOpen /dev/ublkb<ID> my-device-unencrypted
# cryptsetup close my-device-unencrypted
```

If you are using key files, you can also use systemd-cryptsetup services to
manage dm-crypt. This is useful when you want to specify dependencies to
`orb@<instance>.service` and downstream services, eg. backup services.
```nix
{ ... }:
{
  environment.etc."crypttab".text = ''
    mydecrypteddev /dev/ublkb<ID> /path/to/key/file noauto
  '';
  systemd.services."systemd-cryptsetup@mydecrypteddev" = {
    # Inform Nix that this is an overriding units for auto-generated ones.
    overrideStrategy = "asDropin";
    # Specify dependencies to the orb service.
    bindsTo = [ "orb@my-instance.service" ];
    after = [ "orb@my-instance.service" ];
  };
}
```

</details>

### Example: format it as BTRFS

<details>
<summary>
Details
</summary>

:warning: Of course, this will destroy all of your data on the emulated device,
aka. the remote directory in OneDrive holding the data.

It is recommended to format BTRFS with `block-group-tree` feature enabled, to
dramastically reduce mounting time (~50s to ~2s). But unfortunately btrfs-progs
currently had [a bug](https://github.com/kdave/btrfs-progs/issues/765) on it
with zoned device.
If you have a build of btrfs-progs's
[`devel` branch](https://github.com/kdave/btrfs-progs/tree/devel), or patched
version from flake output `btrfs-progs-fix-zoned-bgt` (used as `nix shell
github:oxalica/orb#btrfs-progs-fix-zoned-bgt`), you can format with:
```console
# mkfs.btrfs /dev/ublkb<ID> -O block-group-tree
```

Otherwise, for released btrfs-progs, do:
```console
# mkfs.btrfs /dev/ublkb<ID>
```

`zoned` feature will be automatically detected and enabled without manual
specification.

Now you can mount it and do read/write operations. These are recommended mount
options (disable atime, 5min commit time, high level zstd compression enabled):
```console
sudo mount -t btrfs -o noatime,commit=300,compress=zstd:7 /dev/ublkb<ID> /mnt/my-mount-point
```

</details>

## License

The sub-package `orb-ublk` (directory `/orb-ublk` and the whole sub-tree of it)
is licensed under either of [Apache License, Version
2.0](./orb-ublk/LICENSE-APACHE) or [MIT license](./orb-ublk/LICENSE-MIT) at
your option.

The main package (all other files in the repository except content of
`/orb-ublk` directory) is licensed under [GNU General Public License
v3.0](./LICENSE-GPL-3.0) or (at your option) later versions.
