# MAC Privacy Protection (MPP) Wireshark Dissector Plugin

Wireshark dissector plugin for MAC Privacy Protection (MPP) protocol (802.1AEdk).

## Install

### Debian

- Install Wireshark version 4.6 (currently in the `forky` repository)
- Download the `.deb` and install it using `apt`.

### Other

See [Build and Install](#build-and-install).

## Build and Install

- Install Wireshark version 4.6
  - Depending on your OS, you may need to install from a repository which is not the default.
  - You may need to build from source. If so, the source can be downloaded [here](https://www.wireshark.org/download/src/).
  - Follow the directions [here](https://tshark.dev/setup/install/#install-from-source) to build and install `tshark` from source.
- Clone this repository
- Build a release by running `cargo build --release`
  - If wireshark is installed in a non-standard directory on macOS, set the `WIRESHARK_LIB_DIR` environment variable to the path of the directory containing `libwireshark.dylib`.
- Copy the generated library file to the Wireshark plugin directory
  - You can check the Wireshark plugin directory by running `tshark -G folders`. Look for the directory labeled "Personal Plugins".
  - On `*nix` platforms, the built plugin library is at `target/release/libmac_privacy_dissector.so`. On Windows it is at `target/release/mac_privacy_dissector.dll`.

Example:

```sh
WS_PLUGIN_DIR="$(tshark -G folders | grep -i "^Personal Plugins" | sed 's/^Personal Plugins:[[:space:]]*//i')"
mkdir -p "$WS_PLUGIN_DIR/epan"
cp ./target/release/libmac_privacy_dissector.dylib "$WS_PLUGIN_DIR/epan/mac_privacy.so"
```

- Verify plugin has loaded
  - Run `tshark -G plugins` and verify that the Mac Privacy plugin is present (`tshark` will show an error if it failed to load)

Once setup is complete, Wireshark and Tshark will automatically load and use the MACPrivacy plugin when MACPrivacy data is found.

## Example Capture File

Example capture files can be found in the `tests/data` directory.

To decrypt MACsec data, add the following keys to the MACsec pre-shared key list: `fedcba9876543210fedcba9876543210`, `0123456789abcdef0123456789abcdef`.
