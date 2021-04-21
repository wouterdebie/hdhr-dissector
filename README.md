hdhr-dissector
==============

Wireshark/tshark Plugin in C for [HDHomerun Packets](https://github.com/Silicondust/libhdhomerun/blob/master/hdhomerun_pkt.h).

NOTE: This for makes the dissector work for wireshark 3.
# Build

- Download Wireshark source-code.
- Create __hdhr__ directory inside __wireshark/plugins/epan__ folder.
- Download/Clone source code from this repo into the __hdhr__ folder.
- Inside __wireshark__ folder, create __CMakeListsCustom.txt__ and add the line.
```
set(CUSTOM_PLUGIN_SRC_DIR plugins/epan/hdhr)
```
- Follow the build instructions of Wireshark for your OS setup

# Notes

- This code has been tested with latest stable release of Wireshark (3.2.0) on MacOS

