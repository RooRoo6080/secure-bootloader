# Guardian Of Outstanding Firmware, Yay! (GOOFY)
Secure microcontroller bootloader based on 32-bit ARM architecture

To be used on Texas Instruments Tiva C Series EK-TM4C123GXL Launchpad
```
______   ______     ______     __    __  
/\__  _\ /\  ___\   /\  __ \   /\ "-./  \ 
\/_/\ \/ \ \  __\   \ \  __ \  \ \ \-./\ \
  \ \_\  \ \_____\  \ \_\ \_\  \ \_\ \ \_\
   \/_/   \/_____/   \/_/\/_/   \/_/  \/_/

⠀⠀⠀⠀⠀⠀⣀⣠⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣴⡿⠋⠉⠉⠻⢿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⠹⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠈⣿⡄⠀⠀⠀⠀⠀⠀⢸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⣷⠀⠀⠀⠀⠀⠀⢸⣿⠀⠀⢀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢻⣇⠀⠀⠀⠀⠀⢸⣿⣿⡿⠿⠿⠟⠛⠛⠻⢿⣿⣶⣄⠀⠀⠀
⠀⠀⠀⠀⠀⢈⣿⠆⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣤⣤⣤⠀⠈⠻⣿⣇⠀⠀
⠀⠀⠀⠀⢀⣾⡏⠀⠀⠀⠀⠀⠀⠀⣴⡿⠋⠉⠀⠀⠀⠀⠀⠀⠀⢹⡿⠀⠀
⠀⠀⣀⣤⣼⣿⠀⠀⠀⠀⠀⠀⠀⢸⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣷⣄⠀
⢠⣾⠟⠋⠉⠋⠀⠀⠀⠀⠀⠀⠀⠈⣿⣦⣀⣀⣀⣤⣤⣶⣶⠿⠋⠁⢹⣿⡇
⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡟⢉⣿⠋⠉⠉⠉⠁⠀⠀⠀⠀⢸⣿⠀
⢸⣿⠀⠀⠀⠀⠀⢀⣀⣀⣤⣴⠿⠋⠀⠘⣷⡀⠀⠀⠀⠀⠀⠀⢀⣴⣿⠏⠀
⢸⣿⡄⠀⠀⠀⠀⠈⠉⠉⠁⠀⠀⠀⠀⠀⣸⣿⢶⣤⣤⣴⡶⠿⠛⠙⣿⣆⠀
⠈⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⣽⣿⠀
⠀⠘⣿⣆⠀⠀⠀⠀⣠⣤⡀⠀⠀⠀⠀⠈⠻⣧⣀⡀⠀⠀⠀⣀⣠⣴⡿⠇⠀
⠀⠀⠘⢿⣿⣦⣤⣴⡿⠻⠿⣷⣦⣤⣤⣤⣴⣾⣿⡿⠿⠿⠿⠟⠛⠉⠀⠀⠀
⠀⠀⠀⠀⠉⢉⣉⠉⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

```

By Reuel Joseph, Ethan Fuks, Arthur Zhu, Irene Lin, Daniel Miao
as part of the MIT BWSI Embedded Security and Hardware Hacking program

With our secure (TM) automotive bootloader, we guarantee that cars running our software will be unhackable (provided hacking is not attempted).

# Project Structure
```
├── bootloader 
│   ├── bin
│   │   ├── bootloader.bin
│   ├── src
│   │   ├── bootloader.c
│   │   ├── startup_gcc.c
│   ├── inc
│   │   ├── keys.h
│   │   ├── bootloader.h
│   ├── bootloader.ld
│   ├── Makefile
│   ├── preprocessed.c
├── firmware
│   ├── lib
│   ├── src
│   ├── firmware.ld
│   ├── Makefile
├── lib
│   ├── driverlib
│   ├── inc
│   ├── uart
│   ├── wolfssl
├── tools 
│   ├── bl_build.py 
│   ├── fw_protect.py 
│   ├── fw_update.py 
│   ├── secret_build_output.txt
│   ├── firmware_protected.bin
├── README.md
```
## Get Started

Run the following commands in order.

Building and flashing the bootloader
```
cd tools
python bl_build.py
lm4flash ../bootloader/bin/bootloader.bin
```
Protect the firmware `fw_protect.py`
```
cd ../firmware
make
cd ../tools
python3 fw_protect.py --infile ../firmware/bin/firmware.bin --outfile firmware_protected.bin --version 2 --message "Firmware V2"
```
Reset the TM4C by pressing the RESET button, then run `fw_update.py`
```
python fw_update.py --firmware ./firmware_protected.bin --port /dev/<tty-port> --debug
python -m serial.tools.miniterm /dev/<tty-port> 115200
```

## Bootloader

The Bootloader manages which firmware gets updated to the TM4C, and will start the execution of the loaded vehicle firmware. It checks the version of the new firmware against the internal firmware version before accepting the new firmware.

### bootloader.c

The bootloader.c file contains all the essential instructions and functions to successfully run the system and secure firmware.
```
load_firmware()		Reads incoming firmware and its metadata from UART, performs version checks, and writes it to FW_INCOMING_BASE

boot_firmware()		Manages the firmware update process by verifying incoming firmware, moving it to FW_CHECK_BASE, verifying again, decrypting, moving to FW_BASE, and then executing it

verify_signature()	Verifies the SHA-256 hashed and RSA-2048 PSS encrypted signature of firmware and metadata

move_and_decrypt()	Moves data from an origin to a destination while performing AES decryption in 1KB chunks

move_firmware()		Moves a specified number of KB of data from an origin address to a destination address in flash memory

erase_partition()	Erases a specified number of flash pages starting from a given memory address

check_canary()		Verifies a stack canary to detect and prevent stack overflow attacks

program_flash()		Erases a flash page and then programs data to it

uart_write_str_length() Modification of uart_write_str, but it stops ata specified length OR a null terminator

```
#### Memory Map
```
+-------------------------+ 0x40000
|                         |
|      MAX_VERSION        |
|       (0x28000)         |
|                         |
+-------------------------+
|                         |
|   METADATA_INCOMING_BASE|
|       (0x30000)         |
|                         |
+-------------------------+
|                         |
|   METADATA_CHECK_BASE   |
|       (0x28000)         |
|                         |
+-------------------------+
|                         |
|                         |
|    FW_INCOMING_BASE     |
|       (0x20000)         |
|                         |
+-------------------------+
|                         |
|     FW_CHECK_BASE       |
|       (0x18000)         |
|                         |
+-------------------------+
|                         |
|         FW_BASE         |
|       (0x10000)         |
|                         |
+-------------------------+
|                         |
|    METADATA_BASE        |
|       (0xFB00)          |
|                         |
+-------------------------+ 0x0
```
#### EEPROM Memory Map
```
+-------------------------+
|                         |
| RSA_PUB_KEY_EEPROM_LOCATION
|       (0x400)           |
|                         |
+-------------------------+
|                         |
| AES_KEY_EEPROM_LOCATION |
|       (0x200)           |
|                         |
+-------------------------+ 0x0
```
#### Boot order of operations
```
+---------------------+
|                     |
|  New Firmware Load  |
| (into *_INCOMING_BASE)
|                     |
+---------------------+
        |
        v
+---------------------+
| Verify Signature of |
| *_INCOMING_BASE Data|
+---------------------+
        |
        |  NO
        +-------+
        |       |
        |       v
        |  Run Old Firmware
        |  (already in *_CHECK_BASE)
        |  [EXIT]
        |
        v YES
+---------------------+
|   Move to           |
|  *_CHECK_BASE       |
|  (Permissions: rw)  |
+---------------------+
        |
        v
+---------------------+
| Verify Signature of |
| *_CHECK_BASE Data   |
+---------------------+
        |
        |  NO
        +-------+
        |       |
        |       v
        |    QUIT
        |    [EXIT]
        |
        v YES
+---------------------+
|   Decrypt Data      |
|   Move to           |
|  *_BASE             |
|  (Permissions: rwx) |
+---------------------+
        |
        |  NO (e.g., decryption fails, move fails)
        +-------+
        |       |
        |       v
        |    QUIT
        |    [EXIT]
        |
        v YES
+---------------------+
|   Run Decrypted     |
|   Firmware from     |
|   *_BASE            |
+---------------------+
```

#### Additional protections & features
- Disabled debugging & re-flashing
- Stack canaries
- Keys stored in secure EEPROM
- Incoming data length checks
- Runs previous firmware if incoming data fails signature verification


## Tools

There are three python scripts in the `tools` directory which are used to:
1. Provision the bootloader
2. Generate keys
3. Bundle and encrypt the firmware
4. Package the metadata and firmware
5. Update the firmware to a TM4C with a provisioned bootloader 

### bl_build.py

This script calls `make` in the `bootloader` directory to create the bootloader and generates the following:
- AES-128 key + IV
- RSA-2048 private and public keys

### fw_protect.py

This script bundles the version and release message with the firmware binary to package the firmware.
```
┌──────────────────────────────────────────────┐
│           Protected Firmware Output          │
├──────────────────────────────────────────────┤
│                   HEADER                     │
│               (Unencrypted)                  │
│  ┌────────────────────────────────────────┐  │
│  │  Encrypted Payload Length   (2 bytes)  │  │
│  │  Firmware Version           (2 bytes)  │  │
│  │  Message Length             (2 bytes)  │  │
│  │  Message              (<= 1024 bytes)  │  │   
│  └────────────────────────────────────────┘  │
├──────────────────────────────────────────────┤
│                   PAYLOAD                    │
│              (AES-128 CBC Encrypted)         │
│  ┌────────────────────────────────────────┐  │
│  │  Firmware Binary  (<= 30kb )           │  │
│  │  AES Padding                           │  │
│  └────────────────────────────────────────┘  │
├──────────────────────────────────────────────┤
│                 SIGNATURE                    │
│         (SHA-256 hashed, RSA signed)         │
│  ┌────────────────────────────────────────┐  │
│  │  Signature of Header + Payload         │  │
│  │  (RSA 2048-bit = 256 bytes)            │  │
│  └────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
```

### fw_update.py

This script opens a serial channel with the bootloader, then writes the firmware metadata and binary broken into 256-byte data frames to the bootloader to update the firmware to a TM4C with a provisioned bootloader. 
```
+------------------+         +---------------------+
|                  |         |                     |
| Firmware Updater |         |     Bootloader      |
|      Tool        |         |                     |
+------------------+         +---------------------+
        |                            ^
        | send_metadata(metadata)    |
        | (Handshake: "U")           |
        |--------------------------->|
        |                            |
        |       Wait for "U" response|
        |<---------------------------|
        |                            |
        | Send metadata (size, version, message_length)
        |--------------------------->|
        |                            |
        |       Wait for RESP_OK (0x00)
        |<---------------------------|
        |                            |
        | update(firmware_blob)      |
        |                            |
        | For each frame in firmware:|
        |   Construct frame:         |
        |   [Length (2 bytes)]       |
        |   [Data (variable)]        |
        |--------------------------->|
        |                            |
        |       Wait for RESP_OK (0x00)
        |<---------------------------|
        |                            |
        | Send zero-length frame (0x00 0x00) to signal end
        |--------------------------->|
        |                            |
        |       Wait for RESP_OK (0x00)
        |<---------------------------|
        |                            |
        v                            |
```

## Using WolfSSL

WolfSSL is an SSL library designed for embedded systems. Using the WolfSSL library, we incorporated multiple functions including those from aes.h and rsa.h to complete encryption and decryption. Make sure to ```git clone https://github.com/wolfSSL/wolfssl``` to `lib/wolfssl`
