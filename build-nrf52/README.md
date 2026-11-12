# Build System for EPD-nRF52 on Linux

This directory contains the build system for compiling the EPD-nRF5 firmware for nRF52 devices on Linux using ARM GCC.

## Prerequisites

### 1. Install ARM GCC Toolchain

**On Arch/Manjaro:**
```bash
sudo pacman -S arm-none-eabi-gcc arm-none-eabi-binutils arm-none-eabi-newlib
```

**On Ubuntu/Debian:**
```bash
sudo apt-get install gcc-arm-none-eabi binutils-arm-none-eabi
```

**Or download from ARM:**
- Download from: https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm
- Extract and add to PATH, or set `GNU_INSTALL_ROOT` in the Makefile

### 2. Install nRF Command Line Tools (for merging hex files)

**On Arch/Manjaro:**
```bash
sudo pacman -S nrf-command-line-tools
```

**On Ubuntu/Debian:**
- Download from: https://www.nordicsemi.com/Software-and-tools/Development-Tools/nRF-Command-Line-Tools
- Or install via package manager if available

**Verify installation:**
```bash
mergehex --version
nrfjprog --version
```

### 3. Verify ARM GCC Installation

```bash
arm-none-eabi-gcc --version
```

Should show version 9.x or later.

## Building

### Basic Build

From the `build-nrf52` directory:

```bash
make
```

This will:
- Compile all source files
- Link the firmware
- Generate `_build/EPD-nRF52.hex` (application only)
- Generate `_build/EPD-nRF52.bin` (binary format)
- Generate `_build/EPD-nRF52.map` (memory map)

### Complete Firmware (with Bootloader and SoftDevice)

To create a complete firmware file that includes bootloader, softdevice, and application:

```bash
make full
```

This creates `_build/EPD-nRF52-full.hex` which can be flashed directly to a blank chip.
For this bootloader flow, `make full` also generates:
- `_build/EPD-nRF52-settings.hex` (bootloader settings page)
- `_build/EPD-nRF52-ota.zip` (signed OTA package)

`make full` requires:
- `nrfutil` available and working
- A private signing key matching the bootloader public key

By default it expects `../tools/priv.pem`. Override with:

```bash
make full KEY_FILE=/absolute/path/to/priv.pem
```

**Other merge options:**

```bash
# Softdevice + Application (no bootloader)
make sd

# MBR + Softdevice + Application (no bootloader, with MBR)
make mbr-sd
```

### Custom Toolchain Path

If your ARM GCC toolchain is not in `/usr/bin`, you can override it:

```bash
make GNU_INSTALL_ROOT=/path/to/toolchain/bin
```

### Clean Build

```bash
make clean
```

### Help

```bash
make help
```

## Output Files

After building, you'll find in `_build/`:

- `EPD-nRF52.hex` - Application only (Intel HEX format)
- `EPD-nRF52.bin` - Application binary format
- `EPD-nRF52.out` - ELF executable
- `EPD-nRF52.map` - Linker memory map

After running `make full`, you'll also have:

- `EPD-nRF52-full.hex` - **Complete firmware** (Bootloader + SoftDevice + Application)
- `EPD-nRF52-sd.hex` - SoftDevice + Application (if you ran `make sd`)
- `EPD-nRF52-mbr-sd.hex` - MBR + SoftDevice + Application (if you ran `make mbr-sd`)

## Flashing

### Option 1: Flash Complete Firmware (Recommended for first time)

If you built the complete firmware with `make full`:

```bash
# Erase chip
nrfjprog --eraseall

# Flash complete firmware (bootloader + softdevice + application)
nrfjprog --program _build/EPD-nRF52-full.hex

# Reset
nrfjprog --reset
```

### Option 2: Flash Components Separately

```bash
# Erase chip
nrfjprog --eraseall

# Flash softdevice (only needed once)
nrfjprog --program ../SDK/17.1.0_ddde560/components/softdevice/s112/hex/s112_nrf52_7.3.0_softdevice.hex

# Flash bootloader (only needed once)
nrfjprog --program ../tools/bootloader/bl_nrf52811_xxaa_s112.hex

# Flash application
nrfjprog --program _build/EPD-nRF52.hex

# Reset
nrfjprog --reset
```

### Option 3: Flash Application Only (if bootloader/softdevice already installed)

```bash
# Flash application only
nrfjprog --program _build/EPD-nRF52.hex --sectorerase

# Reset
nrfjprog --reset
```

### Using J-Link Commander

```bash
# Connect and flash complete firmware
JLinkExe -device nRF52811 -if SWD -speed 4000 -autoconnect 1
loadfile _build/EPD-nRF52-full.hex
r
g
exit
```

### Using OpenOCD

```bash
# Flash complete firmware
openocd -f interface/jlink.cfg -f target/nrf52.cfg \
  -c "program _build/EPD-nRF52-full.hex verify reset exit"
```

## Configuration

### Target Device

The Makefile is configured for **nRF52811_xxAA**. To change the target:

1. Update `CFLAGS` to change the `NRF52811_XXAA` define
2. Update the linker script path in `LDFLAGS`
3. Update the startup file in `ASM_FILES`

### SoftDevice

Currently configured for **SoftDevice S112** (v7.3.0). The linker script automatically accounts for the softdevice memory layout.

### Memory Layout

- **Flash**: 0x00000000 - 0x00030000 (192 KB total)
  - SoftDevice: 0x00000000 - 0x00019000 (100 KB)
  - Application: 0x00019000 - 0x00030000 (92 KB)

- **RAM**: 0x20000000 - 0x20006000 (24 KB)
  - SoftDevice: 0x20000000 - 0x200022D8
  - Application: 0x200022D8 - 0x20006000

## Troubleshooting

### "arm-none-eabi-gcc: No such file or directory"

Install the ARM GCC toolchain (see Prerequisites).

### Linker errors about missing symbols

- Check that all source files are included in `SRC_FILES`
- Verify include paths in `INC_FOLDERS`
- Check that the linker script path is correct

### "No rule to make target"

- Verify that `PROJECT_ROOT` and `SDK_ROOT` paths are correct
- Check that source files exist at the specified paths

### "ModuleNotFoundError: No module named 'nordicsemi'" (during `make full`)

Your `nrfutil` Python package is incomplete/broken. Reinstall it, for example:

```bash
python3 -m pip install --user --upgrade nrfutil
```

### Build fails with undefined references

- Ensure the softdevice hex file is flashed first
- Check that all required SDK components are included
- Verify compiler defines match the Keil project configuration

## Project Structure

```
build-nrf52/
├── Makefile          # Build configuration
├── README.md         # This file
└── _build/           # Build output (generated)
    ├── EPD-nRF52.hex
    ├── EPD-nRF52.bin
    ├── EPD-nRF52.out
    └── EPD-nRF52.map
```

## Differences from Keil Build

This Makefile uses:
- **GCC** instead of ARMCC/Keil compiler
- **GCC-specific** files:
  - `app_error_handler_gcc.c` instead of `app_error_handler_keil.c`
  - `SEGGER_RTT_Syscalls_GCC.c` instead of `SEGGER_RTT_Syscalls_KEIL.c`
- **GNU linker** with GCC linker script format
- **Standard Make** instead of Keil's build system

The output should be functionally equivalent to the Keil build.
