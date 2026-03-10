# EPD-nRF5

E-paper display firmware for Nordic nRF52 microcontrollers with Bluetooth Low Energy (BLE) support. This firmware enables wireless image transfer, OTA updates, and flexible configuration for e-paper displays.

This project is part of the [OpenDisplay](https://opendisplay.org/) ecosystem, providing open-source firmware and protocol standards for e-paper displays.

## About

This is a fork of [tsl0922/EPD-nRF5](https://github.com/tsl0922/EPD-nRF5) for compatibility with the OpenDisplay protocol standard.

### Key Features

- **Low Power Operation**: Optimized for minimal power consumption with deep sleep support
- **BLE Communication**: Bluetooth Low Energy for wireless updates and configuration
- **Multiple Display Support**: Supports UC81xx and SSD16xx series e-paper displays
- **Direct Write Mode**: Bufferless image transfer for efficient memory usage
- **OTA Updates**: Over-the-air firmware updates via BLE DFU
- **Button Support**: Interrupt-based button handling with press counting
- **LED Control**: RGB LED support with configurable flash patterns
- **Battery Monitoring**: Built-in battery voltage reading via ADC

## Supported Hardware

### Microcontrollers
- nRF52811 (primary target)

### E-Paper Displays
- UC81xx series (UC8176, UC8179, etc.)
- SSD16xx series (SSD1680, SSD1681, etc.)
- Custom pin mapping support
- Multiple color schemes (B/W, B/W+Red, B/W+Yellow)

## Building

### Prerequisites

- ARM GCC toolchain (arm-none-eabi-gcc)
- nRF Command Line Tools (for flashing and hex merging)
- nrfutil (for OTA package generation, optional)

See [build-nrf52/README.md](build-nrf52/README.md) for detailed installation and build instructions.

### Quick Start

```bash
cd build-nrf52
make
```

This generates `_build/EPD-nRF52.hex` which can be flashed to the device.

### Complete Firmware Build

To build a complete firmware package including bootloader and softdevice:

```bash
cd build-nrf52
make full KEY_FILE=/path/to/priv.pem
```

This generates:
- `_build/EPD-nRF52-full.hex` - Complete firmware
- `_build/EPD-nRF52-ota.zip` - Signed OTA package
- `_build/EPD-nRF52-settings.hex` - Bootloader settings

## Flashing

### Using nrfjprog

```bash
# Flash complete firmware
nrfjprog --eraseall
nrfjprog --program build-nrf52/_build/EPD-nRF52-full.hex
nrfjprog --reset
```

## Configuration

The firmware uses a TLV (Type-Length-Value) based configuration system that supports:

- System configuration (device name, manufacturer data)
- Display configuration (pin mapping, panel type, color scheme)
- LED configuration (pin mapping, flash patterns)
- Button configuration (pin mapping, debounce settings)
- Sensor configuration
- Data bus configuration
- Power options

Configuration can be written via BLE using the OpenDisplay protocol. See the [OpenDisplay documentation](https://opendisplay.org/) for protocol details.

## BLE Protocol

The firmware implements the OpenDisplay BLE protocol standard. Key commands include:

- `0x0040` - Read configuration
- `0x0041` - Write configuration
- `0x0042` - Write configuration chunk
- `0x0070` - Direct write start
- `0x0071` - Direct write data
- `0x0072` - Direct write end
- `0x0073` - LED activate
- `0x0043` - Firmware version
- `0x000F` - Reboot

See the [OpenDisplay protocol documentation](https://opendisplay.org/) for complete protocol specifications.

## Power Consumption

The firmware is optimized for low power operation:

- **Idle current**: ~35 µA (with EPD powered down)
- **Active current**: ~100 µA (during BLE operations)
- **Display update**: ~5-10 mA (during refresh)

EPD GPIO is automatically powered down when not in use to minimize idle consumption.

## Development

### Building with Logging

RTT logging is disabled by default to reduce code size and power consumption. To enable:

```bash
cd build-nrf52
make ENABLE_RTT=1
```

### Versioning

Firmware version can be set during build:

```bash
cd build-nrf52
make MAJOR_VERSION=2 MINOR_VERSION=5 SHA_VALUE=abc123def456
```

## License

This project is licensed under the GPL-3.0 license. See [LICENSE](LICENSE) for details.
