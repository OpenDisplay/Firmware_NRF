# Makefile for EPD-nRF52 on Linux
# Target: nRF52811_xxAA with SoftDevice S112

# Project root directory (relative to build directory)
PROJECT_ROOT = ..

# SDK version
SDK_VERSION = 17.1.0_ddde560
SDK_ROOT = $(PROJECT_ROOT)/SDK/$(SDK_VERSION)

# Output directory
OUTPUT_DIRECTORY = _build

# Target name
TARGET = EPD-nRF52

# Toolchain configuration
GNU_INSTALL_ROOT ?= /usr/bin
GNU_PREFIX ?= arm-none-eabi
GNU_VERSION ?= $(shell $(GNU_INSTALL_ROOT)/$(GNU_PREFIX)-gcc --version | head -n1 | sed 's/.*\([0-9]\.[0-9]\.[0-9]\).*/\1/')

# Toolchain commands
CC      := $(GNU_INSTALL_ROOT)/$(GNU_PREFIX)-gcc
CXX     := $(GNU_INSTALL_ROOT)/$(GNU_PREFIX)-g++
AS      := $(GNU_INSTALL_ROOT)/$(GNU_PREFIX)-as
AR      := $(GNU_INSTALL_ROOT)/$(GNU_PREFIX)-ar
LD      := $(GNU_INSTALL_ROOT)/$(GNU_PREFIX)-ld
NM      := $(GNU_INSTALL_ROOT)/$(GNU_PREFIX)-nm
OBJDUMP := $(GNU_INSTALL_ROOT)/$(GNU_PREFIX)-objdump
OBJCOPY := $(GNU_INSTALL_ROOT)/$(GNU_PREFIX)-objcopy
SIZE    := $(GNU_INSTALL_ROOT)/$(GNU_PREFIX)-size

# Check if toolchain exists
ifeq ($(shell which $(CC) 2>/dev/null),)
$(error ARM GCC toolchain not found. Please install arm-none-eabi-gcc)
endif

# Source files - Application
SRC_FILES += $(PROJECT_ROOT)/main.c
SRC_FILES += $(PROJECT_ROOT)/config_storage.c
SRC_FILES += $(PROJECT_ROOT)/config_parser.c
SRC_FILES += $(PROJECT_ROOT)/encryption.c
SRC_FILES += $(PROJECT_ROOT)/led_control.c
SRC_FILES += $(PROJECT_ROOT)/button_control.c

# Source files - EPD
# EPD_config.c removed - legacy config system replaced by config_storage.c
SRC_FILES += $(PROJECT_ROOT)/EPD/EPD_driver.c
SRC_FILES += $(PROJECT_ROOT)/EPD/EPD_service.c
SRC_FILES += $(PROJECT_ROOT)/EPD/UC81xx.c
SRC_FILES += $(PROJECT_ROOT)/EPD/SSD16xx.c

# Source files - GUI
# GUI files removed - not used in current implementation (only MODE_PICTURE supported)
# SRC_FILES += $(PROJECT_ROOT)/GUI/GUI.c
# SRC_FILES += $(PROJECT_ROOT)/GUI/fonts.c
# SRC_FILES += $(PROJECT_ROOT)/GUI/u8g2_font.c
# SRC_FILES += $(PROJECT_ROOT)/GUI/Adafruit_GFX.c

# Source files - nRF BLE
SRC_FILES += $(SDK_ROOT)/components/ble/common/ble_advdata.c
SRC_FILES += $(SDK_ROOT)/components/ble/ble_advertising/ble_advertising.c
SRC_FILES += $(SDK_ROOT)/components/ble/common/ble_conn_params.c
SRC_FILES += $(SDK_ROOT)/components/ble/common/ble_srv_common.c
SRC_FILES += $(SDK_ROOT)/components/ble/nrf_ble_gatt/nrf_ble_gatt.c

# Source files - nRF DFU
SRC_FILES += $(SDK_ROOT)/components/ble/ble_services/ble_dfu/ble_dfu.c
SRC_FILES += $(SDK_ROOT)/components/ble/ble_services/ble_dfu/ble_dfu_unbonded.c

# Source files - nRF Drivers
SRC_FILES += $(SDK_ROOT)/integration/nrfx/legacy/nrf_drv_clock.c
SRC_FILES += $(SDK_ROOT)/integration/nrfx/legacy/nrf_drv_spi.c
SRC_FILES += $(SDK_ROOT)/modules/nrfx/soc/nrfx_atomic.c
SRC_FILES += $(SDK_ROOT)/modules/nrfx/drivers/src/nrfx_clock.c
SRC_FILES += $(SDK_ROOT)/modules/nrfx/drivers/src/nrfx_gpiote.c
SRC_FILES += $(SDK_ROOT)/modules/nrfx/drivers/src/prs/nrfx_prs.c
SRC_FILES += $(SDK_ROOT)/modules/nrfx/drivers/src/nrfx_spi.c
SRC_FILES += $(SDK_ROOT)/modules/nrfx/drivers/src/nrfx_spim.c
SRC_FILES += $(SDK_ROOT)/modules/nrfx/drivers/src/nrfx_wdt.c

# Source files - nRF Libraries
SRC_FILES += $(SDK_ROOT)/components/libraries/util/app_error.c
SRC_FILES += $(SDK_ROOT)/components/libraries/util/app_error_handler_gcc.c
SRC_FILES += $(SDK_ROOT)/components/libraries/util/app_error_weak.c
SRC_FILES += $(SDK_ROOT)/components/libraries/scheduler/app_scheduler.c
SRC_FILES += $(SDK_ROOT)/components/libraries/timer/app_timer2.c
SRC_FILES += $(SDK_ROOT)/components/libraries/util/app_util_platform.c
SRC_FILES += $(SDK_ROOT)/components/libraries/timer/drv_rtc.c
SRC_FILES += $(SDK_ROOT)/components/libraries/fds/fds.c
SRC_FILES += $(SDK_ROOT)/components/libraries/util/nrf_assert.c
SRC_FILES += $(SDK_ROOT)/components/libraries/atomic_fifo/nrf_atfifo.c
SRC_FILES += $(SDK_ROOT)/components/libraries/atomic_flags/nrf_atflags.c
SRC_FILES += $(SDK_ROOT)/components/libraries/atomic/nrf_atomic.c
SRC_FILES += $(SDK_ROOT)/components/libraries/balloc/nrf_balloc.c
SRC_FILES += $(SDK_ROOT)/components/libraries/bootloader/dfu/nrf_dfu_svci.c
SRC_FILES += $(SDK_ROOT)/external/fprintf/nrf_fprintf.c
SRC_FILES += $(SDK_ROOT)/external/fprintf/nrf_fprintf_format.c
SRC_FILES += $(SDK_ROOT)/components/libraries/fstorage/nrf_fstorage.c
SRC_FILES += $(SDK_ROOT)/components/libraries/fstorage/nrf_fstorage_sd.c
SRC_FILES += $(SDK_ROOT)/components/libraries/memobj/nrf_memobj.c
SRC_FILES += $(SDK_ROOT)/components/libraries/pwr_mgmt/nrf_pwr_mgmt.c
SRC_FILES += $(SDK_ROOT)/components/libraries/ringbuf/nrf_ringbuf.c
SRC_FILES += $(SDK_ROOT)/components/libraries/experimental_section_vars/nrf_section_iter.c
SRC_FILES += $(SDK_ROOT)/components/libraries/sortlist/nrf_sortlist.c
SRC_FILES += $(SDK_ROOT)/components/libraries/strerror/nrf_strerror.c

# RTT Logging support (optional, disabled by default)
# Enable with: make ENABLE_RTT=1
ENABLE_RTT ?= 0

# Source files - nRF Log (only if RTT is enabled)
ifeq ($(ENABLE_RTT),1)
SRC_FILES += $(SDK_ROOT)/components/libraries/log/src/nrf_log_backend_rtt.c
SRC_FILES += $(SDK_ROOT)/components/libraries/log/src/nrf_log_backend_serial.c
SRC_FILES += $(SDK_ROOT)/components/libraries/log/src/nrf_log_default_backends.c
SRC_FILES += $(SDK_ROOT)/components/libraries/log/src/nrf_log_frontend.c
SRC_FILES += $(SDK_ROOT)/components/libraries/log/src/nrf_log_str_formatter.c

# Source files - Segger RTT
SRC_FILES += $(SDK_ROOT)/external/segger_rtt/SEGGER_RTT.c
SRC_FILES += $(SDK_ROOT)/external/segger_rtt/SEGGER_RTT_printf.c
SRC_FILES += $(SDK_ROOT)/external/segger_rtt/SEGGER_RTT_Syscalls_GCC.c
endif

# Source files - SoftDevice
SRC_FILES += $(SDK_ROOT)/components/softdevice/common/nrf_sdh.c
SRC_FILES += $(SDK_ROOT)/components/softdevice/common/nrf_sdh_ble.c
SRC_FILES += $(SDK_ROOT)/components/softdevice/common/nrf_sdh_soc.c

# Source files - Startup
SRC_FILES += $(SDK_ROOT)/modules/nrfx/mdk/system_nrf52.c

# Assembly files (GCC version)
ASM_FILES += $(SDK_ROOT)/modules/nrfx/mdk/gcc_startup_nrf52811.S

# Include directories
INC_FOLDERS += $(PROJECT_ROOT)
INC_FOLDERS += $(PROJECT_ROOT)/EPD
# GUI include folder removed - GUI files not used in current implementation
# INC_FOLDERS += $(PROJECT_ROOT)/GUI
INC_FOLDERS += $(SDK_ROOT)
INC_FOLDERS += $(SDK_ROOT)/components/ble/common
INC_FOLDERS += $(SDK_ROOT)/components/ble/ble_advertising
INC_FOLDERS += $(SDK_ROOT)/components/ble/nrf_ble_gatt
INC_FOLDERS += $(SDK_ROOT)/components/ble/ble_services/ble_dfu
INC_FOLDERS += $(SDK_ROOT)/components/libraries/atomic
INC_FOLDERS += $(SDK_ROOT)/components/libraries/atomic_fifo
INC_FOLDERS += $(SDK_ROOT)/components/libraries/atomic_flags
INC_FOLDERS += $(SDK_ROOT)/components/libraries/balloc
INC_FOLDERS += $(SDK_ROOT)/components/libraries/bootloader
INC_FOLDERS += $(SDK_ROOT)/components/libraries/bootloader/ble_dfu
INC_FOLDERS += $(SDK_ROOT)/components/libraries/bootloader/dfu
INC_FOLDERS += $(SDK_ROOT)/components/libraries/delay
INC_FOLDERS += $(SDK_ROOT)/components/libraries/fstorage
INC_FOLDERS += $(SDK_ROOT)/components/libraries/fds
INC_FOLDERS += $(SDK_ROOT)/components/libraries/experimental_section_vars
# Include directories - nRF Log (always needed for header, even when disabled)
INC_FOLDERS += $(SDK_ROOT)/components/libraries/log
INC_FOLDERS += $(SDK_ROOT)/components/libraries/log/src
INC_FOLDERS += $(SDK_ROOT)/components/libraries/memobj
INC_FOLDERS += $(SDK_ROOT)/components/libraries/mutex
INC_FOLDERS += $(SDK_ROOT)/components/libraries/pwr_mgmt
INC_FOLDERS += $(SDK_ROOT)/components/libraries/ringbuf
INC_FOLDERS += $(SDK_ROOT)/components/libraries/sortlist
INC_FOLDERS += $(SDK_ROOT)/components/libraries/scheduler
INC_FOLDERS += $(SDK_ROOT)/components/libraries/strerror
INC_FOLDERS += $(SDK_ROOT)/components/libraries/svc
INC_FOLDERS += $(SDK_ROOT)/components/libraries/timer
INC_FOLDERS += $(SDK_ROOT)/components/libraries/util
INC_FOLDERS += $(SDK_ROOT)/components/softdevice/common
INC_FOLDERS += $(SDK_ROOT)/components/softdevice/s112/headers
INC_FOLDERS += $(SDK_ROOT)/components/softdevice/s112/headers/nrf52
INC_FOLDERS += $(SDK_ROOT)/components/toolchain/cmsis/include
INC_FOLDERS += $(SDK_ROOT)/external/fprintf
# Include directories - Segger RTT (only if RTT is enabled)
ifeq ($(ENABLE_RTT),1)
INC_FOLDERS += $(SDK_ROOT)/external/segger_rtt
endif
INC_FOLDERS += $(SDK_ROOT)/integration/nrfx
INC_FOLDERS += $(SDK_ROOT)/integration/nrfx/legacy
INC_FOLDERS += $(SDK_ROOT)/modules/nrfx
INC_FOLDERS += $(SDK_ROOT)/modules/nrfx/mdk
INC_FOLDERS += $(SDK_ROOT)/modules/nrfx/drivers/include
INC_FOLDERS += $(SDK_ROOT)/modules/nrfx/hal
INC_FOLDERS += $(SDK_ROOT)/external/nrf_oberon/include

# Compiler defines
CFLAGS += -DAPP_TIMER_V2
CFLAGS += -DAPP_TIMER_V2_RTC1_ENABLED
CFLAGS += -DCONFIG_GPIO_AS_PINRESET
CFLAGS += -DDEVELOP_IN_NRF52840
CFLAGS += -DFLOAT_ABI_SOFT
CFLAGS += -DNRF52811_XXAA
CFLAGS += -DNRFX_COREDEP_DELAY_US_LOOP_CYCLES=3
CFLAGS += -DNRF_DFU_SVCI_ENABLED
CFLAGS += -DNRF_DFU_TRANSPORT_BLE=1
CFLAGS += -DNRF_SD_BLE_API_VERSION=7
# Define version strings - use separate defines for major/minor to avoid quote issues
CFLAGS += -DBUILD_VERSION_MAJOR=$(MAJOR_VERSION)
CFLAGS += -DBUILD_VERSION_MINOR=$(MINOR_VERSION)
# Pass SHA value (if provided) - header will construct SHA_STRING from it
ifneq ($(SHA_VALUE),)
CFLAGS += -DSHA_VALUE=$(shell echo '"$(SHA_VALUE)"')
endif
CFLAGS += -DAPP_VERSION=$(APP_VERSION)
CFLAGS += -DS112
CFLAGS += -DSOFTDEVICE_PRESENT
CFLAGS += -D__HEAP_SIZE=8192
CFLAGS += -D__STACK_SIZE=2048
# Enable logging (only if RTT is enabled)
ifeq ($(ENABLE_RTT),1)
CFLAGS += -DNRF_LOG_ENABLED=1
CFLAGS += -DNRF_LOG_DEFAULT_LEVEL=4
else
CFLAGS += -DNRF_LOG_ENABLED=0
endif

# Compiler flags
CFLAGS += -mcpu=cortex-m4
CFLAGS += -mthumb -mabi=aapcs
CFLAGS += -Wall -Werror
CFLAGS += -Wno-array-bounds  # Disable array-bounds warning (SDK code triggers false positives)
CFLAGS += -mfloat-abi=soft
CFLAGS += -ffunction-sections -fdata-sections
CFLAGS += -fno-strict-aliasing
CFLAGS += -fno-builtin -fshort-enums
CFLAGS += -std=c99
# Optimization: Keil uses Optim=4 (equivalent to -O3)
# Default: -Os (optimize for size) to fit with bootloader
# Override with OPT_LEVEL=O2 or OPT_LEVEL=O3 for testing if needed
OPT_LEVEL ?= Os
CFLAGS += -$(OPT_LEVEL) -g3
# Prevent removal of critical initialization code
CFLAGS += -fno-omit-frame-pointer
# Ensure main and SystemInit are not optimized away  
CFLAGS += -fno-inline-functions-called-once
# Disable -flto as it can cause issues with startup/initialization code
# CFLAGS += -flto

# Add include paths
CFLAGS += $(addprefix -I,$(INC_FOLDERS))

# Assembly flags
ASMFLAGS += -mcpu=cortex-m4
ASMFLAGS += -mthumb -mabi=aapcs
ASMFLAGS += -mfloat-abi=soft
ASMFLAGS += -x assembler-with-cpp

# Linker flags
LDFLAGS += -mthumb -mabi=aapcs -L$(SDK_ROOT)/modules/nrfx/mdk -T$(CURDIR)/nrf52811_xxaa_s112.ld
LDFLAGS += -Xlinker -Map=$(OUTPUT_DIRECTORY)/$(TARGET).map
LDFLAGS += -mcpu=cortex-m4
LDFLAGS += -mfloat-abi=soft --specs=nano.specs
LDFLAGS += -Wl,--gc-sections -Wl,--build-id=none
LDFLAGS += -Wl,-z,muldefs
# Keep main and critical initialization functions
LDFLAGS += -Wl,--undefined=main
LDFLAGS += -Wl,--undefined=SystemInit
# Disable -flto as it can cause issues with startup/initialization
# LDFLAGS += -flto
# Oberon crypto library (soft-float, Cortex-M4 for nRF52811)
OBERON_LIB_DIR = $(SDK_ROOT)/external/nrf_oberon/lib/cortex-m4/soft-float
LDFLAGS += -L$(OBERON_LIB_DIR)
LDFLAGS += -Wl,--start-group -lc -lnosys -lm -Wl,--end-group

# Object files - convert source paths to object paths
# Project files: PROJECT_ROOT/... -> OUTPUT_DIRECTORY/...
# SDK files: SDK_ROOT/... -> OUTPUT_DIRECTORY/sdk/...
OBJ_FILES = $(foreach src,$(filter $(PROJECT_ROOT)/%,$(SRC_FILES)),$(OUTPUT_DIRECTORY)/$(patsubst $(PROJECT_ROOT)/%,%,$(src:.c=.o)))
OBJ_FILES += $(foreach src,$(filter $(SDK_ROOT)/%,$(SRC_FILES)),$(OUTPUT_DIRECTORY)/sdk/$(patsubst $(SDK_ROOT)/%,%,$(src:.c=.o)))
# Handle both .s and .S assembly files
OBJ_FILES += $(foreach src,$(filter %.s,$(ASM_FILES)),$(OUTPUT_DIRECTORY)/sdk/$(patsubst $(SDK_ROOT)/%,%,$(src:.s=.o)))
OBJ_FILES += $(foreach src,$(filter %.S,$(ASM_FILES)),$(OUTPUT_DIRECTORY)/sdk/$(patsubst $(SDK_ROOT)/%,%,$(src:.S=.o)))

# Default target - build full firmware with bootloader
all: $(OUTPUT_DIRECTORY)/$(TARGET)-full.hex

# Convenience targets
app: $(OUTPUT_DIRECTORY)/$(TARGET).hex
full: $(OUTPUT_DIRECTORY)/$(TARGET)-full.hex
sd: $(OUTPUT_DIRECTORY)/$(TARGET)-sd.hex
mbr-sd: $(OUTPUT_DIRECTORY)/$(TARGET)-mbr-sd.hex

# Create output directory structure
$(OUTPUT_DIRECTORY):
	@mkdir -p $(OUTPUT_DIRECTORY)
	@mkdir -p $(OUTPUT_DIRECTORY)/EPD
	@mkdir -p $(OUTPUT_DIRECTORY)/GUI
	@mkdir -p $(OUTPUT_DIRECTORY)/sdk

# Compile project C files
$(OUTPUT_DIRECTORY)/%.o: $(PROJECT_ROOT)/%.c | $(OUTPUT_DIRECTORY)
	@echo "Compiling: $<"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

# Compile SDK C files
$(OUTPUT_DIRECTORY)/sdk/%.o: $(SDK_ROOT)/%.c | $(OUTPUT_DIRECTORY)
	@echo "Compiling: $<"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

# Compile project assembly files
$(OUTPUT_DIRECTORY)/%.o: $(PROJECT_ROOT)/%.s | $(OUTPUT_DIRECTORY)
	@echo "Assembling: $<"
	@mkdir -p $(dir $@)
	@$(CC) $(ASMFLAGS) -c $< -o $@

# Compile SDK assembly files (.s)
$(OUTPUT_DIRECTORY)/sdk/%.o: $(SDK_ROOT)/%.s | $(OUTPUT_DIRECTORY)
	@echo "Assembling: $<"
	@mkdir -p $(dir $@)
	@$(CC) $(ASMFLAGS) -c $< -o $@

# Compile SDK assembly files (.S - with C preprocessor)
$(OUTPUT_DIRECTORY)/sdk/%.o: $(SDK_ROOT)/%.S | $(OUTPUT_DIRECTORY)
	@echo "Assembling: $<"
	@mkdir -p $(dir $@)
	@$(CC) $(ASMFLAGS) -c $< -o $@

# Link (Oberon library must come after OBJ_FILES so linker resolves symbols)
$(OUTPUT_DIRECTORY)/$(TARGET).out: $(OBJ_FILES) | $(OUTPUT_DIRECTORY)
	@echo "Linking: $@"
	@$(CC) $(LDFLAGS) -o $@ $(OBJ_FILES) -loberon_3.0.8
	@$(SIZE) $@

# Create hex file
$(OUTPUT_DIRECTORY)/$(TARGET).hex: $(OUTPUT_DIRECTORY)/$(TARGET).out
	@echo "Creating hex file: $@"
	@$(OBJCOPY) -O ihex $< $@

# Create binary file
$(OUTPUT_DIRECTORY)/$(TARGET).bin: $(OUTPUT_DIRECTORY)/$(TARGET).out
	@echo "Creating binary file: $@"
	@$(OBJCOPY) -O binary $< $@

# Paths to bootloader and softdevice
BOOTLOADER_HEX = $(PROJECT_ROOT)/tools/bootloader/bl_nrf52811_xxaa_s112.hex
SOFTDEVICE_HEX = $(SDK_ROOT)/components/softdevice/s112/hex/s112_nrf52_7.3.0_softdevice.hex
MBR_HEX = $(SDK_ROOT)/components/softdevice/mbr/hex/mbr_nrf52_2.4.1_mbr.hex
KEY_FILE ?= $(PROJECT_ROOT)/tools/priv.pem
DFU_SETTINGS_HEX = $(OUTPUT_DIRECTORY)/$(TARGET)-settings.hex
DFU_OTA_ZIP = $(OUTPUT_DIRECTORY)/$(TARGET)-ota.zip
# Version configuration: can set MAJOR/MINOR or APP_VERSION directly
MAJOR_VERSION ?= 1
MINOR_VERSION ?= 0
# APP_VERSION: if not explicitly set, calculate from MAJOR.MINOR (as single incrementing number)
# Format: major * 100 + minor (e.g., 1.0 = 100, 1.5 = 105, 2.0 = 200)
# Or use hex format like 0x19 (25 decimal) for legacy compatibility
# Note: nrfutil expects a decimal number, not hex
APP_VERSION ?= $(shell echo $$(( $(MAJOR_VERSION) * 100 + $(MINOR_VERSION) )))
BOOTLOADER_VERSION ?= 1
BL_SETTINGS_VERSION ?= 1
DFU_HW_VERSION ?= 52

# Build version string for firmware reporting (e.g., "1.0")
# Allow manual override of SHA, otherwise auto-detect from git
SHA ?= $(shell cd $(PROJECT_ROOT) && git rev-parse --short HEAD 2>/dev/null || echo "")
# Use shell echo to properly escape quotes for compiler -D flag
BUILD_VERSION_STR = $(shell echo '"$(MAJOR_VERSION).$(MINOR_VERSION)"')
# For SHA_STRING: pass SHA value and let header construct the string
# This avoids quote escaping issues with -D flags
SHA_VALUE = $(if $(SHA),$(SHA),)
DFU_FAMILY ?= NRF52810
DFU_SD_ID ?= 0x126
DFU_SD_REQ ?= 0x126

# Check if mergehex is available
MERGEHEX := $(shell which mergehex 2>/dev/null)
# Prefer system-installed native nrfutil binary (non-Python version)
# Fall back to Python 3.11 nordicsemi if system binary not found
NRFUTIL ?= $(shell if [ -x /usr/bin/nrfutil ]; then echo "/usr/bin/nrfutil"; elif python3.11 -m nordicsemi --help >/dev/null 2>&1; then echo "python3.11 -m nordicsemi"; else which nrfutil 2>/dev/null; fi)
GENERATE_OTA ?= 0

# Merge softdevice + application (no bootloader)
$(OUTPUT_DIRECTORY)/$(TARGET)-sd.hex: $(OUTPUT_DIRECTORY)/$(TARGET).hex
	@if [ -z "$(MERGEHEX)" ]; then \
		echo "Error: mergehex not found. Install nRF Command Line Tools."; \
		echo "  Arch/Manjaro: sudo pacman -S nrf-command-line-tools"; \
		echo "  Or download from: https://www.nordicsemi.com/Software-and-tools/Development-Tools/nRF-Command-Line-Tools"; \
		exit 1; \
	fi
	@echo "Merging softdevice + application: $@"
	@$(MERGEHEX) -m $(SOFTDEVICE_HEX) $(OUTPUT_DIRECTORY)/$(TARGET).hex -o $@
	@echo "Created: $@"

# Merge MBR + softdevice + application (no bootloader, with MBR)
$(OUTPUT_DIRECTORY)/$(TARGET)-mbr-sd.hex: $(OUTPUT_DIRECTORY)/$(TARGET).hex
	@if [ -z "$(MERGEHEX)" ]; then \
		echo "Error: mergehex not found. Install nRF Command Line Tools."; \
		exit 1; \
	fi
	@echo "Merging MBR + softdevice + application: $@"
	@$(MERGEHEX) -m $(MBR_HEX) $(SOFTDEVICE_HEX) $(OUTPUT_DIRECTORY)/$(TARGET).hex -o $@
	@echo "Created: $@"

# Generate signed OTA zip and bootloader settings (required for bootloader to accept app)
$(DFU_SETTINGS_HEX): $(OUTPUT_DIRECTORY)/$(TARGET).hex
	@if [ -z "$(NRFUTIL)" ]; then \
		echo "Error: nrfutil not found. Install nrfutil to generate DFU settings."; \
		exit 1; \
	fi
	@if [ ! -r "$(KEY_FILE)" ]; then \
		echo "Error: Private key not found: $(KEY_FILE)"; \
		echo "This bootloader expects signed firmware. Copy the matching private key and retry:"; \
		echo "  make full KEY_FILE=/absolute/path/to/priv.pem"; \
		exit 1; \
	fi
	@if [ "$(GENERATE_OTA)" = "1" ]; then \
		echo "Generating OTA package: $(DFU_OTA_ZIP)"; \
		if $(NRFUTIL) nrf5sdk-tools pkg generate --help >/dev/null 2>&1; then \
			$(NRFUTIL) nrf5sdk-tools pkg generate \
				--application $(OUTPUT_DIRECTORY)/$(TARGET).hex \
				--key-file $(KEY_FILE) \
				--hw-version $(DFU_HW_VERSION) \
				--sd-req $(DFU_SD_REQ) \
				--application-version 222 \
				$(DFU_OTA_ZIP); \
		else \
			$(NRFUTIL) pkg generate \
				--application $(OUTPUT_DIRECTORY)/$(TARGET).hex \
				--key-file $(KEY_FILE) \
				--hw-version $(DFU_HW_VERSION) \
				--sd-req $(DFU_SD_REQ) \
				--application-version 222 \
				$(DFU_OTA_ZIP); \
		fi; \
	else \
		echo "Skipping OTA package generation (GENERATE_OTA=0)"; \
	fi
	@echo "Generating bootloader settings: $(DFU_SETTINGS_HEX)"
	@if $(NRFUTIL) nrf5sdk-tools settings generate --help >/dev/null 2>&1; then \
		echo "Using new modular nrfutil syntax: nrf5sdk-tools settings"; \
		$(NRFUTIL) nrf5sdk-tools settings generate \
			--family $(DFU_FAMILY) \
			--application $(OUTPUT_DIRECTORY)/$(TARGET).hex \
			--softdevice $(SOFTDEVICE_HEX) \
			--application-version $(APP_VERSION) \
			--bootloader-version $(BOOTLOADER_VERSION) \
			--bl-settings-version $(BL_SETTINGS_VERSION) \
			--key-file $(KEY_FILE) \
			--no-backup \
			$(DFU_SETTINGS_HEX) || (echo ""; echo "Error: Failed to generate settings with nrf5sdk-tools."; echo "If you see 'command not found', install it with: nrfutil install nrf5sdk-tools"; exit 1); \
	elif $(NRFUTIL) settings generate --help >/dev/null 2>&1; then \
		echo "Using legacy nrfutil syntax: settings"; \
		$(NRFUTIL) settings generate \
			--family $(DFU_FAMILY) \
			--application $(OUTPUT_DIRECTORY)/$(TARGET).hex \
			--softdevice $(SOFTDEVICE_HEX) \
			--application-version $(APP_VERSION) \
			--bootloader-version $(BOOTLOADER_VERSION) \
			--bl-settings-version $(BL_SETTINGS_VERSION) \
			--key-file $(KEY_FILE) \
			--no-backup \
			$(DFU_SETTINGS_HEX); \
	else \
		echo "Error: Neither 'nrfutil nrf5sdk-tools settings' nor 'nrfutil settings' command found."; \
		echo "For new modular nrfutil, install: nrfutil install nrf5sdk-tools"; \
		echo "Or use legacy Python-based nrfutil if available."; \
		exit 1; \
	fi

# Merge bootloader + softdevice + application + settings (complete bootable firmware)
$(OUTPUT_DIRECTORY)/$(TARGET)-full.hex: $(OUTPUT_DIRECTORY)/$(TARGET).hex $(DFU_SETTINGS_HEX)
	@if [ -z "$(MERGEHEX)" ]; then \
		echo "Error: mergehex not found. Install nRF Command Line Tools."; \
		exit 1; \
	fi
	@if [ ! -f "$(BOOTLOADER_HEX)" ]; then \
		echo "Error: Bootloader hex not found: $(BOOTLOADER_HEX)"; \
		exit 1; \
	fi
	@if [ ! -f "$(SOFTDEVICE_HEX)" ]; then \
		echo "Error: Softdevice hex not found: $(SOFTDEVICE_HEX)"; \
		exit 1; \
	fi
	@echo "Merging softdevice + bootloader + application + settings: $@"
	@if $(MERGEHEX) -m $(SOFTDEVICE_HEX) $(BOOTLOADER_HEX) $(OUTPUT_DIRECTORY)/$(TARGET).hex -o $@ 2>&1; then \
		$(MERGEHEX) -m $@ $(DFU_SETTINGS_HEX) -o $@; \
		echo "Created: $@ (complete firmware with bootloader + settings)"; \
	else \
		echo ""; \
		echo "WARNING: Failed to merge bootloader (application may be too large)."; \
		echo "Creating softdevice + application only instead..."; \
		$(MERGEHEX) -m $(SOFTDEVICE_HEX) $(OUTPUT_DIRECTORY)/$(TARGET).hex -o $@; \
		echo "Created: $@ (softdevice + application, bootloader must be flashed separately)"; \
		echo "Note: Bootloader can be flashed separately with:"; \
		echo "  nrfjprog --program $(BOOTLOADER_HEX)"; \
	fi

# Clean
clean:
	@echo "Cleaning..."
	@rm -rf $(OUTPUT_DIRECTORY)

# J-Link flashing tools
NRFJPROG ?= nrfjprog
JLINKEXE ?= JLinkExe
JLINKRTTCLIENT ?= JLinkRTTClient
JLINKRTTLOGGER ?= JLinkRTTLogger
PYOCD ?= pyocd

# Install target: clean, build sd and flash to device
# Usage: make install          - Flash complete firmware (bootloader + softdevice + app)
#        make install RTT=1    - Flash firmware and start RTT monitoring
install: clean full
	@echo "Flashing complete firmware (bootloader + softdevice + app) to device..."
	@if command -v $(NRFJPROG) >/dev/null 2>&1; then \
		echo "Using nrfjprog..."; \
		$(NRFJPROG) --program $(OUTPUT_DIRECTORY)/$(TARGET)-full.hex --chiperase --verify --reset; \
	elif command -v $(JLINKEXE) >/dev/null 2>&1; then \
		echo "Using JLinkExe..."; \
		echo "r" > /tmp/jlink_flash.jlink; \
		echo "loadfile $(CURDIR)/$(OUTPUT_DIRECTORY)/$(TARGET)-full.hex" >> /tmp/jlink_flash.jlink; \
		echo "r" >> /tmp/jlink_flash.jlink; \
		echo "g" >> /tmp/jlink_flash.jlink; \
		echo "exit" >> /tmp/jlink_flash.jlink; \
		$(JLINKEXE) -device NRF52811_XXAA -if SWD -speed 4000 -autoconnect 1 -CommanderScript /tmp/jlink_flash.jlink; \
		rm -f /tmp/jlink_flash.jlink; \
	else \
		echo "ERROR: Neither nrfjprog nor JLinkExe found!"; \
		echo "Please install nRF Command Line Tools (nrfjprog) or SEGGER J-Link Software"; \
		exit 1; \
	fi
	@echo "Firmware flashed successfully!"
	@if [ "$(RTT)" = "1" ]; then \
		echo ""; \
		echo "Starting RTT monitoring..."; \
		echo "Press Ctrl+C to stop"; \
		if command -v $(PYOCD) >/dev/null 2>&1; then \
			echo "Using pyocd RTT (simplest method)..."; \
			echo "Note: Using 'attach' mode to avoid halting CPU (BLE will work)"; \
			echo ""; \
			trap 'exit' INT TERM; \
			$(PYOCD) rtt -t nrf52811_xxaa -M attach || true; \
		elif command -v $(JLINKEXE) >/dev/null 2>&1 && command -v $(JLINKRTTCLIENT) >/dev/null 2>&1; then \
			echo "Starting J-Link RTT Server in background..."; \
			($(JLINKEXE) -device NRF52811_XXAA -if SWD -speed 4000 -autoconnect 1 -RTTTelnetPort 19021; exec sleep infinity) > /tmp/jlink_rtt.log 2>&1 & \
			JLINK_PID=$$!; \
			echo "Waiting for RTT server to start (PID: $$JLINK_PID)..."; \
			sleep 5; \
			if ! kill -0 $$JLINK_PID 2>/dev/null; then \
				echo "ERROR: JLinkExe failed to start. Check /tmp/jlink_rtt.log"; \
				cat /tmp/jlink_rtt.log 2>/dev/null || true; \
				rm -f /tmp/jlink_rtt.log; \
				exit 1; \
			fi; \
			echo "Connecting RTT Client (logs will appear below)..."; \
			echo ""; \
			trap 'kill $$JLINK_PID 2>/dev/null; rm -f /tmp/jlink_rtt.log; exit' INT TERM; \
			$(JLINKRTTCLIENT) || true; \
			kill $$JLINK_PID 2>/dev/null || true; \
			rm -f /tmp/jlink_rtt.log; \
		else \
			echo "Note: RTT monitoring requires pyocd, or JLinkExe and JLinkRTTClient."; \
			echo ""; \
			echo "Alternative: Use JLinkRTTViewer GUI (recommended):"; \
			echo "  JLinkRTTViewer"; \
			echo "Then configure: Device=NRF52811_XXAA, Interface=SWD, Speed=4000"; \
		fi; \
	fi

# Help
help:
	@echo "Available targets:"
	@echo "  all              - Build complete firmware (bootloader + softdevice + app) [default]"
	@echo "  app              - Build the firmware application only"
	@echo "  full             - Build complete firmware (bootloader + softdevice + app)"
	@echo "  sd               - Build firmware with softdevice (no bootloader)"
	@echo "  mbr-sd           - Build firmware with MBR + softdevice (no bootloader)"
	@echo "  install          - Clean, build full firmware and flash to device via J-Link"
	@echo "  install RTT=1    - Clean, build full firmware, flash and start RTT monitoring"
	@echo "  clean            - Remove build files"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "DFU/Bootloader signing (required for make all/full):"
	@echo "  KEY_FILE=$(KEY_FILE)"
	@echo "  make KEY_FILE=/absolute/path/to/priv.pem"
	@echo "  make full KEY_FILE=/absolute/path/to/priv.pem"
	@echo "  make GENERATE_OTA=1 KEY_FILE=/absolute/path/to/priv.pem"
	@echo ""
	@echo "RTT Logging (disabled by default):"
	@echo "  make ENABLE_RTT=1        - Build with RTT logging enabled"
	@echo "  make clean ENABLE_RTT=1  - Clean and build with RTT logging"
	@echo "  make install ENABLE_RTT=1 RTT=1 - Build with RTT, flash and start monitoring"
	@echo ""
	@echo "Version configuration (default: MAJOR=1, MINOR=0, APP_VERSION=100):"
	@echo "  make MAJOR_VERSION=2 MINOR_VERSION=5  - Set version to 2.5 (APP_VERSION=205)"
	@echo "  make APP_VERSION=123                  - Set APP_VERSION directly (overrides MAJOR/MINOR)"
	@echo "  make SHA=abc123def                    - Override git SHA (default: auto-detect from git)"
	@echo "  Version format: APP_VERSION = MAJOR * 100 + MINOR (e.g., 1.0 = 100, 2.5 = 205)"
	@echo ""
	@echo "Output files:"
	@echo "  _build/$(TARGET).hex         - Application only"
	@echo "  _build/$(TARGET)-sd.hex      - Softdevice + Application"
	@echo "  _build/$(TARGET)-mbr-sd.hex  - MBR + Softdevice + Application"
	@echo "  _build/$(TARGET)-full.hex    - Bootloader + Softdevice + Application (complete)"
	@echo ""
	@echo "Toolchain: $(GNU_INSTALL_ROOT)/$(GNU_PREFIX)-gcc"
	@echo "Version: $(GNU_VERSION)"
	@if [ -z "$(MERGEHEX)" ]; then \
		echo ""; \
		echo "Warning: mergehex not found. Install nRF Command Line Tools for merging."; \
	fi

.PHONY: all clean help full sd mbr-sd install
