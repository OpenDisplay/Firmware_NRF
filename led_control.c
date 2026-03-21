#include "led_control.h"
#include "constants.h"
#include "EPD_driver.h"
#include "structs.h"
#include "main.h"
#include "hal/hal.h"

static uint8_t activeLedInstance = LED_INSTANCE_NONE;  // LED instance index for flashing
static bool ledFlashActive = false;       // Flag to indicate if LED flashing is active
static uint8_t ledFlashPosition = 0;      // Current position in LED flash pattern group

extern struct GlobalConfig globalConfig;

void flashLed(uint8_t color, uint8_t brightness) {
    if (activeLedInstance == LED_INSTANCE_NONE) {
        for (uint8_t i = 0; i < globalConfig.led_count; i++) {
            if (globalConfig.leds[i].led_type == 1) {  // RGB LED type
                activeLedInstance = i;
                break;
            }
        }
        if (activeLedInstance == LED_INSTANCE_NONE) {
            return;  // No RGB LED configured
        }
    }
    struct LedConfig* led = &globalConfig.leds[activeLedInstance];
    uint8_t ledRedPin = led->led_1_r;
    uint8_t ledGreenPin = led->led_2_g;
    uint8_t ledBluePin = led->led_3_b;
    bool invertRed = (led->led_flags & LED_FLAG_INVERT_RED) != 0;
    bool invertGreen = (led->led_flags & LED_FLAG_INVERT_GREEN) != 0;
    bool invertBlue = (led->led_flags & LED_FLAG_INVERT_BLUE) != 0;
    uint8_t colorred = (color >> 5) & 0b00000111;
    uint8_t colorgreen = (color >> 2) & 0b00000111;
    uint8_t colorblue = color & 0b00000011;
    
    for (uint16_t i = 0; i < brightness; i++) {
        digitalWrite(ledRedPin, invertRed ? !(colorred >= 7) : (colorred >= 7));
        digitalWrite(ledGreenPin, invertGreen ? !(colorgreen >= 7) : (colorgreen >= 7));
        digitalWrite(ledBluePin, invertBlue ? !(colorblue >= 3) : (colorblue >= 3));
        hal_delay_us(LED_PWM_DELAY_US);
        digitalWrite(ledRedPin, invertRed ? !(colorred >= 1) : (colorred >= 1));
        digitalWrite(ledGreenPin, invertGreen ? !(colorgreen >= 1) : (colorgreen >= 1));
        hal_delay_us(LED_PWM_DELAY_US);
        digitalWrite(ledRedPin, invertRed ? !(colorred >= 6) : (colorred >= 6));
        digitalWrite(ledGreenPin, invertGreen ? !(colorgreen >= 6) : (colorgreen >= 6));
        digitalWrite(ledBluePin, invertBlue ? !(colorblue >= 1) : (colorblue >= 1));
        hal_delay_us(LED_PWM_DELAY_US);
        digitalWrite(ledRedPin, invertRed ? !(colorred >= 2) : (colorred >= 2));
        digitalWrite(ledGreenPin, invertGreen ? !(colorgreen >= 2) : (colorgreen >= 2));
        hal_delay_us(LED_PWM_DELAY_US);
        digitalWrite(ledRedPin, invertRed ? !(colorred >= 5) : (colorred >= 5));
        digitalWrite(ledGreenPin, invertGreen ? !(colorgreen >= 5) : (colorgreen >= 5));
        hal_delay_us(LED_PWM_DELAY_US);
        digitalWrite(ledRedPin, invertRed ? !(colorred >= 3) : (colorred >= 3));
        digitalWrite(ledGreenPin, invertGreen ? !(colorgreen >= 3) : (colorgreen >= 3));
        digitalWrite(ledBluePin, invertBlue ? !(colorblue >= 2) : (colorblue >= 2));
        hal_delay_us(LED_PWM_DELAY_US);
        digitalWrite(ledRedPin, invertRed ? !(colorred >= 4) : (colorred >= 4));
        digitalWrite(ledGreenPin, invertGreen ? !(colorgreen >= 4) : (colorgreen >= 4));
        hal_delay_us(LED_PWM_DELAY_US);
        digitalWrite(ledRedPin, invertRed ? HIGH : LOW);
        digitalWrite(ledGreenPin, invertGreen ? HIGH : LOW);
        digitalWrite(ledBluePin, invertBlue ? HIGH : LOW);
    }
}

void ledFlashLogic(void) {
    if (!ledFlashActive) {
        return;
    }
    if (activeLedInstance == LED_INSTANCE_NONE) {
        for (uint8_t i = 0; i < globalConfig.led_count; i++) {
            if (globalConfig.leds[i].led_type == 1) {  // RGB LED type
                activeLedInstance = i;
                break;
            }
        }
        if (activeLedInstance == LED_INSTANCE_NONE) {
            NRF_LOG_ERROR("No RGB LED configured");
            return;
        }
    }
    struct LedConfig* led = &globalConfig.leds[activeLedInstance];
    uint8_t* ledcfg = led->reserved;
    uint8_t brightness = ((ledcfg[0] & LED_BRIGHTNESS_MASK) >> LED_BRIGHTNESS_SHIFT) + 1;  // Bits 4-7: brightness (1-16)
    uint8_t mode = ledcfg[0] & LED_MODE_MASK;  // Bits 0-3: mode
    if (mode == 1) {
        const uint8_t interloopdelayfactor = LED_DELAY_FACTOR;
        const uint8_t loopdelayfactor = LED_DELAY_FACTOR;
        uint8_t c1 = ledcfg[1];
        uint8_t c2 = ledcfg[4];
        uint8_t c3 = ledcfg[7];
        uint8_t loop1delay = (ledcfg[2] >> 4) & 0x0F;
        uint8_t loop2delay = (ledcfg[5] >> 4) & 0x0F;
        uint8_t loop3delay = (ledcfg[8] >> 4) & 0x0F;
        uint8_t loopcnt1 = ledcfg[2] & 0x0F;
        uint8_t loopcnt2 = ledcfg[5] & 0x0F;
        uint8_t loopcnt3 = ledcfg[8] & 0x0F;
        uint8_t ildelay1 = ledcfg[3];
        uint8_t ildelay2 = ledcfg[6];
        uint8_t ildelay3 = ledcfg[9];
        uint8_t grouprepeats = ledcfg[10] + 1;
        while (ledFlashActive) {
            if (ledFlashPosition >= grouprepeats && grouprepeats != 255) {
                brightness = 0;
                ledcfg[0] = 0x00;  // Disable mode
                ledFlashPosition = 0;
                break;
            }
            
            for (uint8_t i = 0; i < loopcnt1; i++) {
                flashLed(c1, brightness);
                hal_delay_ms(loop1delay * loopdelayfactor);
            }
            hal_delay_ms(ildelay1 * interloopdelayfactor);
            
            for (uint8_t i = 0; i < loopcnt2; i++) {
                flashLed(c2, brightness);
                hal_delay_ms(loop2delay * loopdelayfactor);
            }
            hal_delay_ms(ildelay2 * interloopdelayfactor);
            
            for (uint8_t i = 0; i < loopcnt3; i++) {
                flashLed(c3, brightness);
                hal_delay_ms(loop3delay * loopdelayfactor);
            }
            hal_delay_ms(ildelay3 * interloopdelayfactor);
            
            ledFlashPosition++;
        }
    }
}

void led_init(void) {
    if (globalConfig.led_count > 0) {
        for (uint8_t i = 0; i < globalConfig.led_count; i++) {
            struct LedConfig* led = &globalConfig.leds[i];
    bool invertRed = (led->led_flags & LED_FLAG_INVERT_RED) != 0;
    bool invertGreen = (led->led_flags & LED_FLAG_INVERT_GREEN) != 0;
    bool invertBlue = (led->led_flags & LED_FLAG_INVERT_BLUE) != 0;
    bool invertLed4 = (led->led_flags & LED_FLAG_INVERT_LED4) != 0;
            
            if (led->led_1_r != 0xFF) {
                pinMode(led->led_1_r, OUTPUT);
                digitalWrite(led->led_1_r, invertRed ? HIGH : LOW);
            }
            if (led->led_2_g != 0xFF) {
                pinMode(led->led_2_g, OUTPUT);
                digitalWrite(led->led_2_g, invertGreen ? HIGH : LOW);
            }
            if (led->led_3_b != 0xFF) {
                pinMode(led->led_3_b, OUTPUT);
                digitalWrite(led->led_3_b, invertBlue ? HIGH : LOW);
            }
            if (led->led_4 != 0xFF) {
                pinMode(led->led_4, OUTPUT);
                digitalWrite(led->led_4, invertLed4 ? HIGH : LOW);
            }
        }
        for (uint8_t i = 0; i < globalConfig.led_count; i++) {
            if (globalConfig.leds[i].led_type == 0) {
                activeLedInstance = i;
                flashLed(0xE0, 15);  // Red
                flashLed(0x1C, 15);  // Green
                flashLed(0x03, 15);  // Blue
                flashLed(0xFF, 15);  // White
            }
        }
    }
}

void led_activate(uint8_t instance) {
    activeLedInstance = instance;
}

void led_set_flash_active(bool active) {
    ledFlashActive = active;
    if (active) {
        ledFlashPosition = 0;
    }
}
