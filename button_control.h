#ifndef BUTTON_CONTROL_H__
#define BUTTON_CONTROL_H__

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint8_t button_id;          // Button ID (0-7, from instance_number + pin offset)
    uint8_t press_count;         // Press count (0-15)
    volatile uint32_t last_press_time;    // Timestamp of last press (seconds, updated in ISR)
    volatile uint8_t current_state;       // Current button state (0=released, 1=pressed, updated in ISR)
    uint8_t byte_index;          // Byte index in dynamicreturndata
    uint8_t pin;                 // GPIO pin number
    uint8_t instance_index;      // BinaryInputs instance index
    bool initialized;            // Whether this button is initialized
    uint8_t pin_offset;          // Pin offset within instance (0-7) for faster ISR lookup
    bool inverted;               // Inverted flag for this pin (cached for ISR)
} ButtonState;

#define MAX_BUTTONS 32  // Up to 4 instances * 8 pins = 32 buttons max

void button_init(void);

void process_button_events(void);

#endif // BUTTON_CONTROL_H__
