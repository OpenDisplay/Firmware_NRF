#include "encryption.h"
#include "config_storage.h"
#include "constants.h"
#include "EPD_service.h"
#include "nrf_log.h"

#include "ocrypto_aes_ccm.h"
#include "ocrypto_aes_cmac.h"
#include "ocrypto_aes_cbc.h"
#include "ocrypto_constant_time.h"

#include "nrf_soc.h"
#include "nrf.h"

#include "nrf_gpio.h"

#include <string.h>
#include <stdlib.h>

struct SecurityConfig  securityConfig  = {0};
struct EncryptionSession encryptionSession = {0};
bool encryptionInitialized = false;

extern uint32_t timestamp(void);

static uint32_t millis_approx(void) {
    return timestamp() * 1000;
}

bool aes_cmac(const uint8_t key[16], const uint8_t* msg, size_t msg_len,
              uint8_t tag[16])
{
    ocrypto_aes_cmac_authenticate(tag, 16, msg, msg_len, key, 16);
    return true;
}

bool aes_ecb_encrypt(const uint8_t key[16], const uint8_t in[16],
                     uint8_t out[16])
{
    uint8_t iv[16];
    memset(iv, 0, sizeof(iv));
    ocrypto_aes_cbc_encrypt(out, in, 16, key, 16, iv);
    return true;
}

bool aes_ccm_encrypt(const uint8_t key[16],
                     const uint8_t* nonce, size_t nonce_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* plaintext, size_t plaintext_len,
                     uint8_t* ciphertext,
                     uint8_t* tag, size_t tag_len)
{
    ocrypto_aes_ccm_encrypt(ciphertext, tag, tag_len,
                            plaintext, plaintext_len,
                            key, 16,
                            nonce, nonce_len,
                            aad, aad_len);
    return true;
}

bool aes_ccm_decrypt(const uint8_t key[16],
                     const uint8_t* nonce, size_t nonce_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* ciphertext, size_t ciphertext_len,
                     uint8_t* plaintext,
                     const uint8_t* tag, size_t tag_len)
{
    int rc = ocrypto_aes_ccm_decrypt(plaintext, tag, tag_len,
                                     ciphertext, ciphertext_len,
                                     key, 16,
                                     nonce, nonce_len,
                                     aad, aad_len);
    return (rc == 0);
}

void secure_random(uint8_t* output, size_t len)
{
    uint8_t available = 0;
    size_t offset = 0;

    while (offset < len) {
        uint8_t to_get = (uint8_t)((len - offset) > 255 ? 255 : (len - offset));
        uint32_t err = sd_rand_application_vector_get(output + offset, to_get);
        if (err == NRF_SUCCESS) {
            offset += to_get;
        } else {
            (void)sd_rand_application_bytes_available_get(&available);
            if (available == 0) {
                volatile uint32_t i = 0;
                while (i < 1000) i++;
            }
        }
    }
}

bool constantTimeCompare(const uint8_t* a, const uint8_t* b, size_t len)
{
    return ocrypto_constant_time_equal(a, b, len) == 1;
}

static bool deriveSessionKey(const uint8_t* master_key,
                             const uint8_t* client_nonce,
                             const uint8_t* server_nonce,
                             const uint8_t* device_id,
                             uint8_t* session_key)
{
    static const char label[] = "OpenDisplay session";

    uint8_t cmac_input[64];
    size_t offset = 0;
    memcpy(cmac_input + offset, label, strlen(label));
    offset += strlen(label);
    cmac_input[offset++] = 0x00; /* separator */
    memcpy(cmac_input + offset, device_id, 4);
    offset += 4;
    memcpy(cmac_input + offset, client_nonce, 16);
    offset += 16;
    memcpy(cmac_input + offset, server_nonce, 16);
    offset += 16;
    cmac_input[offset++] = 0x00; /* key-length high byte (128 bits) */
    cmac_input[offset++] = 0x80; /* key-length low  byte */
    uint8_t intermediate[16];
    if (!aes_cmac(master_key, cmac_input, offset, intermediate)) return false;
    uint8_t final_input[16];
    memset(final_input, 0, 8);
    final_input[7] = 0x01; /* counter = 1, big-endian */
    memcpy(final_input + 8, intermediate, 8);
    return aes_ecb_encrypt(master_key, final_input, session_key);
}

static void deriveSessionId(const uint8_t* session_key,
                            const uint8_t* client_nonce,
                            const uint8_t* server_nonce,
                            uint8_t* session_id)
{
    uint8_t input[32];
    memcpy(input, client_nonce, 16);
    memcpy(input + 16, server_nonce, 16);

    uint8_t cmac_output[16];
    if (aes_cmac(session_key, input, 32, cmac_output)) {
        memcpy(session_id, cmac_output, 8);
    } else {
        memset(session_id, 0, 8);
    }
}

void clearEncryptionSession(void)
{
    ocrypto_constant_time_fill_zero(encryptionSession.session_key, 16);
    encryptionSession.authenticated      = false;
    memset(encryptionSession.session_id, 0, 8);
    encryptionSession.nonce_counter      = 0;
    encryptionSession.last_seen_counter  = 0;
    memset(encryptionSession.replay_window, 0, sizeof(encryptionSession.replay_window));
    encryptionSession.replay_idx          = 0;
    encryptionSession.integrity_failures = 0;
    encryptionSession.last_activity      = 0;
    encryptionSession.session_start_time = 0;
    memset(encryptionSession.client_nonce, 0, 16);
    memset(encryptionSession.server_nonce, 0, 16);
    memset(encryptionSession.pending_server_nonce, 0, 16);
    encryptionSession.server_nonce_time  = 0;
}

bool isEncryptionEnabled(void)
{
    return (securityConfig.encryption_enabled != 0);
}

bool isAuthenticated(void)
{
    return encryptionSession.authenticated;
}

bool checkEncryptionSessionTimeout(void)
{
    if (!encryptionSession.authenticated) return false;
    if (securityConfig.session_timeout_seconds == 0) return true; /* no timeout */

    uint32_t now  = millis_approx();
    uint32_t elapsed = (now - encryptionSession.last_activity) / 1000;
    if (elapsed > securityConfig.session_timeout_seconds) {
        NRF_LOG_INFO("Session timed out");
        clearEncryptionSession();
        return false;
    }
    return true;
}

void updateEncryptionSessionActivity(void)
{
    encryptionSession.last_activity = millis_approx();
}

void getCurrentNonce(uint8_t* nonce)
{
    if (!encryptionSession.authenticated) {
        memset(nonce, 0, 16);
        return;
    }
    memcpy(nonce, encryptionSession.session_id, 8);
    uint64_t ctr = encryptionSession.nonce_counter;
    for (int i = 0; i < 8; i++) {
        nonce[8 + i] = (uint8_t)((ctr >> (56 - i * 8)) & 0xFF);
    }
}

void incrementNonceCounter(void)
{
    if (encryptionSession.authenticated) {
        encryptionSession.nonce_counter++;
        if (encryptionSession.nonce_counter == 0) {
            NRF_LOG_WARNING("Nonce counter wrapped, invalidating session");
            clearEncryptionSession();
        }
    }
}

bool verifyNonceReplay(uint8_t* nonce)
{
    if (!encryptionSession.authenticated) return false;

    uint8_t nonce_session_id[8];
    uint64_t nonce_counter = 0;
    memcpy(nonce_session_id, nonce, 8);
    for (int i = 0; i < 8; i++) {
        nonce_counter = (nonce_counter << 8) | nonce[8 + i];
    }

    if (!constantTimeCompare(nonce_session_id, encryptionSession.session_id, 8)) {
        NRF_LOG_ERROR("Nonce session_id mismatch");
        NRF_LOG_HEXDUMP_ERROR(nonce_session_id, 8);
        NRF_LOG_HEXDUMP_ERROR(encryptionSession.session_id, 8);
        return false;
    }

    int64_t diff = (int64_t)nonce_counter - (int64_t)encryptionSession.last_seen_counter;
    if (diff < -32 || diff > 32) {
        NRF_LOG_ERROR("Nonce counter outside replay window");
        return false;
    }

    if (nonce_counter <= encryptionSession.last_seen_counter && diff != 0) {
        bool already_seen = false;
        for (int i = 0; i < 64; i++) {
            if (encryptionSession.replay_window[i] == nonce_counter) {
                already_seen = true;
                break;
            }
        }
        if (already_seen) {
            NRF_LOG_ERROR("Nonce counter replay detected");
            return false;
        }
    }

    if (nonce_counter > encryptionSession.last_seen_counter)
        encryptionSession.last_seen_counter = nonce_counter;

    encryptionSession.replay_window[encryptionSession.replay_idx] = nonce_counter;
    encryptionSession.replay_idx = (encryptionSession.replay_idx + 1) % 64;

    return true;
}

bool handleAuthenticate(uint8_t* data, uint16_t len,
                        uint8_t* p_response, uint16_t* p_response_len)
{
    if (!isEncryptionEnabled()) {
        p_response[0] = 0x00;
        p_response[1] = RESP_AUTHENTICATE;
        p_response[2] = AUTH_STATUS_NOT_CONFIG;
        *p_response_len = 3;
        return false;
    }

    uint32_t now = millis_approx();

    if (encryptionSession.last_auth_time > 0) {
        uint32_t elapsed = (now - encryptionSession.last_auth_time) / 1000;
        if (elapsed < 60) {
            if (encryptionSession.auth_attempts >= 10) {
                p_response[0] = 0x00;
                p_response[1] = RESP_AUTHENTICATE;
                p_response[2] = AUTH_STATUS_RATE_LIMIT;
                *p_response_len = 3;
                return false;
            }
        } else {
            encryptionSession.auth_attempts = 0;
        }
    }
    encryptionSession.auth_attempts++;
    encryptionSession.last_auth_time = now;

    if (len == 1 && data[0] == 0x00) {
        if (encryptionSession.authenticated && checkEncryptionSessionTimeout()) {
            NRF_LOG_INFO("New auth requested, clearing session");
            clearEncryptionSession();
        }

        secure_random(encryptionSession.pending_server_nonce, 16);
        encryptionSession.server_nonce_time = now;

        uint8_t device_id[4];
        uint32_t device_id_32 = NRF_FICR->DEVICEID[0];
        device_id[0] = (uint8_t)(device_id_32 >> 24);
        device_id[1] = (uint8_t)(device_id_32 >> 16);
        device_id[2] = (uint8_t)(device_id_32 >> 8);
        device_id[3] = (uint8_t)(device_id_32);

        p_response[0] = 0x00;
        p_response[1] = RESP_AUTHENTICATE;
        p_response[2] = AUTH_STATUS_CHALLENGE;
        memcpy(p_response + 3, encryptionSession.pending_server_nonce, 16);
        memcpy(p_response + 19, device_id, 4);
        *p_response_len = 23;

        NRF_LOG_INFO("Auth challenge sent");
        return false;
    }

    if (len == 32) {
        uint8_t client_nonce[16];
        uint8_t challenge_response[16];
        memcpy(client_nonce, data, 16);
        memcpy(challenge_response, data + 16, 16);

        if (now - encryptionSession.server_nonce_time > 30000) {
            NRF_LOG_ERROR("Server nonce expired");
            p_response[0] = 0x00;
            p_response[1] = RESP_AUTHENTICATE;
            p_response[2] = AUTH_STATUS_ERROR;
            *p_response_len = 3;
            return false;
        }

        uint8_t device_id[4];
        uint32_t device_id_32 = NRF_FICR->DEVICEID[0];
        device_id[0] = (uint8_t)(device_id_32 >> 24);
        device_id[1] = (uint8_t)(device_id_32 >> 16);
        device_id[2] = (uint8_t)(device_id_32 >> 8);
        device_id[3] = (uint8_t)(device_id_32);
        
        uint8_t challenge_input[36];
        memcpy(challenge_input, encryptionSession.pending_server_nonce, 16);
        memcpy(challenge_input + 16, client_nonce, 16);
        memcpy(challenge_input + 32, device_id, 4);

        uint8_t expected[16];
        if (!aes_cmac(securityConfig.encryption_key, challenge_input, 36, expected)) {
            NRF_LOG_ERROR("CMAC computation failed");
            p_response[0] = 0x00;
            p_response[1] = RESP_AUTHENTICATE;
            p_response[2] = AUTH_STATUS_ERROR;
            *p_response_len = 3;
            return false;
        }

        if (!constantTimeCompare(challenge_response, expected, 16)) {
            NRF_LOG_ERROR("Auth failed (wrong key)");
            p_response[0] = 0x00;
            p_response[1] = RESP_AUTHENTICATE;
            p_response[2] = AUTH_STATUS_FAILED;
            *p_response_len = 3;
            memset(encryptionSession.pending_server_nonce, 0, 16);
            return false;
        }

        memcpy(encryptionSession.client_nonce, client_nonce, 16);
        memcpy(encryptionSession.server_nonce, encryptionSession.pending_server_nonce, 16);

        if (!deriveSessionKey(securityConfig.encryption_key, client_nonce,
                              encryptionSession.pending_server_nonce,
                              device_id,
                              encryptionSession.session_key)) {
            NRF_LOG_ERROR("Session key derivation failed");
            p_response[0] = 0x00;
            p_response[1] = RESP_AUTHENTICATE;
            p_response[2] = AUTH_STATUS_ERROR;
            *p_response_len = 3;
            return false;
        }

        deriveSessionId(encryptionSession.session_key, client_nonce,
                        encryptionSession.server_nonce,
                        encryptionSession.session_id);

        if (ocrypto_constant_time_is_zero(encryptionSession.session_id, 8)) {
            NRF_LOG_ERROR("Session ID is all zeros!");
            p_response[0] = 0x00;
            p_response[1] = RESP_AUTHENTICATE;
            p_response[2] = AUTH_STATUS_ERROR;
            *p_response_len = 3;
            return false;
        }

        encryptionSession.authenticated      = true;
        encryptionSession.nonce_counter      = 0;
        encryptionSession.last_seen_counter  = 0;
        encryptionSession.replay_idx          = 0;
        encryptionSession.integrity_failures = 0;
        encryptionSession.session_start_time = now;
        encryptionSession.last_activity      = now;
        memset(encryptionSession.replay_window, 0, sizeof(encryptionSession.replay_window));
        memset(encryptionSession.pending_server_nonce, 0, 16);
        encryptionSession.server_nonce_time = 0;

        uint8_t server_mac[16];
        uint8_t server_input[36];
        memcpy(server_input,      encryptionSession.server_nonce, 16);
        memcpy(server_input + 16, client_nonce, 16);
        memcpy(server_input + 32, device_id, 4);
        if (!aes_cmac(encryptionSession.session_key, server_input, 36, server_mac)) {
            NRF_LOG_ERROR("Server MAC computation failed");
            clearEncryptionSession();
            p_response[0] = 0x00;
            p_response[1] = RESP_AUTHENTICATE;
            p_response[2] = AUTH_STATUS_ERROR;
            *p_response_len = 3;
            return false;
        }

        p_response[0] = 0x00;
        p_response[1] = RESP_AUTHENTICATE;
        p_response[2] = AUTH_STATUS_SUCCESS;
        memcpy(p_response + 3, server_mac, 16);
        *p_response_len = 19;

        NRF_LOG_INFO("Authentication successful, session established");
        return true;
    }

    /* Invalid format */
    NRF_LOG_ERROR("Invalid auth request (len=%d)", len);
    p_response[0] = 0x00;
    p_response[1] = RESP_AUTHENTICATE;
    p_response[2] = AUTH_STATUS_ERROR;
    *p_response_len = 3;
    return false;
}

bool decryptCommand(uint8_t* ciphertext, uint16_t ciphertext_len,
                    uint8_t* plaintext, uint16_t* plaintext_len,
                    uint8_t* nonce_full, uint8_t* auth_tag,
                    uint16_t command_header)
{
    if (!isAuthenticated()) return false;

    if (!verifyNonceReplay(nonce_full)) {
        encryptionSession.integrity_failures++;
        if (encryptionSession.integrity_failures >= 3) {
            NRF_LOG_WARNING("Too many integrity failures, clearing session");
            clearEncryptionSession();
        }
        return false;
    }

    if (ciphertext_len == 0 || ciphertext_len > 512) {
        NRF_LOG_ERROR("Invalid ciphertext len: %d", ciphertext_len);
        return false;
    }

    uint8_t nonce_ccm[13];
    memcpy(nonce_ccm, nonce_full + 3, 13);

    uint8_t ad[2];
    ad[0] = (command_header >> 8) & 0xFF;
    ad[1] = command_header & 0xFF;

    static uint8_t decrypted_with_length[512];
    bool ok = aes_ccm_decrypt(encryptionSession.session_key,
                              nonce_ccm, 13,
                              ad, 2,
                              ciphertext, ciphertext_len,
                              decrypted_with_length,
                              auth_tag, 12);
    if (ok) {
        uint8_t payload_length = decrypted_with_length[0];
        if (payload_length > ciphertext_len - 1) {
            NRF_LOG_ERROR("Invalid payload length in decrypted data");
            memset(decrypted_with_length, 0, sizeof(decrypted_with_length));
            return false;
        }
        if (payload_length > 0) {
            memcpy(plaintext, decrypted_with_length + 1, payload_length);
        }
        *plaintext_len = payload_length;
        encryptionSession.integrity_failures = 0;
        updateEncryptionSessionActivity();
        memset(decrypted_with_length, 0, sizeof(decrypted_with_length));
        return true;
    }

    NRF_LOG_ERROR("CCM decrypt failed");
    encryptionSession.integrity_failures++;
    if (encryptionSession.integrity_failures >= 3) {
        NRF_LOG_WARNING("Too many integrity failures, clearing session");
        clearEncryptionSession();
    }
    return false;
}

bool encryptResponse(uint8_t* plaintext, uint16_t plaintext_len,
                     uint8_t* ciphertext, uint16_t* ciphertext_len,
                     uint8_t* nonce, uint8_t* auth_tag)
{
    if (!isAuthenticated()) return false;

    getCurrentNonce(nonce);
    incrementNonceCounter();

    uint8_t nonce_ccm[13];
    memcpy(nonce_ccm, nonce + 3, 13);

    uint8_t ad[2] = { plaintext[0], plaintext[1] };

    static uint8_t payload_with_length[513];
    uint16_t payload_len = plaintext_len - 2;
    payload_with_length[0] = payload_len & 0xFF;
    if (payload_len > 0) {
        memcpy(payload_with_length + 1, plaintext + 2, payload_len);
    }
    uint16_t total_payload_len = 1 + payload_len;
    bool ok = aes_ccm_encrypt(encryptionSession.session_key,
                              nonce_ccm, 13,
                              ad, 2,
                              payload_with_length, total_payload_len,
                              ciphertext + 2 + 16,
                              auth_tag, 12);
    memset(payload_with_length, 0, sizeof(payload_with_length));
    if (ok) {
        uint8_t nonce_copy[16];
        memcpy(nonce_copy, nonce, 16);

        ciphertext[0] = plaintext[0];
        ciphertext[1] = plaintext[1];
        memcpy(ciphertext + 2, nonce_copy, 16);
        /* encrypted data already at ciphertext + 18 */
        memcpy(ciphertext + 2 + 16 + total_payload_len, auth_tag, 12);
        *ciphertext_len = 2 + 16 + total_payload_len + 12;

        updateEncryptionSessionActivity();
        return true;
    }
    return false;
}

void encryption_init(void)
{
    memset(&encryptionSession, 0, sizeof(encryptionSession));
    encryptionInitialized = true;
    NRF_LOG_INFO("Encryption subsystem initialized");
}

void secureEraseConfig(bool reboot_after)
{
    uint8_t zeros[MAX_CONFIG_SIZE];
    memset(zeros, 0, sizeof(zeros));
    saveConfig(zeros, sizeof(zeros));
    NRF_LOG_INFO("Config securely erased (zero overwrite)");
    if (reboot_after) {
        NRF_LOG_INFO("Rebooting after secure erase");
        NVIC_SystemReset();
    }
}

void checkResetPin(void)
{
    if (!isEncryptionEnabled()) return;
    if (!(securityConfig.flags & SECURITY_FLAG_RESET_PIN_ENABLED)) return;
    if (securityConfig.reset_pin == 0xFF) return;
    uint32_t pin = securityConfig.reset_pin;
    uint32_t pull = NRF_GPIO_PIN_NOPULL;
    if (securityConfig.flags & SECURITY_FLAG_RESET_PIN_PULLUP)
        pull = NRF_GPIO_PIN_PULLUP;
    else if (securityConfig.flags & SECURITY_FLAG_RESET_PIN_PULLDOWN)
        pull = NRF_GPIO_PIN_PULLDOWN;
    nrf_gpio_cfg_input(pin, (nrf_gpio_pin_pull_t)pull);
    volatile uint32_t d;
    for (d = 0; d < 100000; d++) { /* ~100ms at 16 MHz */ }
    uint32_t state = nrf_gpio_pin_read(pin);
    bool trigger = false;
    if (securityConfig.flags & SECURITY_FLAG_RESET_PIN_POLARITY) {
        trigger = (state != 0);
    } else {
        trigger = (state == 0);
    }
    nrf_gpio_cfg_default(pin);
    if (trigger) {
        NRF_LOG_WARNING("Reset pin triggered – erasing config and rebooting");
        secureEraseConfig(true);
    }
}
