#ifndef __ENCRYPTION_H
#define __ENCRYPTION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "structs.h"

extern struct SecurityConfig securityConfig;
extern struct EncryptionSession encryptionSession;
extern bool encryptionInitialized;

void encryption_init(void);

bool isEncryptionEnabled(void);

bool isAuthenticated(void);

void clearEncryptionSession(void);

bool checkEncryptionSessionTimeout(void);

void updateEncryptionSessionActivity(void);

bool handleAuthenticate(uint8_t* data, uint16_t len,
                        uint8_t* p_response, uint16_t* p_response_len);

void getCurrentNonce(uint8_t* nonce);

void incrementNonceCounter(void);

bool verifyNonceReplay(uint8_t* nonce);

bool decryptCommand(uint8_t* ciphertext, uint16_t ciphertext_len,
                    uint8_t* plaintext, uint16_t* plaintext_len,
                    uint8_t* nonce_full, uint8_t* auth_tag,
                    uint16_t command_header);

bool encryptResponse(uint8_t* plaintext, uint16_t plaintext_len,
                     uint8_t* ciphertext, uint16_t* ciphertext_len,
                     uint8_t* nonce, uint8_t* auth_tag);

bool aes_cmac(const uint8_t key[16], const uint8_t* msg, size_t msg_len,
              uint8_t tag[16]);

bool aes_ecb_encrypt(const uint8_t key[16], const uint8_t in[16],
                     uint8_t out[16]);

bool aes_ccm_encrypt(const uint8_t key[16],
                     const uint8_t* nonce, size_t nonce_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* plaintext, size_t plaintext_len,
                     uint8_t* ciphertext,
                     uint8_t* tag, size_t tag_len);

bool aes_ccm_decrypt(const uint8_t key[16],
                     const uint8_t* nonce, size_t nonce_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* ciphertext, size_t ciphertext_len,
                     uint8_t* plaintext,
                     const uint8_t* tag, size_t tag_len);

void secure_random(uint8_t* output, size_t len);

bool constantTimeCompare(const uint8_t* a, const uint8_t* b, size_t len);

void secureEraseConfig(bool reboot_after);

void checkResetPin(void);

#endif // __ENCRYPTION_H
