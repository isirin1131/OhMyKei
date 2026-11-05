/* PIN/UV protocol cryptography shared by ClientPIN and hmac-secret. */
#ifndef OMK_FIDO_PIN_PROTOCOL_H
#define OMK_FIDO_PIN_PROTOCOL_H

#include "fido/omk_cbor.h"
#include "omk_port.h"

/* Callers validate protocol (1 or 2) at the request boundary. These helpers
 * neither own nor modify authenticator state. Failed derivation clears both
 * outputs; command handlers remain responsible for clearing keys after use. */
bool omk_pin_protocol_derive(const omk_cbor_doc *doc,
                             const omk_cbor_val *cose, uint32_t protocol,
                             const uint8_t private_key[32], uint8_t aes[32],
                             uint8_t hmac[32]);

/* plain_len is the exact expected plaintext length; out must hold that many
 * bytes. Command handlers select it from their parameter's allowed sizes. */
bool omk_pin_protocol_decrypt(const uint8_t aes[32], uint32_t protocol,
                              const uint8_t *in, size_t in_len,
                              uint8_t *out, size_t plain_len);

/* out must hold in_len bytes for protocol 1, or in_len + 16 for protocol 2. */
bool omk_pin_protocol_encrypt(const omk_port *port, const uint8_t aes[32],
                              uint32_t protocol, const uint8_t *in,
                              size_t in_len, uint8_t *out, size_t *out_len);

#endif /* OMK_FIDO_PIN_PROTOCOL_H */
