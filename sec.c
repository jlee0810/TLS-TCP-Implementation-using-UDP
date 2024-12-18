#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "consts.h"
#include "io.h"
#include "security.h"

int state_sec = 0;              // Current state for handshake
uint8_t nonce[NONCE_SIZE];      // Store generated nonce to verify signature
uint8_t peer_nonce[NONCE_SIZE]; // Store peer's nonce to sign

uint8_t *server_hello_message = NULL;
size_t server_hello_message_length = 0;

uint8_t *client_key_exchange_request = NULL;
size_t client_key_exchange_request_length = 0;

void init_sec(int initial_state)
{
    state_sec = initial_state;
    init_io();

    if (state_sec == CLIENT_CLIENT_HELLO_SEND)
    {
        generate_private_key();
        derive_public_key();
        derive_self_signed_certificate();
        load_ca_public_key("ca_public_key.bin");
    }
    else if (state_sec == SERVER_CLIENT_HELLO_AWAIT)
    {
        load_certificate("server_cert.bin");
        load_private_key("server_key.bin");
        derive_public_key();
    }

    generate_nonce(nonce, NONCE_SIZE);
}

ssize_t input_sec(uint8_t *buf, size_t max_length)
{
    switch (state_sec)
    {
    case CLIENT_CLIENT_HELLO_SEND:
    {
        print("SEND CLIENT HELLO");

        // 1 byte for the type, 2 bytes for the length, and 32 bytes for the value.
        uint8_t client_hello_nonce[1 + 2 + NONCE_SIZE];

        // Define Type
        client_hello_nonce[0] = NONCE_CLIENT_HELLO;
        uint16_t length = htons(NONCE_SIZE);
        memcpy(client_hello_nonce + 1, &length, 2);
        memcpy(client_hello_nonce + 3, nonce, NONCE_SIZE);

        uint8_t client_hello_message[1 + 2 + sizeof(client_hello_nonce)];
        client_hello_message[0] = CLIENT_HELLO;
        uint16_t nonce_msg_length = htons(sizeof(client_hello_nonce));
        memcpy(client_hello_message + 1, &nonce_msg_length, 2);
        memcpy(client_hello_message + 3, client_hello_nonce, sizeof(client_hello_nonce));

        size_t client_hello_length = sizeof(client_hello_message);
        memcpy(buf, client_hello_message, client_hello_length);

        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return client_hello_length;

        // /* Insert Client Hello sending logic here */
        // state_sec = CLIENT_SERVER_HELLO_AWAIT;
        // return 0;
    }
    case SERVER_SERVER_HELLO_SEND:
    {
        print("SEND SERVER HELLO");

        /* Insert Server Hello sending logic here */

        // Nonce
        uint8_t server_hello_nonce[1 + 2 + NONCE_SIZE];
        server_hello_nonce[0] = NONCE_SERVER_HELLO;
        uint16_t nonce_length = htons(NONCE_SIZE);
        memcpy(server_hello_nonce + 1, &nonce_length, 2);
        memcpy(server_hello_nonce + 3, nonce, NONCE_SIZE);
        size_t server_hello_nonce_size = sizeof(server_hello_nonce);

        // Certificate (already in TLV)
        size_t server_certificate_size = cert_size;
        uint8_t *server_certificate = malloc(server_certificate_size);
        memcpy(server_certificate, certificate, server_certificate_size);

        // Sign Client Nonce
        uint8_t client_nonce_sign[72];
        size_t client_nonce_sign_size = sign(peer_nonce, NONCE_SIZE, client_nonce_sign);

        size_t signature_size = 1 + 2 + client_nonce_sign_size;
        uint8_t *signature = malloc(signature_size);
        signature[0] = NONCE_SIGNATURE_SERVER_HELLO;
        uint16_t sign_length = htons(client_nonce_sign_size);
        memcpy(signature + 1, &sign_length, 2);
        memcpy(signature + 3, client_nonce_sign, client_nonce_sign_size);

        size_t nested_length = server_hello_nonce_size + server_certificate_size + signature_size;

        // Server Hello
        size_t total_server_hello_length = 1 + 2 + nested_length;
        uint8_t *server_hello = malloc(total_server_hello_length);
        server_hello[0] = SERVER_HELLO;
        uint16_t server_hello_length_field = htons(nested_length);
        memcpy(server_hello + 1, &server_hello_length_field, 2);
        size_t offset = 3;
        memcpy(server_hello + offset, server_hello_nonce, server_hello_nonce_size);
        offset += server_hello_nonce_size;
        memcpy(server_hello + offset, server_certificate, server_certificate_size);
        offset += server_certificate_size;
        memcpy(server_hello + offset, signature, signature_size);

        memcpy(buf, server_hello, total_server_hello_length);

        free(server_certificate);
        free(signature);
        free(server_hello);

        state_sec = SERVER_KEY_EXCHANGE_REQUEST_AWAIT;
        return total_server_hello_length;
    }
    case CLIENT_KEY_EXCHANGE_REQUEST_SEND:
    {
        print("SEND KEY EXCHANGE REQUEST");

        /* Insert Key Exchange Request sending logic here */
        uint8_t *buf_received = server_hello_message;
        size_t length_received = server_hello_message_length;

        uint16_t server_hello_length = ntohs(*(uint16_t *)(buf_received + 1));
        uint8_t *p = buf_received + 3;
        size_t remaining = server_hello_length;

        uint8_t server_nonce[NONCE_SIZE];
        uint8_t *server_certificate = NULL;
        size_t server_certificate_length = 0;
        uint8_t *nonce_signature = NULL;
        size_t nonce_signature_length = 0;

        while (remaining > 0)
        {
            uint8_t type = p[0];
            uint16_t length = ntohs(*(uint16_t *)(p + 1));
            uint8_t *value = p + 3;

            switch (type)
            {
            case NONCE_SERVER_HELLO:
                memcpy(server_nonce, value, NONCE_SIZE);
                memcpy(peer_nonce, server_nonce, NONCE_SIZE);
                break;

            case CERTIFICATE:
                server_certificate_length = length;
                server_certificate = malloc(server_certificate_length);
                memcpy(server_certificate, value, server_certificate_length);
                break;

            case NONCE_SIGNATURE_SERVER_HELLO:
                nonce_signature_length = length;
                nonce_signature = malloc(nonce_signature_length);
                memcpy(nonce_signature, value, nonce_signature_length);
                break;

            default:
                break;
            }

            p += 3 + length;
            remaining -= 3 + length;
        }

        // Server certificate
        uint8_t *cert_p = server_certificate;
        size_t cert_remaining = server_certificate_length;

        uint8_t *server_public_key = NULL;
        size_t server_public_key_length = 0;
        uint8_t *public_key_signature = NULL;
        size_t public_key_signature_length = 0;

        while (cert_remaining > 0)
        {
            uint8_t nested_type = cert_p[0];
            uint16_t nested_length = ntohs(*(uint16_t *)(cert_p + 1));

            uint8_t *nested_value = cert_p + 3;

            switch (nested_type)
            {
            case PUBLIC_KEY:
                server_public_key_length = nested_length;
                server_public_key = malloc(server_public_key_length);
                memcpy(server_public_key, nested_value, server_public_key_length);
                break;

            case SIGNATURE:
                public_key_signature_length = nested_length;
                public_key_signature = malloc(public_key_signature_length);
                memcpy(public_key_signature, nested_value, public_key_signature_length);
                break;

            default:
                break;
            }

            cert_p += 3 + nested_length;
            cert_remaining -= 3 + nested_length;
        }

        // Verify server's certificate
        load_peer_public_key(server_public_key, server_public_key_length);
        int cert_verify = verify(server_public_key, server_public_key_length, public_key_signature, public_key_signature_length, ec_ca_public_key);
        if (cert_verify != 1)
            exit(1);

        // Verify ignature of the client's nonce
        int nonce_verify = verify(nonce, NONCE_SIZE, nonce_signature, nonce_signature_length, ec_peer_public_key);
        if (nonce_verify != 1)
            exit(2);

        // Sign server's nonce
        uint8_t signature[72];
        size_t sig_len = sign(peer_nonce, NONCE_SIZE, signature);

        // Nonce Signature TLV
        size_t nonce_sig_tlv_len = 1 + 2 + sig_len;
        uint8_t *nonce_sig_tlv = malloc(nonce_sig_tlv_len);

        nonce_sig_tlv[0] = NONCE_SIGNATURE_KEY_EXCHANGE_REQUEST;
        uint16_t sig_length_net = htons(sig_len);
        memcpy(nonce_sig_tlv + 1, &sig_length_net, 2);
        memcpy(nonce_sig_tlv + 3, signature, sig_len);

        size_t total_nested_len = cert_size + nonce_sig_tlv_len;

        // Key Exchange Request TLV
        size_t total_key_request_message_len = 1 + 2 + total_nested_len;

        buf[0] = KEY_EXCHANGE_REQUEST;
        uint16_t total_len_net = htons(total_nested_len);
        memcpy(buf + 1, &total_len_net, 2);

        memcpy(buf + 3, certificate, cert_size);
        memcpy(buf + 3 + cert_size, nonce_sig_tlv, nonce_sig_tlv_len);

        derive_secret();
        derive_keys();

        free(nonce_sig_tlv);
        free(server_certificate);
        free(server_public_key);
        free(public_key_signature);
        free(nonce_signature);
        free(server_hello_message);
        server_hello_message = NULL;
        server_hello_message_length = 0;

        state_sec = CLIENT_FINISHED_AWAIT;
        return total_key_request_message_len;
    }
    case SERVER_FINISHED_SEND:
    {
        print("SEND FINISHED");
        /* Insert Finished sending logic here */
        uint8_t *buf_received = client_key_exchange_request;
        size_t length_received = client_key_exchange_request_length;

        uint16_t client_key_exchange_length = ntohs(*(uint16_t *)(buf_received + 1));
        uint8_t *p = buf_received + 3;
        size_t remaining = client_key_exchange_length;

        uint8_t *client_certificate = NULL;
        size_t client_certificate_length = 0;
        uint8_t *nonce_signature = NULL;
        size_t nonce_signature_length = 0;

        while (remaining > 0)
        {
            uint8_t type = p[0];
            uint16_t length = ntohs(*(uint16_t *)(p + 1));
            uint8_t *value = p + 3;

            switch (type)
            {
            case CERTIFICATE:
                client_certificate_length = length;
                client_certificate = malloc(client_certificate_length);
                memcpy(client_certificate, value, client_certificate_length);
                break;

            case NONCE_SIGNATURE_KEY_EXCHANGE_REQUEST:
                nonce_signature_length = length;
                nonce_signature = malloc(nonce_signature_length);
                memcpy(nonce_signature, value, nonce_signature_length);
                break;

            default:
                break;
            }

            p += 3 + length;
            remaining -= 3 + length;
        }

        uint8_t *cert_p = client_certificate;
        size_t cert_remaining = client_certificate_length;

        uint8_t *client_public_key = NULL;
        size_t client_public_key_length = 0;
        uint8_t *public_key_signature = NULL;
        size_t public_key_signature_length = 0;

        while (cert_remaining > 0)
        {
            uint8_t nested_type = cert_p[0];
            uint16_t nested_length = ntohs(*(uint16_t *)(cert_p + 1));

            uint8_t *nested_value = cert_p + 3;

            switch (nested_type)
            {
            case PUBLIC_KEY:
                client_public_key_length = nested_length;
                client_public_key = malloc(client_public_key_length);
                memcpy(client_public_key, nested_value, client_public_key_length);
                break;

            case SIGNATURE:
                public_key_signature_length = nested_length;
                public_key_signature = malloc(public_key_signature_length);
                memcpy(public_key_signature, nested_value, public_key_signature_length);
                break;

            default:
                break;
            }

            cert_p += 3 + nested_length;
            cert_remaining -= 3 + nested_length;
        }

        // Verify client's self-signed certificate
        load_peer_public_key(client_public_key, client_public_key_length);
        int cert_verify = verify(client_public_key, client_public_key_length, public_key_signature, public_key_signature_length, ec_peer_public_key);
        if (cert_verify != 1)
        {
            fprintf(stderr, "Certificate verification failed\n");
            exit(1);
        }
        // Verify signature of server's nonce
        int nonce_verify = verify(nonce, NONCE_SIZE, nonce_signature, nonce_signature_length, ec_peer_public_key);
        if (nonce_verify != 1)
        {
            fprintf(stderr, "Nonce verification failed\n");
            exit(2);
        }

        fprintf(stderr, "Certificate and nonce verification passed\n");

        derive_secret();
        derive_keys();

        free(client_certificate);
        free(client_public_key);
        free(public_key_signature);
        free(nonce_signature);
        free(client_key_exchange_request);
        client_key_exchange_request = NULL;

        buf[0] = FINISHED;
        uint16_t finished_length = htons(0);
        memcpy(buf + 1, &finished_length, 2);

        state_sec = DATA_STATE;
        return 3;
    }

    case DATA_STATE:
    {
        /* Insert Data sending logic here */

        // PT refers to the amount you read from stdin in bytes
        // CT refers to the resulting ciphertext size
        // fprintf(stderr, "SEND DATA PT %ld CT %lu\n", stdin_size, cip_size);

        size_t max_payload_size = max_length > 1012 ? 1012 : max_length;

        size_t data_message_header_size = 3;
        size_t iv_message_size = 1 + 2 + IV_SIZE;
        size_t mac_message_size = 1 + 2 + MAC_SIZE;
        size_t ciphertext_message_header_size = 3;

        size_t overhead = data_message_header_size + iv_message_size + mac_message_size + ciphertext_message_header_size;

        size_t max_ciphertext_size = max_payload_size - overhead;
        size_t max_blocks = max_ciphertext_size / 16;
        size_t max_potential_ciphertext_size = max_blocks * 16;
        size_t max_plaintext_size = max_potential_ciphertext_size - 1;

        uint8_t plaintext[max_plaintext_size];
        ssize_t plaintext_len = input_io(plaintext, max_plaintext_size);

        // Encrypt plaintext
        uint8_t iv[IV_SIZE];
        uint8_t ciphertext[plaintext_len];
        size_t ciphertext_len = encrypt_data(plaintext, plaintext_len, iv, ciphertext);

        uint8_t hmac_input[IV_SIZE + ciphertext_len];
        memcpy(hmac_input, iv, IV_SIZE);
        memcpy(hmac_input + IV_SIZE, ciphertext, ciphertext_len);

        // Create an HMAC digest of IV + ciphertext
        uint8_t hmac_digest[MAC_SIZE];
        hmac(hmac_input, IV_SIZE + ciphertext_len, hmac_digest);

        // Data message TLV
        size_t offset = 0;
        uint8_t data_message[max_payload_size];

        data_message[offset] = DATA;
        offset += 1;
        uint16_t data_length = iv_message_size + ciphertext_message_header_size + ciphertext_len + mac_message_size;
        uint16_t data_length_net = htons(data_length);
        memcpy(data_message + offset, &data_length_net, 2);
        offset += 2;

        // IV message
        data_message[offset] = INITIALIZATION_VECTOR;
        offset += 1;
        uint16_t iv_length_net = htons(IV_SIZE);
        memcpy(data_message + offset, &iv_length_net, 2);
        offset += 2;
        memcpy(data_message + offset, iv, IV_SIZE);
        offset += IV_SIZE;

        // Ciphertext message
        data_message[offset] = CIPHERTEXT;
        offset += 1;
        uint16_t ciphertext_length_net = htons(ciphertext_len);
        memcpy(data_message + offset, &ciphertext_length_net, 2);
        offset += 2;
        memcpy(data_message + offset, ciphertext, ciphertext_len);
        offset += ciphertext_len;

        // MAC message
        data_message[offset] = MESSAGE_AUTHENTICATION_CODE;
        offset += 1;
        uint16_t mac_length_net = htons(MAC_SIZE);
        memcpy(data_message + offset, &mac_length_net, 2);
        offset += 2;
        memcpy(data_message + offset, hmac_digest, MAC_SIZE);
        offset += MAC_SIZE;

        memcpy(buf, data_message, offset);

        fprintf(stderr, "SEND DATA PT %ld CT %lu\n", plaintext_len, ciphertext_len);

        return offset;
    }
    default:
        return 0;
    }
}

void output_sec(uint8_t *buf, size_t length)
{
    // This passes it directly to standard output (working like Project 1)
    // return output_io(buf, length);

    switch (state_sec)
    {
    case SERVER_CLIENT_HELLO_AWAIT:
    {
        if (*buf != CLIENT_HELLO)
            exit(4);

        print("RECV CLIENT HELLO");

        /* Insert Client Hello receiving logic here */
        uint8_t *p = buf + 3;

        uint8_t nested_type = p[0];
        memcpy(peer_nonce, p + 3, NONCE_SIZE);

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT:
    {
        if (*buf != SERVER_HELLO)
            exit(4);

        print("RECV SERVER HELLO");

        /* Insert Server Hello receiving logic here */
        server_hello_message_length = length;
        server_hello_message = malloc(length);
        memcpy(server_hello_message, buf, length);

        state_sec = CLIENT_KEY_EXCHANGE_REQUEST_SEND;
        break;
    }
    case SERVER_KEY_EXCHANGE_REQUEST_AWAIT:
    {
        if (*buf != KEY_EXCHANGE_REQUEST)
            exit(4);

        print("RECV KEY EXCHANGE REQUEST");

        /* Insert Key Exchange Request receiving logic here */
        client_key_exchange_request = malloc(length);
        client_key_exchange_request_length = length;
        memcpy(client_key_exchange_request, buf, length);

        state_sec = SERVER_FINISHED_SEND;
        break;
    }
    case CLIENT_FINISHED_AWAIT:
    {
        if (*buf != FINISHED)
            exit(4);

        print("RECV FINISHED");

        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE:
    {
        if (*buf != DATA)
            exit(4);

        /* Insert Data receiving logic here */

        // PT refers to the resulting plaintext size in bytes
        // CT refers to the received ciphertext size
        // fprintf(stderr, "RECV DATA PT %ld CT %hu\n", data_len, cip_len);
        size_t offset = 1;
        uint16_t data_length = ntohs(*(uint16_t *)(buf + offset));
        offset += 2;

        size_t remaining = data_length;
        uint8_t *p = buf + offset;

        uint8_t iv[IV_SIZE];
        uint8_t *ciphertext = NULL;
        size_t ciphertext_len = 0;
        uint8_t received_mac[MAC_SIZE];

        while (remaining > 0)
        {
            uint8_t type = p[0];
            uint16_t length = ntohs(*(uint16_t *)(p + 1));
            uint8_t *value = p + 3;

            switch (type)
            {
            case INITIALIZATION_VECTOR:
                memcpy(iv, value, IV_SIZE);
                break;

            case CIPHERTEXT:
                ciphertext_len = length;
                ciphertext = malloc(ciphertext_len);
                memcpy(ciphertext, value, ciphertext_len);
                break;

            case MESSAGE_AUTHENTICATION_CODE:
                memcpy(received_mac, value, MAC_SIZE);
                break;

            default:
                break;
            }

            p += 3 + length;
            remaining -= 3 + length;
        }

        uint8_t hmac_input[IV_SIZE + ciphertext_len];
        memcpy(hmac_input, iv, IV_SIZE);
        memcpy(hmac_input + IV_SIZE, ciphertext, ciphertext_len);

        uint8_t calculated_mac[MAC_SIZE];
        hmac(hmac_input, IV_SIZE + ciphertext_len, calculated_mac);

        // Check if the digest matches the MAC code in the received Data message
        if (memcmp(received_mac, calculated_mac, MAC_SIZE) != 0)
            exit(3);

        // Decrypt
        uint8_t plaintext[ciphertext_len];
        size_t plaintext_len = decrypt_cipher(ciphertext, ciphertext_len, iv, plaintext);

        output_io(plaintext, plaintext_len);

        fprintf(stderr, "RECV DATA PT %lu CT %lu\n", plaintext_len, ciphertext_len);

        free(ciphertext);
        break;
    }
    default:
        break;
    }
}
