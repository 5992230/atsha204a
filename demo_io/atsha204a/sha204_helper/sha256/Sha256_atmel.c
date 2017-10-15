/*
 ============================================================================
 Name        : Sha256.c
 Author      : Günter Fuchs
 Version     :
 Copyright   : Atmel
 Description : calculate digest using SHA256 secure hash algorithm in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// #include "sha256_os.h"

#define rotate_right(value, places) ((value >> places) | (value << (32 - places)))


/** \brief This function creates a SHA256 digest on a little-endian system.
 *
 * \param[in] len length of message in number of bytes (multiple of 4)
 * \param[in] message pointer to message
 * \param[out] digest SHA256 of message
 */
void create_sha256(int32_t len, uint8_t *message, uint8_t *digest)
{
	int32_t j, swap_counter;
	uint32_t i, w_index;
	int32_t message_index = 0;
	uint32_t padded_len = len + 12;
	uint32_t bit_len = len * 8;
	uint32_t s0, s1;
	uint32_t t1, t2;
	uint32_t maj, ch;
	uint32_t word_value;
	uint32_t rotate_register[8];

	union {
		uint32_t w_word[64];
		uint8_t w_byte[64 * sizeof(int)];
	} w_union;

	uint32_t hash[] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372,	0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};

	const uint32_t k[] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	// Process message.
	while (message_index < padded_len) {

		// Break message into 64-byte chunks.
		w_index = 0;
		do {
			// Copy message chunk into compression array.
			if (message_index < len) {
				for (swap_counter = sizeof(int) - 1; swap_counter >= 0; swap_counter--)
					// No padding needed. Swap four message bytes to chunk array.
					w_union.w_byte[swap_counter + w_index] = message[message_index++];

				w_index += sizeof(int);
			}
			else {
				// We reached end of message. Append '1' bit and pad.
				// Switch to word indexing.
				w_index /= sizeof(int);
				w_union.w_word[w_index++] = 0x80000000;
				// Pad last chunk with zeros to a chunk length % 56 = 0
				// and pad the four high bytes of "len" since we work only
				// with integers and not with long integers.
				while (w_index < 15)
					 w_union.w_word[w_index++] = 0;
				// Append original message length as 32-bit integer.
				w_union.w_word[w_index] = bit_len;
				// Indicate that the last chunk is being processed.
				message_index += 64;
				// We are done with pre-processing last chunk.
				break;
			}
		} while (message_index % 64);
		// Created one chunk.

		w_index = 16;
		while (w_index < 64) {
			// right rotate for 32-bit variable in C: (value >> places) | (value << 32 - places)
			word_value = w_union.w_word[w_index - 15];
			s0 = rotate_right(word_value, 7) ^ rotate_right(word_value, 18) ^ (word_value >> 3);

			word_value = w_union.w_word[w_index - 2];
			s1 = rotate_right(word_value, 17) ^ rotate_right(word_value, 19) ^ (word_value >> 10);

			w_union.w_word[w_index] = w_union.w_word[w_index - 16] + s0 + w_union.w_word[w_index - 7] + s1;

			w_index++;
		}

		// Initialize hash value for this chunk.
		for (i = 0; i < 8; i++)
			rotate_register[i] = hash[i];

		// hash calculation loop
		for (i = 0; i < 64; i++) {
			s0 = rotate_right(rotate_register[0], 2)
				^ rotate_right(rotate_register[0], 13)
				^ rotate_right(rotate_register[0], 22);
			maj = (rotate_register[0] & rotate_register[1])
				^ (rotate_register[0] & rotate_register[2])
				^ (rotate_register[1] & rotate_register[2]);
			t2 = s0 + maj;
			s1 = rotate_right(rotate_register[4], 6)
				^ rotate_right(rotate_register[4], 11)
				^ rotate_right(rotate_register[4], 25);
			ch =  (rotate_register[4] & rotate_register[5])
				^ (~rotate_register[4] & rotate_register[6]);
			t1 = rotate_register[7] + s1 + ch + k[i] + w_union.w_word[i];

			rotate_register[7] = rotate_register[6];
			rotate_register[6] = rotate_register[5];
			rotate_register[5] = rotate_register[4];
			rotate_register[4] = rotate_register[3] + t1;
			rotate_register[3] = rotate_register[2];
			rotate_register[2] = rotate_register[1];
			rotate_register[1] = rotate_register[0];
			rotate_register[0] = t1 + t2;
		}

	    // Add the hash of this chunk to current result.
		for (i = 0; i < 8; i++)
			hash[i] += rotate_register[i];
	}

	// All chunks have been processed.
	// Concatenate the hashes to produce digest, MSB of every hash first.
	for (i = 0; i < 8; i++) {
		for (j = sizeof(int) - 1; j >= 0; j--, hash[i] >>= 8)
			digest[i * sizeof(int) + j] = hash[i] & 0xFF;
	}
}


// /** \brief This function displays a buffer as hex-ascii.
 // * \param[in] len number of bytes to display
 // * \param[in] buffer pointer to binary buffer
 // */
// void put_hex_string(uint8_t len, uint8_t *buffer)
// {
	// uint8_t index = 0;
	// while (index < len) {
		// printf("%02X ", buffer[index++]);
		// if (index % 8 == 0)
			// printf("\n");
	// }
	// printf("\n");
// }


// int main(void) {
	// static uint8_t digest_sha256[32];
	// static uint8_t digest_sha256_os[32];
	// sha256_ctx ctx;
	// static uint8_t message[] = {
			// 0x00, 0x00, 0xA1, 0xAC, 0x57, 0xFF, 0x40, 0x4E,
			// 0x45, 0xD4, 0x04, 0x01, 0xBD, 0x0E, 0xD3, 0xC6,
			// 0x73, 0xD3, 0xB7, 0xB8, 0x2D, 0x85, 0xD9, 0xF3,
			// 0x13, 0xB5, 0x5E, 0xDA, 0x3D, 0x94, 0x00, 0x00,
			// 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			// 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
			// 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			// 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
			// 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEE,
			// 0x00, 0x00, 0x00, 0x00, 0x01, 0x23, 0x00, 0x00
	// };

	// puts("calculate digest using SHA256 secure hash algorithm\n");

	// puts("message:");
	// put_hex_string(sizeof(message), message);

	// sha256_init(&ctx);
	// sha256_update(&ctx, (const uint8_t *) message, sizeof(message));
	// sha256_final(&ctx, digest_sha256_os);
	// puts("digest from Open Source algorithm:");
	// put_hex_string(sizeof(digest_sha256_os), digest_sha256_os);

	// create_sha256(sizeof(message), message, digest_sha256);
	// puts("digest from Atmel's algorithm:");
	// put_hex_string(sizeof(digest_sha256), digest_sha256);

	// return EXIT_SUCCESS;
// }
