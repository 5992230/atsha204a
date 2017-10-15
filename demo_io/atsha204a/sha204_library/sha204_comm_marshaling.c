/** \file
 *  \brief Command Marshaling Layer of SHA204 Library
 *  \author Atmel Crypto Products
 *  \date   November 20, 2013

* \copyright Copyright (c) 2014 Atmel Corporation. All rights reserved.
*
* \atmel_crypto_device_library_license_start
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* 3. The name of Atmel may not be used to endorse or promote products derived
*    from this software without specific prior written permission.
*
* 4. This software may only be redistributed and used in connection with an
*    Atmel integrated circuit.
*
* THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR IMPLIED
* WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
* EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
* ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* \atmel_crypto_device_library_license_stop
 */

#include <string.h>                    // needed for memcpy()
#include "sha204_lib_return_codes.h"   // declarations of function return codes
#include "sha204_comm_marshaling.h"    // definitions and declarations for the Command Marshaling module


// Define this to compile and link this function.
//#define SHA204_CHECK_PARAMETERS

/** \ingroup atsha204_command_marshaling
 * \brief This function checks the parameters for sha204m_execute().
 *
 *
 * \param[in] op_code command op-code
 * \param[in] param1 first parameter
 * \param[in] param2 second parameter
 * \param[in] datalen1 number of bytes in first data block
 * \param[in] data1 pointer to first data block
 * \param[in] datalen2 number of bytes in second data block
 * \param[in] data2 pointer to second data block
 * \param[in] datalen3 number of bytes in third data block
 * \param[in] data3 pointer to third data block
 * \param[in] tx_size size of tx buffer
 * \param[in] tx_buffer pointer to tx buffer
 * \param[in] rx_size size of rx buffer
 * \param[out] rx_buffer pointer to rx buffer
 * \return status of the operation
 */
uint8_t sha204m_check_parameters(uint8_t op_code, uint8_t param1, uint16_t param2,
		uint8_t datalen1, uint8_t *data1, uint8_t datalen2, uint8_t *data2, uint8_t datalen3, uint8_t *data3,
		uint8_t tx_size, uint8_t *tx_buffer, uint8_t rx_size, uint8_t *rx_buffer)
{
#ifdef SHA204_CHECK_PARAMETERS

	uint8_t len = datalen1 + datalen2 + datalen3 + SHA204_CMD_SIZE_MIN;
	if (!tx_buffer || (tx_size < len) || (rx_size < SHA204_RSP_SIZE_MIN) || !rx_buffer)
		return SHA204_BAD_PARAM;

	if ((datalen1 > 0 && !data1) || (datalen2 > 0 && !data2) || (datalen3 > 0 && !data3))
		return SHA204_BAD_PARAM;

	// Check parameters depending on op-code.
	switch (op_code) {
	case SHA204_CHECKMAC:
		if (!data1 || !data2 || (param1 & ~CHECKMAC_MODE_MASK) || (param2 > SHA204_KEY_ID_MAX))
			// Neither data1 nor data2 can be null.
			// param1 has to match an allowed CheckMac mode.
			// key_id > 15 not allowed.
			return SHA204_BAD_PARAM;
		break;

	case SHA204_DERIVE_KEY:
		if (param2 > SHA204_KEY_ID_MAX)
			// key_id > 15 not allowed.
			return SHA204_BAD_PARAM;
		break;

	case SHA204_DEVREV:
		// Neither parameters nor data are used by this command.
		break;

	case SHA204_GENDIG:
		if ((param1 > GENDIG_ZONE_DATA) || (param2 > SHA204_KEY_ID_MAX))
			// param1 has to match an allowed GenDig mode.
			// key_id > 15 not allowed.
			return SHA204_BAD_PARAM;
		break;

	case SHA204_HMAC:
		if (param1 & ~HMAC_MODE_MASK)
			// param1 has to match an allowed HMAC mode.
			return SHA204_BAD_PARAM;
		break;

	case SHA204_LOCK:
		if ((param1 & ~LOCK_ZONE_MASK)
					|| ((param1 & LOCK_ZONE_NO_CRC) && param2))
			// param1 has to match an allowed Lock mode.
			// If no CRC is required the CRC should be 0.
			return SHA204_BAD_PARAM;
		break;

	case SHA204_MAC:
		if ((param1 & ~MAC_MODE_MASK)
					|| (!(param1 & MAC_MODE_BLOCK2_TEMPKEY) && !data1))
			// param1 has to match an allowed MAC mode.
			// If the MAC mode requires challenge data, data1 should not be null.
			return SHA204_BAD_PARAM;
		break;

	case SHA204_NONCE:
		if (!data1 || (param1 > NONCE_MODE_PASSTHROUGH)	|| (param1 == NONCE_MODE_INVALID))
			// data1 cannot be null.
			// param1 has to match an allowed Nonce mode.
			return SHA204_BAD_PARAM;
		break;

	case SHA204_PAUSE:
		// param1 can have any value. param2 and data are not used by this command.
		break;

	case SHA204_RANDOM:
		if (param1 > RANDOM_NO_SEED_UPDATE)
			// param1 has to match an allowed Random mode.
			return SHA204_BAD_PARAM;
		break;

	case SHA204_READ:
		if (param1 & ~READ_ZONE_MASK)
			// param1 has to match an allowed Read mode.
			return SHA204_BAD_PARAM;
		break;

	case SHA204_UPDATE_EXTRA:
		if (param1 > UPDATE_CONFIG_BYTE_85)
			// param1 has to match an allowed UpdateExtra mode.
			return SHA204_BAD_PARAM;
		break;

	case SHA204_WRITE:
		if (!data1 || (param1 & ~WRITE_ZONE_MASK))
			// data1 cannot be null.
			// param1 has to match an allowed Write mode.
			return SHA204_BAD_PARAM;
		break;

	default:
		// unknown op-code
		return SHA204_BAD_PARAM;
	}
#endif

	return SHA204_SUCCESS;
}


/** \brief This function creates a command packet, sends it, and receives its response.
 *
 * \param[in] op_code command op-code
 * \param[in] param1 first parameter
 * \param[in] param2 second parameter
 * \param[in] datalen1 number of bytes in first data block
 * \param[in] data1 pointer to first data block
 * \param[in] datalen2 number of bytes in second data block
 * \param[in] data2 pointer to second data block
 * \param[in] datalen3 number of bytes in third data block
 * \param[in] data3 pointer to third data block
 * \param[in] tx_size size of tx buffer
 * \param[in] tx_buffer pointer to tx buffer
 * \param[in] rx_size size of rx buffer
 * \param[out] rx_buffer pointer to rx buffer
 * \return status of the operation
 */
uint8_t sha204m_execute(uint8_t op_code, uint8_t param1, uint16_t param2,
			uint8_t datalen1, uint8_t *data1, uint8_t datalen2, uint8_t *data2, uint8_t datalen3, uint8_t *data3,
			uint8_t tx_size, uint8_t *tx_buffer, uint8_t rx_size, uint8_t *rx_buffer)
{
	uint8_t poll_delay, poll_timeout, response_size;
	uint8_t *p_buffer;
	uint8_t len;

	// Define SHA204_CHECK_PARAMETERS to compile and link this feature.
	uint8_t ret_code = sha204m_check_parameters(op_code, param1, param2,
				datalen1, data1, datalen2, data2, datalen3, data3,
				tx_size, tx_buffer, rx_size, rx_buffer);
	if (ret_code != SHA204_SUCCESS) {
		(void) sha204p_sleep();
		return ret_code;
	}

	// Supply delays and response size.
	switch (op_code) {
	case SHA204_CHECKMAC:
		poll_delay = CHECKMAC_DELAY;
		poll_timeout = CHECKMAC_EXEC_MAX - CHECKMAC_DELAY;
		response_size = CHECKMAC_RSP_SIZE;
		break;

	case SHA204_DERIVE_KEY:
		poll_delay = DERIVE_KEY_DELAY;
		poll_timeout = DERIVE_KEY_EXEC_MAX - DERIVE_KEY_DELAY;
		response_size = DERIVE_KEY_RSP_SIZE;
		break;

	case SHA204_DEVREV:
		poll_delay = DEVREV_DELAY;
		poll_timeout = DEVREV_EXEC_MAX - DEVREV_DELAY;
		response_size = DEVREV_RSP_SIZE;
		break;

	case SHA204_GENDIG:
		poll_delay = GENDIG_DELAY;
		poll_timeout = GENDIG_EXEC_MAX - GENDIG_DELAY;
		response_size = GENDIG_RSP_SIZE;
		break;

	case SHA204_HMAC:
		poll_delay = HMAC_DELAY;
		poll_timeout = HMAC_EXEC_MAX - HMAC_DELAY;
		response_size = HMAC_RSP_SIZE;
		break;

	case SHA204_LOCK:
		poll_delay = LOCK_DELAY;
		poll_timeout = LOCK_EXEC_MAX - LOCK_DELAY;
		response_size = LOCK_RSP_SIZE;
		break;

	case SHA204_MAC:
		poll_delay = MAC_DELAY;
		poll_timeout = MAC_EXEC_MAX - MAC_DELAY;
		response_size = MAC_RSP_SIZE;
		break;

	case SHA204_NONCE:
		poll_delay = NONCE_DELAY;
		poll_timeout = NONCE_EXEC_MAX - NONCE_DELAY;
		response_size = param1 == NONCE_MODE_PASSTHROUGH
							? NONCE_RSP_SIZE_SHORT : NONCE_RSP_SIZE_LONG;
		break;

	case SHA204_PAUSE:
		poll_delay = PAUSE_DELAY;
		poll_timeout = PAUSE_EXEC_MAX - PAUSE_DELAY;
		response_size = PAUSE_RSP_SIZE;
		break;

	case SHA204_RANDOM:
		poll_delay = RANDOM_DELAY;
		poll_timeout = RANDOM_EXEC_MAX - RANDOM_DELAY;
		response_size = RANDOM_RSP_SIZE;
		break;

	case SHA204_READ:
		poll_delay = READ_DELAY;
		poll_timeout = READ_EXEC_MAX - READ_DELAY;
		response_size = (param1 & SHA204_ZONE_COUNT_FLAG)
							? READ_32_RSP_SIZE : READ_4_RSP_SIZE;
		break;
	case SHA204_SHA:
		poll_delay = SHA_DELAY;
		poll_timeout = SHA_EXEC_MAX - SHA_DELAY;
		response_size = param1 == SHA_MODE_INIT
							? SHA_INIT_RSP_SIZE : SHA_COMPUTE_RSP_SIZE;
		break;
	case SHA204_UPDATE_EXTRA:
		poll_delay = UPDATE_DELAY;
		poll_timeout = UPDATE_EXEC_MAX - UPDATE_DELAY;
		response_size = UPDATE_RSP_SIZE;
		break;

	case SHA204_WRITE:
		poll_delay = WRITE_DELAY;
		poll_timeout = WRITE_EXEC_MAX - WRITE_DELAY;
		response_size = WRITE_RSP_SIZE;
		break;

	default:
		poll_delay = 0;
		poll_timeout = SHA204_COMMAND_EXEC_MAX;
		response_size = rx_size;
	}

	// Assemble command.
	len = datalen1 + datalen2 + datalen3 + SHA204_CMD_SIZE_MIN;
	p_buffer = tx_buffer;
	*p_buffer++ = len;
	*p_buffer++ = op_code;
	*p_buffer++ = param1;
	*p_buffer++ = param2 & 0xFF;
	*p_buffer++ = param2 >> 8;

	if (datalen1 > 0) {
		memcpy(p_buffer, data1, datalen1);
		p_buffer += datalen1;
	}
	if (datalen2 > 0) {
		memcpy(p_buffer, data2, datalen2);
		p_buffer += datalen2;
	}
	if (datalen3 > 0) {
		memcpy(p_buffer, data3, datalen3);
		p_buffer += datalen3;
	}

	sha204c_calculate_crc(len - SHA204_CRC_SIZE, tx_buffer, p_buffer);

	// Send command and receive response.
	ret_code = sha204c_send_and_receive(&tx_buffer[0], response_size,
				&rx_buffer[0],	poll_delay, poll_timeout);
	
	// Put device to sleep if command fails
	if (ret_code != SHA204_SUCCESS)
		(void) sha204p_sleep();
	
	return ret_code;
}
