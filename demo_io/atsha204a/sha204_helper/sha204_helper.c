//         ATMEL Microcontroller Software Support  -  Colorado Springs, CO -
// ----------------------------------------------------------------------------
// DISCLAIMER:  THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
// DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
// EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// ----------------------------------------------------------------------------

/** \file
 *  \brief  SHA204 Helper Functions
 *  \author Tuwuh Sarwoprasojo, Atmel Bali Team
 *  \date   November 21, 2011
 */

#include <string.h>                    // needed for memcpy()
#include <stdint.h>

#include "sha204_helper.h"
#include "sha204_lib_return_codes.h"   // declarations of function return codes
#include "sha204_comm_marshaling.h"    // definitions and declarations for the Command module

// Atmel's SHA256 implementation
// #include "Sha256_atmel.h"

// Modified free/open-source SHA256 implementation (taken from SA102 library)
#include "sha256.h"


/** \brief This is a wrapper function for SHA256 algorithm.
 *
 *         User can modify this function depending on their SHA256 implementation.
 *
 * \param [in,out] param Structure for input/output parameters. Refer to sha204h_calculate_sha256_in_out.
 */
static void sha204h_calculate_sha256(struct sha204h_calculate_sha256_in_out *param)
{
	// This is the "free/open-source" implementation
	sha256(param->message, param->length, param->digest);
	
	// This is Atmel's implementation
	// create_sha256(param->length, param->message, param->digest);
}


/** \brief This function calculates a 32-byte nonce based on 20-byte input value (NumIn) and 32-byte random number (RandOut).
 *
 *         This nonce will match with the nonce generated in the Device by Nonce opcode.
 *         To use this function, Application first executes Nonce command in the Device, with a chosen NumIn.
 *         Nonce opcode Mode parameter must be set to use random nonce (mode 0 or 1).
 *         The Device generates a nonce, stores it in its TempKey, and outputs random number RandOut to host.
 *         This RandOut along with NumIn are passed to nonce calculation function. The function calculates the nonce, and returns it.
 *         This function can also be used to fill in the nonce directly to TempKey (pass-through mode). The flags will automatically set according to the mode used.
 *
 * \param [in,out] param Structure for input/output parameters. Refer to sha204h_nonce_in_out.
 * \return status of the operation.
 */
uint8_t sha204h_nonce(struct sha204h_nonce_in_out *param)
{
	// Local Variables
	struct sha204h_calculate_sha256_in_out calculate_sha256_param;
	uint8_t temporary[SHA204_MSG_SIZE_NONCE];
	uint8_t *p_temp;

	// Check parameters
	if (	!param->temp_key || !param->num_in
			|| (param->mode > NONCE_MODE_PASSTHROUGH)
			|| (param->mode == NONCE_MODE_INVALID)
			|| (param->mode == NONCE_MODE_SEED_UPDATE && !param->rand_out)
			|| (param->mode == NONCE_MODE_NO_SEED_UPDATE && !param->rand_out) )
		return SHA204_BAD_PARAM;

	// Calculate or pass-through the nonce to TempKey->Value
	if ((param->mode == NONCE_MODE_SEED_UPDATE) || (param->mode == NONCE_MODE_NO_SEED_UPDATE)) {
		// Calculate nonce using SHA-256 (refer to datasheet)
		p_temp = temporary;

		memcpy(p_temp, param->rand_out, 32);
		p_temp += 32;

		memcpy(p_temp, param->num_in, 20);
		p_temp += 20;

		*p_temp++ = SHA204_NONCE;
		*p_temp++ = param->mode;
		*p_temp++ = 0x00;

		// Calculate SHA256 to get the nonce
		calculate_sha256_param.length  = SHA204_MSG_SIZE_NONCE;
		calculate_sha256_param.message = temporary;
		calculate_sha256_param.digest  = param->temp_key->value;
		sha204h_calculate_sha256(&calculate_sha256_param);

		// Update TempKey->SourceFlag to 0 (random)
		param->temp_key->source_flag = 0;
	} else if (param->mode == NONCE_MODE_PASSTHROUGH) {
		// Pass-through mode
		memcpy(param->temp_key->value, param->num_in, 32);

		// Update TempKey->SourceFlag to 1 (not random)
		param->temp_key->source_flag = 1;
	}

	// Update TempKey fields
	param->temp_key->key_id = 0;
	param->temp_key->gen_data = 0;
	param->temp_key->check_flag = 0;
	param->temp_key->valid = 1;

	return SHA204_SUCCESS;
}


/** \brief This function generates an SHA-256 digest (MAC) of a key, challenge, and other informations.
 *
 *         The resulting digest will match with those generated in the Device by MAC opcode.
 *         The TempKey (if used) should be valid (temp_key.valid = 1) before executing this function.
 *
 * \param [in,out] param Structure for input/output parameters. Refer to sha204h_mac_in_out.
 * \return status of the operation.
 */
uint8_t sha204h_mac(struct sha204h_mac_in_out *param)
{
	// Local Variables
	struct sha204h_calculate_sha256_in_out calculate_sha256_param;
	uint8_t temporary[SHA204_MSG_SIZE_MAC];
	uint8_t i;
	uint8_t *p_temp;

	// Check parameters
	if (	!param->response
			|| ((param->mode & ~MAC_MODE_MASK) != 0)
			|| (((param->mode & MAC_MODE_BLOCK1_TEMPKEY) == 0) && !param->key)
			|| (((param->mode & MAC_MODE_BLOCK2_TEMPKEY) == 0) && !param->challenge)
			|| (((param->mode & MAC_MODE_USE_TEMPKEY_MASK) != 0) && !param->temp_key)
			|| (((param->mode & MAC_MODE_INCLUDE_OTP_64) != 0) && !param->otp)
			|| (((param->mode & MAC_MODE_INCLUDE_OTP_88) != 0) && !param->otp)
			|| (((param->mode & MAC_MODE_INCLUDE_SN) != 0) && !param->sn) )
		return SHA204_BAD_PARAM;

	// Check TempKey fields validity if TempKey is used
	if (	((param->mode & MAC_MODE_USE_TEMPKEY_MASK) != 0) &&
			// TempKey.CheckFlag must be 0 and TempKey.Valid must be 1
			(  (param->temp_key->check_flag != 0)
			|| (param->temp_key->valid != 1)
			// If either mode parameter bit 0 or bit 1 are set, mode parameter bit 2 must match temp_key.source_flag
			// Logical not (!) are used to evaluate the expression to TRUE/FALSE first before comparison (!=)
			|| (!(param->mode & MAC_MODE_SOURCE_FLAG_MATCH) != !(param->temp_key->source_flag)) ))
	{
		// Invalidate TempKey, then return
		param->temp_key->valid = 0;
		return SHA204_CMD_FAIL;
	}

	// Start calculation
	p_temp = temporary;

	// (1) first 32 bytes
	if (param->mode & MAC_MODE_BLOCK1_TEMPKEY) {
		memcpy(p_temp, param->temp_key->value, 32);    // use TempKey.Value
		p_temp += 32;
	} else {
		memcpy(p_temp, param->key, 32);                // use Key[KeyID]
		p_temp += 32;
	}

	// (2) second 32 bytes
	if (param->mode & MAC_MODE_BLOCK2_TEMPKEY) {
		memcpy(p_temp, param->temp_key->value, 32);    // use TempKey.Value
		p_temp += 32;
	} else {
		memcpy(p_temp, param->challenge, 32);          // use challenge
		p_temp += 32;
	}

	// (3) 1 byte opcode
	*p_temp++ = SHA204_MAC;

	// (4) 1 byte mode parameter
	*p_temp++ = param->mode;

	// (5) 2 bytes keyID
	*p_temp++ = param->key_id & 0xFF;
	*p_temp++ = (param->key_id >> 8) & 0xFF;

	// (6, 7) 8 bytes OTP[0:7] or 0x00's, 3 bytes OTP[8:10] or 0x00's
	if (param->mode & MAC_MODE_INCLUDE_OTP_88) {
		memcpy(p_temp, param->otp, 11);            // use OTP[0:10], Mode:5 is overridden
		p_temp += 11;
	} else {
		if (param->mode & MAC_MODE_INCLUDE_OTP_64) {
			memcpy(p_temp, param->otp, 8);         // use 8 bytes OTP[0:7] for (6)
			p_temp += 8;
		} else {
			for (i = 0; i < 8; i++) {             // use 8 bytes 0x00's for (6)
				*p_temp++ = 0x00;
			}
		}

		for (i = 0; i < 3; i++) {                 // use 3 bytes 0x00's for (7)
			*p_temp++ = 0x00;
		}
	}

	// (8) 1 byte SN[8] = 0xEE
	*p_temp++ = SHA204_SN_8;

	// (9) 4 bytes SN[4:7] or 0x00's
	if (param->mode & MAC_MODE_INCLUDE_SN) {
		memcpy(p_temp, &param->sn[4], 4);     //use SN[4:7] for (9)
		p_temp += 4;
	} else {
		for (i = 0; i < 4; i++) {            //use 0x00's for (9)
			*p_temp++ = 0x00;
		}
	}

	// (10) 2 bytes SN[0:1] = 0x0123
	*p_temp++ = SHA204_SN_0;
	*p_temp++ = SHA204_SN_1;

	// (11) 2 bytes SN[2:3] or 0x00's
	if (param->mode & MAC_MODE_INCLUDE_SN) {
		memcpy(p_temp, &param->sn[2], 2);     //use SN[2:3] for (11)
		p_temp += 2;
	} else {
		for (i = 0; i < 2; i++) {            //use 0x00's for (11)
			*p_temp++ = 0x00;
		}
	}

	// Calculate SHA256 to get the MAC digest
	calculate_sha256_param.length  = SHA204_MSG_SIZE_MAC;
	calculate_sha256_param.message = temporary;
	calculate_sha256_param.digest  = param->response;
	sha204h_calculate_sha256(&calculate_sha256_param);

	// Update TempKey fields
	if (param->temp_key) {
		param->temp_key->valid = 0;
	}

	return SHA204_SUCCESS;
}


/** \brief This function calculates SHA-256 digest (MAC) of a password and other informations, to be verified using CheckMac command in the Device.
 *
 *         This password checking operation is described in "Section 3.3.6 Password Checking" of "Atmel ATSHA204 [DATASHEET]" (8740C-CRYPTO-7/11).
 *         Before performing password checking operation, TempKey should contain a randomly generated nonce. The TempKey in Device and Application should be equal.
 *         User enters the password to be verified to Application.
 *         Application passes this password to CheckMac calculation function, along with 13-byte OtherData, 32-byte target key, and optionally 11-byte OTP.
 *         The function calculates a 32-byte ClientResp, returns it to Application. The function also replaces the current TempKey value with the target key.
 *         Application passes the calculated ClientResp along with OtherData to the Device, and has it execute CheckMac command.
 *         The Device validates ClientResp, and copies target slot to TempKey.
 *
 *         If the password is stored in odd numbered slot, the target slot is the password slot itself, so target_key parameter should point to the password being checked.
 *         If the password is stored in even numbered slot, the target slot is next odd numbered slot (KeyID+1), so target_key parameter should point to a key that is equal to target slot in the Device.
 *
 *         Note that the function does not check the result of password checking operation.
 *         Regardless of whether the CheckMac command returns success or not, TempKey in Application will hold the value of target key.
 *         Therefore Application has to make sure that password checking operation succeeds before using the TempKey for subsequent operations.
 *
 * \param [in,out] param Structure for input/output parameters. Refer to sha204h_check_mac_in_out.
 * \return status of the operation.
 */
 
 //modify
 /*
	原来这个函数只支持tempkey，不支持自己的ClientChal,现在改为支持ClientChal
 */
uint8_t sha204h_check_mac(struct sha204h_check_mac_in_out *param)
{
	// Local Variables
	struct sha204h_calculate_sha256_in_out calculate_sha256_param;
	uint8_t temporary[SHA204_MSG_SIZE_MAC];
	uint8_t i;
	uint8_t *p_temp;

	// Check parameters
	if (	(!param->temp_key && ((param->mode & MAC_MODE_USE_TEMPKEY_MASK) == MAC_MODE_BLOCK2_TEMPKEY) )
			|| !param->password || !param->other_data
			|| !param->target_key || !param->client_resp
			|| (((param->mode & MAC_MODE_INCLUDE_OTP_64) != 0) && !param->otp) )
		return SHA204_BAD_PARAM;

	// Check TempKey fields validity (TempKey is always used)
	// TempKey.CheckFlag must be 0, TempKey.Valid must be 1, TempKey.SourceFlag must be 0
	if(param->temp_key)
	{
		if (	(param->temp_key->check_flag != 0)
				|| (param->temp_key->valid != 1)
				|| (param->temp_key->source_flag != 0) )
		{
			// Invalidate TempKey, then return
			param->temp_key->valid = 0;
			return SHA204_CMD_FAIL;
		}
	}
	// Start calculation
	p_temp = temporary;

	// (1) first 32 bytes
	memcpy(p_temp, param->password, 32);           // password to be checked
	p_temp += 32;

	// (2) second 32 bytes
	if((param->mode & MAC_MODE_USE_TEMPKEY_MASK) == MAC_MODE_BLOCK2_TEMPKEY)
		memcpy(p_temp, param->temp_key->value, 32);    // use TempKey.Value
	else
		memcpy(p_temp, param->client_chl, 32); 
	p_temp += 32;

	// (3, 4, 5) 4 byte OtherData[0:3]
	memcpy(p_temp, &param->other_data[0], 4);
	p_temp += 4;

	// (6) 8 bytes OTP[0:7] or 0x00's
	if (param->mode & MAC_MODE_INCLUDE_OTP_64) {
		memcpy(p_temp, param->otp, 8);         // use 8 bytes OTP[0:7] for (6)
		p_temp += 8;
	} else {
		for (i = 0; i < 8; i++) {             // use 8 bytes 0x00's for (6)
			*p_temp++ = 0x00;
		}
	}

	// (7) 3 byte OtherData[4:6]
	memcpy(p_temp, &param->other_data[4], 3);  // use OtherData[4:6] for (7)
	p_temp += 3;

	// (8) 1 byte SN[8] = 0xEE
	*p_temp++ = SHA204_SN_8;

	// (9) 4 byte OtherData[7:10]
	memcpy(p_temp, &param->other_data[7], 4);  // use OtherData[7:10] for (9)
	p_temp += 4;

	// (10) 2 bytes SN[0:1] = 0x0123
	*p_temp++ = SHA204_SN_0;
	*p_temp++ = SHA204_SN_1;

	// (11) 2 byte OtherData[11:12]
	memcpy(p_temp, &param->other_data[11], 2); // use OtherData[11:12] for (11)
	p_temp += 2;

	// Calculate SHA256 to get the MAC digest
	calculate_sha256_param.length  = SHA204_MSG_SIZE_MAC;
	calculate_sha256_param.message = temporary;
	calculate_sha256_param.digest  = param->client_resp;
	sha204h_calculate_sha256(&calculate_sha256_param);

	// Update TempKey fields
	if(param->temp_key)
	{
		memcpy(param->temp_key->value, param->target_key, 32);
		param->temp_key->gen_data = 0;
		param->temp_key->source_flag = 1;
		param->temp_key->valid = 1;
	}
	return SHA204_SUCCESS;
}


/** \brief This function generates an HMAC/SHA-256 digest of a key and other informations.
 *
 *         The resulting digest will match with those generated in the Device by HMAC opcode.
 *         The TempKey should be valid (temp_key.valid = 1) before executing this function.
 *
 * \param [in,out] param Structure for input/output parameters. Refer to sha204h_hmac_in_out.
 * \return status of the operation.
 */
uint8_t sha204h_hmac(struct sha204h_hmac_in_out *param)
{
	// Local Variables
	struct sha204h_calculate_sha256_in_out calculate_sha256_param;
	uint8_t temporary[SHA204_MSG_SIZE_HMAC_INNER];
	uint8_t i;
	uint8_t *p_temp;

	// Check parameters
	if (	!param->response || !param->key || !param->temp_key
			|| ((param->mode & ~HMAC_MODE_MASK) != 0)
			|| (((param->mode & MAC_MODE_INCLUDE_OTP_64) != 0) && !param->otp)
			|| (((param->mode & MAC_MODE_INCLUDE_OTP_88) != 0) && !param->otp)
			|| (((param->mode & MAC_MODE_INCLUDE_SN) != 0) && !param->sn) )
		return SHA204_BAD_PARAM;

	// Check TempKey fields validity (TempKey is always used)
	if (	// TempKey.CheckFlag must be 0 and TempKey.Valid must be 1
			   (param->temp_key->check_flag != 0)
			|| (param->temp_key->valid != 1)
			// The mode parameter bit 2 must match temp_key.source_flag
			// Logical not (!) are used to evaluate the expression to TRUE/FALSE first before comparison (!=)
			|| (!(param->mode & MAC_MODE_SOURCE_FLAG_MATCH) != !(param->temp_key->source_flag)) )
	{
		// Invalidate TempKey, then return
		param->temp_key->valid = 0;
		return SHA204_CMD_FAIL;
	}

	// Start first calculation (inner)
	p_temp = temporary;

	// Refer to fips-198a.pdf, length Key = 32 bytes, Blocksize = 512 bits = 64 bytes,
	//   so the Key must be padded with zeros
	// XOR K0 with ipad, then append
	for (i = 0; i < 32; i++) {
		*p_temp++ = param->key[i] ^ 0x36;
	}

	// XOR the remaining zeros and append
	for (i = 0; i < 32; i++) {
		*p_temp++ = 0 ^ 0x36;
	}

	// Next append the stream of data 'text'
	// (1) first 32 bytes: zeros
	for (i = 0; i < 32; i++) {
		*p_temp++ = 0;
	}

	// (2) second 32 bytes: TempKey
	memcpy(p_temp, param->temp_key->value, 32);
	p_temp += 32;

	// (3) 1 byte opcode
	*p_temp++ = SHA204_HMAC;

	// (4) 1 byte mode parameter
	*p_temp++ = param->mode;

	// (5) 2 bytes keyID
	*p_temp++ = param->key_id & 0xFF;
	*p_temp++ = (param->key_id >> 8) & 0xFF;

	// (6, 7) 8 bytes OTP[0:7] or 0x00's, 3 bytes OTP[8:10] or 0x00's
	if (param->mode & MAC_MODE_INCLUDE_OTP_88) {
		memcpy(p_temp, param->otp, 11);            // use OTP[0:10], Mode:5 is overridden
		p_temp += 11;
	} else {
		if (param->mode & MAC_MODE_INCLUDE_OTP_64) {
			memcpy(p_temp, param->otp, 8);         // use 8 bytes OTP[0:7] for (6)
			p_temp += 8;
		} else {
			for (i = 0; i < 8; i++) {             // use 8 bytes 0x00's for (6)
				*p_temp++ = 0x00;
			}
		}

		for (i = 0; i < 3; i++) {                 // use 3 bytes 0x00's for (7)
			*p_temp++ = 0x00;
		}
	}

	// (8) 1 byte SN[8] = 0xEE
	*p_temp++ = SHA204_SN_8;

	// (9) 4 bytes SN[4:7] or 0x00's
	if (param->mode & MAC_MODE_INCLUDE_SN) {
		memcpy(p_temp, &param->sn[4], 4);     //use SN[4:7] for (9)
		p_temp += 4;
	} else {
		for (i = 0; i < 4; i++) {            //use 0x00's for (9)
			*p_temp++ = 0x00;
		}
	}

	// (10) 2 bytes SN[0:1] = 0x0123
	*p_temp++ = SHA204_SN_0;
	*p_temp++ = SHA204_SN_1;

	// (11) 2 bytes SN[2:3] or 0x00's
	if (param->mode & MAC_MODE_INCLUDE_SN) {
		memcpy(p_temp, &param->sn[2], 2);     //use SN[2:3] for (11)
		p_temp += 2;
	} else {
		for (i = 0; i < 2; i++) {            //use 0x00's for (11)
			*p_temp++ = 0x00;
		}
	}

	// Calculate SHA256
	// H((K0^ipad):text), use param.response for temporary storage
	calculate_sha256_param.length  = SHA204_MSG_SIZE_HMAC_INNER;
	calculate_sha256_param.message = temporary;
	calculate_sha256_param.digest  = param->response;
	sha204h_calculate_sha256(&calculate_sha256_param);

	// Start second calculation (outer)
	p_temp = temporary;

	// XOR K0 with opad, then append
	for (i = 0; i < 32; i++) {
		*p_temp++ = param->key[i] ^ 0x5C;
	}

	// XOR the remaining zeros and append
	for (i = 0; i < 32; i++) {
		*p_temp++ = 0 ^ 0x5C;
	}

	// Append result from last calculation H((K0^ipad):text)
	memcpy(p_temp, param->response, 32);
	p_temp += 32;

	// Calculate SHA256 to get the resulting HMAC
	calculate_sha256_param.length  = SHA204_MSG_SIZE_HMAC_OUTER;
	calculate_sha256_param.message = temporary;
	calculate_sha256_param.digest  = param->response;
	sha204h_calculate_sha256(&calculate_sha256_param);

	// Update TempKey fields
	param->temp_key->valid = 0;

	return SHA204_SUCCESS;
}


/** \brief This function combines current TempKey with a stored value.
 *
 *         The stored value can be a data slot, OTP page, configuration zone, or hardware transport key.
 *         The TempKey generated by this function will match with the TempKey in the Device generated by GenDig opcode.
 *         The TempKey should be valid (temp_key.valid = 1) before executing this function.
 *         To use this function, Application first executes GenDig command in the Device, with a chosen stored value.
 *         This stored value must be known by the Application, and is passed to GenDig calculation function.
 *         The function calculates new TempKey, and returns it.
 *
 * \param [in,out] param Structure for input/output parameters. Refer to sha204h_gen_dig_in_out.
 * \return status of the operation.
 */
uint8_t sha204h_gen_dig(struct sha204h_gen_dig_in_out *param)
{
	// Local Variables
	struct sha204h_calculate_sha256_in_out calculate_sha256_param;
	uint8_t temporary[SHA204_MSG_SIZE_GEN_DIG];
	uint8_t i;
	uint8_t *p_temp;

	// Check parameters
	if (	!param->stored_value || !param->temp_key
			|| ((param->zone != GENDIG_ZONE_OTP)
			    && (param->zone != GENDIG_ZONE_DATA)
				&& (param->zone != GENDIG_ZONE_CONFIG)) )
		return SHA204_BAD_PARAM;

	// Check TempKey fields validity (TempKey is always used)
	if (	// TempKey.CheckFlag must be 0 and TempKey.Valid must be 1
			   (param->temp_key->check_flag != 0)
			|| (param->temp_key->valid != 1) )
	{
		// Invalidate TempKey, then return
		param->temp_key->valid = 0;
		return SHA204_CMD_FAIL;
	}

	// Start calculation
	p_temp = temporary;

	// (1) 32 bytes inputKey
	//     (Config[KeyID] or OTP[KeyID] or Data.slot[KeyID] or TransportKey[KeyID])
	memcpy(p_temp, param->stored_value, 32);
	p_temp += 32;

	// (2) 1 byte Opcode
	*p_temp++ = SHA204_GENDIG;

	// (3) 1 byte Param1 (zone)
	*p_temp++ = param->zone;

	// (4) 2 bytes Param2 (keyID)
	*p_temp++ = param->key_id & 0xFF;
	*p_temp++ = (param->key_id >> 8) & 0xFF;

	// (5) 1 byte SN[8] = 0xEE
	*p_temp++ = SHA204_SN_8;

	// (6) 2 bytes SN[0:1] = 0x0123
	*p_temp++ = SHA204_SN_0;
	*p_temp++ = SHA204_SN_1;

	// (7) 25 bytes 0x00's
	for (i = 0; i < 25; i++) {
		*p_temp++ = 0x00;
	}

	// (8) 32 bytes TempKey
	memcpy(p_temp, param->temp_key->value, 32);

	// Calculate SHA256 to get the new TempKey
	calculate_sha256_param.length  = SHA204_MSG_SIZE_GEN_DIG;
	calculate_sha256_param.message = temporary;
	calculate_sha256_param.digest  = param->temp_key->value;
	sha204h_calculate_sha256(&calculate_sha256_param);

	// Update TempKey fields
	param->temp_key->valid = 1;

	if ((param->zone == GENDIG_ZONE_DATA) && (param->key_id <= 15)) {
		param->temp_key->gen_data = 1;
		param->temp_key->key_id = (param->key_id & 0xF);    // mask lower 4-bit only
	} else {
		param->temp_key->gen_data = 0;
		param->temp_key->key_id = 0;
	}

	return SHA204_SUCCESS;
}


/** \brief This function combines current value of a key with the TempKey.
 *
 *         Used in conjunction with DeriveKey command, the key derived by this function will match with the key in the Device.
 *         Two kinds of operation are supported:
 *         - Roll Key operation, target_key and parent_key parameters should be set to point to the same location (TargetKey).
 *         - Create Key operation, target_key should be set to point to TargetKey, parent_key should be set to point to ParentKey.
 *         After executing this function, initial value of target_key will be overwritten with the derived key.
 *         The TempKey should be valid (temp_key.valid = 1) before executing this function.
 *
 * \param [in,out] param Structure for input/output parameters. Refer to sha204h_derive_key_in_out.
 * \return status of the operation.
 */
uint8_t sha204h_derive_key(struct sha204h_derive_key_in_out *param)
{
	// Local Variables
	struct sha204h_calculate_sha256_in_out calculate_sha256_param;
	uint8_t temporary[SHA204_MSG_SIZE_DERIVE_KEY];
	uint8_t i;
	uint8_t *p_temp;

	// Check parameters
	if (	!param->parent_key || !param->target_key || !param->temp_key
			|| ((param->random & ~DERIVE_KEY_RANDOM_FLAG) != 0)
			|| (param->target_key_id > SHA204_KEY_ID_MAX) )
		return SHA204_BAD_PARAM;

	// Check TempKey fields validity (TempKey is always used)
	if (	// TempKey.CheckFlag must be 0 and TempKey.Valid must be 1
			   (param->temp_key->check_flag != 0)
			|| (param->temp_key->valid != 1)
			// The random parameter bit 2 must match temp_key.source_flag
			// Logical not (!) are used to evaluate the expression to TRUE/FALSE first before comparison (!=)
			|| (!(param->random & DERIVE_KEY_RANDOM_FLAG) != !(param->temp_key->source_flag)) )
	{
		// Invalidate TempKey, then return
		param->temp_key->valid = 0;
		return SHA204_CMD_FAIL;
	}

	// Start calculation
	p_temp = temporary;

	// (1) 32 bytes parent key
	memcpy(p_temp, param->parent_key, 32);
	p_temp += 32;

	// (2) 1 byte Opcode
	*p_temp++ = SHA204_DERIVE_KEY;

	// (3) 1 byte Param1 (random)
	*p_temp++ = param->random;

	// (4) 2 bytes Param2 (keyID)
	*p_temp++ = param->target_key_id & 0xFF;
	*p_temp++ = (param->target_key_id >> 8) & 0xFF;

	// (5) 1 byte SN[8] = 0xEE
	*p_temp++ = SHA204_SN_8;

	// (6) 2 bytes SN[0:1] = 0x0123
	*p_temp++ = SHA204_SN_0;
	*p_temp++ = SHA204_SN_1;

	// (7) 25 bytes 0x00's
	for (i = 0; i < 25; i++) {
		*p_temp++ = 0x00;
	}

	// (8) 32 bytes tempKey
	memcpy(p_temp, param->temp_key->value, 32);
	p_temp += 32;

	// Calculate SHA256 to get the derived key
	calculate_sha256_param.length  = SHA204_MSG_SIZE_DERIVE_KEY;
	calculate_sha256_param.message = temporary;
	calculate_sha256_param.digest  = param->target_key;
	sha204h_calculate_sha256(&calculate_sha256_param);

	// Update TempKey fields
	param->temp_key->valid = 0;

	return SHA204_SUCCESS;
}


/** \brief This function calculates input MAC for DeriveKey opcode.
 *
 *         DeriveKey command will need an input MAC if SlotConfig[TargetKey].Bit15 is set.
 *
 * \param [in,out] param Structure for input/output parameters. Refer to sha204h_derive_key_mac_in_out.
 * \return status of the operation.
 */
uint8_t sha204h_derive_key_mac(struct sha204h_derive_key_mac_in_out *param)
{
	// Local Variables
	struct sha204h_calculate_sha256_in_out calculate_sha256_param;
	uint8_t temporary[SHA204_MSG_SIZE_DERIVE_KEY_MAC];
	uint8_t *p_temp;

	// Check parameters
	if (	!param->parent_key || !param->mac
			|| ((param->random & ~DERIVE_KEY_RANDOM_FLAG) != 0)
			|| (param->target_key_id > SHA204_KEY_ID_MAX) )
		return SHA204_BAD_PARAM;

	// Start calculation
	p_temp = temporary;

	// (1) 32 bytes parent key
	memcpy(p_temp, param->parent_key, 32);
	p_temp += 32;

	// (2) 1 byte Opcode
	*p_temp++ = SHA204_DERIVE_KEY;

	// (3) 1 byte Param1 (random)
	*p_temp++ = param->random;

	// (4) 2 bytes Param2 (keyID)
	*p_temp++ = param->target_key_id & 0xFF;
	*p_temp++ = (param->target_key_id >> 8) & 0xFF;

	// (5) 1 byte SN[8] = 0xEE
	*p_temp++ = SHA204_SN_8;

	// (6) 2 bytes SN[0:1] = 0x0123
	*p_temp++ = SHA204_SN_0;
	*p_temp++ = SHA204_SN_1;

	// Calculate SHA256 to get the input MAC for DeriveKey command
	calculate_sha256_param.length  = SHA204_MSG_SIZE_DERIVE_KEY_MAC;
	calculate_sha256_param.message = temporary;
	calculate_sha256_param.digest  = param->mac;
	sha204h_calculate_sha256(&calculate_sha256_param);

	return SHA204_SUCCESS;
}


/** \brief This function encrypts 32-byte cleartext data to be written using Write opcode, and optionally calculates input MAC.
 *
 *         To use this function, first the nonce must be valid and synchronized between Device and Application.
 *         Application executes GenDig command in the Device, using parent key. If Data zone has been locked, this is specified by SlotConfig.WriteKey. The Device updates its TempKey.
 *         Application then updates its own TempKey using GenDig calculation function, using the same key.
 *         Application passes the cleartext data to encryption function.
 *         If input MAC is needed, application must pass a valid pointer to buffer in the "mac" parameter.
 *         If input MAC is not needed, application can pass NULL pointer in "mac" parameter.
 *         The function encrypts the data and optionally calculate input MAC, returns it to Application.
 *         Using this encrypted data and input MAC, Application executes Write command in the Device. Device validates the MAC, then decrypts and writes the data.
 *         The encryption function does not check whether the TempKey has been generated by correct ParentKey for the corresponding zone.
 *         Therefore to get a correct result, after Data/OTP locked, Application has to make sure that prior GenDig calculation was done using correct ParentKey.
 *
 * \param [in,out] param Structure for input/output parameters. Refer to sha204h_encrypt_in_out.
 * \return status of the operation.
 */
uint8_t sha204h_encrypt(struct sha204h_encrypt_in_out *param)
{
	// Local Variables
	struct sha204h_calculate_sha256_in_out calculate_sha256_param;
	uint8_t temporary[SHA204_MSG_SIZE_ENCRYPT_MAC];
	uint8_t i;
	uint8_t *p_temp;

	// Check parameters
	if (!param->data || !param->temp_key || ((param->zone & ~WRITE_ZONE_MASK) != 0))
		return SHA204_BAD_PARAM;

	// Check TempKey fields validity, and illegal address
	// Note that temp_key.key_id is not checked,
	//   we cannot make sure if the key used in previous GenDig IS equal to
	//   the key pointed by SlotConfig.WriteKey in the device.
	if (	// TempKey.CheckFlag must be 0
			(param->temp_key->check_flag != 0)
			// TempKey.Valid must be 1
			|| (param->temp_key->valid != 1)
			// TempKey.GenData must be 1
			|| (param->temp_key->gen_data != 1)
			// TempKey.SourceFlag must be 0 (random)
			|| (param->temp_key->source_flag != 0)
			// Illegal address
			|| ((param->address & ~SHA204_ADDRESS_MASK) != 0) )
	{
		// Invalidate TempKey, then return
		param->temp_key->valid = 0;
		return SHA204_CMD_FAIL;
	}

	// If the pointer *mac is provided by the caller then calculate input MAC
	if (param->mac) {
		// Start calculation
		p_temp = temporary;

		// (1) 32 bytes parent key
		memcpy(p_temp, param->temp_key->value, 32);
		p_temp += 32;

		// (2) 1 byte Opcode
		*p_temp++ = SHA204_WRITE;

		// (3) 1 byte Param1 (zone)
		*p_temp++ = param->zone;

		// (4) 2 bytes Param2 (address)
		*p_temp++ = param->address & 0xFF;
		*p_temp++ = (param->address >> 8) & 0xFF;

		// (5) 1 byte SN[8] = 0xEE
		*p_temp++ = SHA204_SN_8;

		// (6) 2 bytes SN[0:1] = 0x0123
		*p_temp++ = SHA204_SN_0;
		*p_temp++ = SHA204_SN_1;

		// (7) 25 bytes 0x00's
		for (i = 0; i < 25; i++) {
			*p_temp++ = 0x00;
		}

		// (8) 32 bytes data
		memcpy(p_temp, param->data, 32);

		// Calculate SHA256 to get the input MAC
		calculate_sha256_param.length  = SHA204_MSG_SIZE_ENCRYPT_MAC;
		calculate_sha256_param.message = temporary;
		calculate_sha256_param.digest  = param->mac;
		sha204h_calculate_sha256(&calculate_sha256_param);
	}

	// Encrypt by XOR-ing Data with the TempKey
	for (i = 0; i < 32; i++) {
		param->data[i] ^= param->temp_key->value[i];
	}

	// Update TempKey fields
	param->temp_key->valid = 0;

	return SHA204_SUCCESS;
}


/** \brief This function decrypts 32-byte encrypted data (Contents) from Read opcode.
 *
 *         To use this function, first the nonce must be valid and synchronized between Device and Application.
 *         Application executes GenDig command in the Device, using key specified by SlotConfig.ReadKey. The Device updates its TempKey.
 *         Application then updates its own TempKey using GenDig calculation function, using the same key.
 *         Application executes Read command in the Device to a user zone configured with EncryptRead.
 *         The Device encrypts 32-byte zone contents, and outputs it to the host.
 *         Application passes this encrypted data to decryption function. The function decrypts the data, and returns it.
 *         TempKey must be updated by GenDig using a ParentKey as specified by SlotConfig.ReadKey before executing this function.
 *         The decryption function does not check whether the TempKey has been generated by correct ParentKey for the corresponding zone.
 *         Therefore to get a correct result, Application has to make sure that prior GenDig calculation was done using correct ParentKey.
 *
 * \param [in,out] param Structure for input/output parameters. Refer to sha204h_decrypt_in_out.
 * \return status of the operation.
 */
uint8_t sha204h_decrypt(struct sha204h_decrypt_in_out *param)
{
	// Local Variables
	uint8_t i;

	// Check parameters
	if (!param->data || !param->temp_key)
		return SHA204_BAD_PARAM;

	// Check TempKey fields validity
	// Note that temp_key.key_id is not checked,
	//   we cannot make sure if the key used in previous GenDig IS equal to
	//   the key pointed by SlotConfig.ReadKey in the device.
	if (	// TempKey.CheckFlag must be 0
			(param->temp_key->check_flag != 0)
			// TempKey.Valid must be 1
			|| (param->temp_key->valid != 1)
			// TempKey.GenData must be 1
			|| (param->temp_key->gen_data != 1)
			// TempKey.SourceFlag must be 0 (random)
			|| (param->temp_key->source_flag != 0) )
	{
		// Invalidate TempKey, then return
		param->temp_key->valid = 0;
		return SHA204_CMD_FAIL;
	}

	// Decrypt by XOR-ing Data with the TempKey
	for (i = 0; i < 32; i++) {
		param->data[i] ^= param->temp_key->value[i];
	}

	// Update TempKey fields
	param->temp_key->valid = 0;

	return SHA204_SUCCESS;
}


/** \brief This function calculates CRC.
 *
 *         crc_register is initialized with *crc, so it can be chained to calculate CRC from large array of data.
 *         For the first calculation or calculation without chaining, crc[0] and crc[1] values must be initialized to 0 by the caller.
 *
 * \param[in] length number of bytes in buffer
 * \param[in] data pointer to data for which CRC should be calculated
 * \param[out] crc pointer to 16-bit CRC
 */
void sha204h_calculate_crc_chain(uint8_t length, uint8_t *data, uint8_t *crc)
{
	uint8_t counter;
	uint16_t crc_register = 0;
	uint16_t polynom = 0x8005;
	uint8_t shift_register;
	uint8_t data_bit, crc_bit;

	crc_register = (((uint16_t) crc[0]) & 0x00FF) | (((uint16_t) crc[1]) << 8);

	for (counter = 0; counter < length; counter++) {
	  for (shift_register = 0x01; shift_register > 0x00; shift_register <<= 1) {
		 data_bit = (data[counter] & shift_register) ? 1 : 0;
		 crc_bit = crc_register >> 15;

		 // Shift CRC to the left by 1.
		 crc_register <<= 1;

		 if ((data_bit ^ crc_bit) != 0)
			crc_register ^= polynom;
	  }
	}

	crc[0] = (uint8_t) (crc_register & 0x00FF);
	crc[1] = (uint8_t) (crc_register >> 8);
}
