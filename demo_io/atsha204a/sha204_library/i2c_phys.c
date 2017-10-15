/** \file
 *  \brief Functions of Hardware Dependent Part of Crypto Device Physical
 *         Layer Using I2C For Communication
 *  \author Atmel Crypto Products
 *  \date  June 24, 2013
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


#include "i2c_phys.h"		// definitions and declarations for the hardware dependent I2C module
#include "stm32f10x_conf.h"
//#include "i2c_master.h"		// modify by tww


///////////////////////////////////////////////////////////////////////////////
// File scope defines
// Default address of 0xC0 ((0xC0 >> 1) = 0x60) - ECC
// Default address of 0xC8 ((0xC8 >> 1) = 0x64) - SHA
// Default address of 0xCA ((0xCA >> 1) = 0x65) - SHA
#define SLAVE_ADDRESS_DEFAULT ((uint8_t)(CRYPTOAUTH_SLAVE_ADDRESS >> 1))

#define ATSHA204A_STUCK_TIME	0xFFFF

// File scope globals
// I2C software module.
uint8_t slave_address = 0xC8;
uint32_t i2c_spd_in_khz = 100*10000;


/** \brief This function initializes and enables the I2C peripheral.
 * */
 
 //modify by tww
static	GPIO_InitTypeDef 	I2C1_GPIO_InitStructure;
static 	I2C_InitTypeDef 	I2C1_InitStructure;
void i2c_enable(void)
{
	RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOB,ENABLE);
	RCC_APB1PeriphClockCmd(RCC_APB1Periph_I2C1, ENABLE);
	I2C_DeInit(I2C1);
	
	I2C1_GPIO_InitStructure.GPIO_Pin = GPIO_Pin_6|GPIO_Pin_7;
	I2C1_GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
	I2C1_GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF_OD;
	GPIO_Init(GPIOB,&I2C1_GPIO_InitStructure);
		
	I2C_StructInit(&I2C1_InitStructure);
	I2C1_InitStructure.I2C_OwnAddress1 = 0xA0;  
	I2C1_InitStructure.I2C_Ack = I2C_Ack_Enable; 
	I2C1_InitStructure.I2C_ClockSpeed =	100000;
	I2C_Init(I2C1,&I2C1_InitStructure);
	I2C_Cmd(I2C1,ENABLE);
}

/** \brief This function disables the I2C peripheral. */
void i2c_disable(void)
{
	//i2c_master_disable(&i2c_master_instance);
	I2C1_GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
	GPIO_Init(GPIOB,&I2C1_GPIO_InitStructure);
}


/** \brief This function sets the address of the I2C peripheral.
			NOTE: Shifts bits right by 1 (addr >> 1) since the driver shifts left when sending address
 * */
void i2c_set_address(uint8_t addr)
{
	slave_address = (addr >> 1);
}

/** \brief This function sets the frequency of the I2C peripheral.
			NOTE: Frequency is defined in kHz
 * */
void i2c_set_speed(uint32_t spd_in_khz)
{
	//i2c_spd_in_khz = spd_in_khz;
	return;
}


/** \brief This function creates a Start condition (SDA low, then SCL low).
 * \return status of the operation
 */
uint8_t i2c_send_start(void)
{
	// Do nothing, return success
	return I2C_SUCCESS;
}

/** \brief This function creates a Stop condition (SCL high, then SDA high).
 * \return status of the operation
 */
uint8_t i2c_send_stop(void)
{
	return I2C_SUCCESS;
}

/** \brief This function sends bytes to an I2C device.
 * \param[in] count number of bytes to send
 * \param[in] data pointer to tx buffer
 * \return status of the operation
 */
uint8_t i2c_send_bytes(uint8_t count, uint8_t *data)
{
	uint32_t Timeout_Stucktime = ATSHA204A_STUCK_TIME;
	int8_t i = 0;
	
	while(I2C_GetFlagStatus(I2C1,I2C_FLAG_BUSY))
	{
		if(Timeout_Stucktime--==0)
			return I2C_TIMEOUT;
	}
	I2C_GenerateSTART(I2C1,ENABLE);
	
	Timeout_Stucktime = ATSHA204A_STUCK_TIME;
	while(!I2C_CheckEvent(I2C1,I2C_EVENT_MASTER_MODE_SELECT))	
	{
		if(Timeout_Stucktime--==0)
			return I2C_TIMEOUT;
	}
	I2C_Send7bitAddress(I2C1,slave_address,I2C_Direction_Transmitter);	
	
	Timeout_Stucktime = ATSHA204A_STUCK_TIME;
	while(!I2C_CheckEvent(I2C1,I2C_EVENT_MASTER_TRANSMITTER_MODE_SELECTED))
	{
		if(Timeout_Stucktime--==0)
			return I2C_TIMEOUT;
	}
	for(i=1;i>=0;i--)
	{
		I2C_SendData(I2C1,*data);
		data++;
		Timeout_Stucktime = ATSHA204A_STUCK_TIME;
		while(!I2C_CheckEvent(I2C1,I2C_EVENT_MASTER_BYTE_TRANSMITTED))
		{
			if(Timeout_Stucktime--==0)
				return I2C_TIMEOUT;
		}
	}
	return I2C_SUCCESS;
}

/** \brief This function receives one byte from an I2C device.
 *
 * \param[out] data pointer to received byte
 * \return status of the operation
 */
uint8_t i2c_receive_byte(uint8_t *data)
{
	return i2c_receive_bytes(1, data);
}

/** \brief This function receives bytes from an I2C device
 *         and sends a Stop.
 *
 * \param[in] count number of bytes to receive
 * \param[out] data pointer to rx buffer
 * \return status of the operation
 */
uint8_t i2c_receive_bytes(uint8_t count, uint8_t *data)
{
	DS3231_Timeout_Stucktime = DS3231_TIMEOUT;
	while(I2C_GetFlagStatus(I2C2,I2C_FLAG_BUSY))
	{
		if(DS3231_Timeout_Stucktime--==0)
		{
				return DS3231_Timeout_CallBack();
		}
	}
	
	I2C_GenerateSTART(I2C2,ENABLE);
	DS3231_Timeout_Stucktime = DS3231_TIMEOUT;
	while(!I2C_CheckEvent(I2C2,I2C_EVENT_MASTER_MODE_SELECT))
	{
		if(DS3231_Timeout_Stucktime--==0)
		{
				return DS3231_Timeout_CallBack();
		}
	}
		
	I2C_Send7bitAddress(I2C2,DS3231_ADDR,I2C_Direction_Transmitter);	
	DS3231_Timeout_Stucktime = DS3231_TIMEOUT;
	while(!I2C_CheckEvent(I2C2,I2C_EVENT_MASTER_TRANSMITTER_MODE_SELECTED))
	{
		if(DS3231_Timeout_Stucktime--==0)
		{
				return DS3231_Timeout_CallBack();
		}
	}

	I2C_SendData(I2C2,DS3231_SECONDS);
	DS3231_Timeout_Stucktime = DS3231_TIMEOUT;
	while(!I2C_CheckEvent(I2C2,I2C_EVENT_MASTER_BYTE_TRANSMITTED))
	{
		if(DS3231_Timeout_Stucktime--==0)
		{
				return DS3231_Timeout_CallBack();
		}
	}
	
	I2C_GenerateSTART(I2C2,ENABLE);
	DS3231_Timeout_Stucktime = DS3231_TIMEOUT;
	while(!I2C_CheckEvent(I2C2,I2C_EVENT_MASTER_MODE_SELECT))
	{
		if(DS3231_Timeout_Stucktime--==0)
		{
				return DS3231_Timeout_CallBack();
		}
	}

	I2C_Send7bitAddress(I2C2,DS3231_ADDR,I2C_Direction_Receiver);
	DS3231_Timeout_Stucktime = DS3231_TIMEOUT;
	while(!I2C_CheckEvent(I2C2,I2C_EVENT_MASTER_RECEIVER_MODE_SELECTED))
	{
		if(DS3231_Timeout_Stucktime--==0)
		{
				return DS3231_Timeout_CallBack();
		}		
	}
	__disable_irq();
	for(i = 0;i<7;i++)
	{
		
		if(6 == i)
		{
			I2C_AcknowledgeConfig(I2C2,DISABLE);
			I2C_GenerateSTOP(I2C2,ENABLE);//必须加到此处
		}
		DS3231_Timeout_Stucktime = DS3231_TIMEOUT;
		while(!I2C_CheckEvent(I2C2,I2C_EVENT_MASTER_BYTE_RECEIVED))
		{
			if(DS3231_Timeout_Stucktime--==0)
			{
				__enable_irq();
				return DS3231_Timeout_CallBack();
			}
		}			
		Temp8[i] = I2C_ReceiveData(I2C2);
	}
}

uint8_t i2c_send_wake()
{
	enum status_code statusCode = STATUS_OK;
	// Send the wake by writing to an address of 0x00
	struct i2c_master_packet packet = {
		.address     = 0x00,
		.data_length = 0,
		.data        = NULL,
		.ten_bit_address = false,
		.high_speed      = false,
		.hs_master_code  = 0x0,
	};

	// Send the 00 address as the wake pulse
	statusCode = i2c_master_write_packet_wait(&i2c_master_instance, &packet);
	
	// A NACK of the address is a successful wake
	return (statusCode == STATUS_ERR_BAD_ADDRESS) ? I2C_SUCCESS : statusCode;
}

uint8_t i2c_send_reset()
{
	enum status_code statusCode = STATUS_OK;
	// Send the wake by writing to an address of 0x00
	struct i2c_master_packet packet = {
		.address     = 0xFF,
		.data_length = 0,
		.data        = NULL,
		.ten_bit_address = false,
		.high_speed      = false,
		.hs_master_code  = 0x0,
	};

	// Send the FF address as the wake pulse
	statusCode = i2c_master_read_packet_wait_no_stop(&i2c_master_instance, &packet);

	// A NACK of the address is a successful reset
	return (statusCode == STATUS_ERR_BAD_ADDRESS) ? I2C_SUCCESS : statusCode;
}

///////////////////////////////////////////////////////////////////////////////
// Master implementation - wrapper functions
void phy_i2c_master_enable(i2c_bus_t bus)
{
	i2c_enable();
}

void phy_i2c_master_disable(i2c_bus_t bus)
{
	i2c_disable();
}


void i2c_master_set_slave_address(i2c_bus_t bus, uint8_t addr)
{
	i2c_set_address(addr);
}

void i2c_master_set_i2c_speed(i2c_bus_t bus, uint32_t spd_in_khz)
{
	i2c_set_speed(spd_in_khz);
}


uint8_t phy_i2c_master_send_start(i2c_bus_t bus)
{
	return i2c_send_start();
}

uint8_t phy_i2c_master_send_stop(i2c_bus_t bus)
{
	return i2c_send_stop();
}

uint8_t i2c_master_send_bytes(i2c_bus_t bus, uint8_t count, uint8_t *data)
{
	return i2c_send_bytes(count, data);
}

uint8_t i2c_master_receive_byte(i2c_bus_t bus, uint8_t *data)
{
	return i2c_receive_byte(data);
}

uint8_t i2c_master_receive_bytes(i2c_bus_t bus, uint8_t count, uint8_t *data)
{
	return i2c_receive_bytes(count, data);
}

uint8_t i2c_master_send_wake(i2c_bus_t bus)
{
	return i2c_send_wake();
}

uint8_t i2c_master_send_reset(i2c_bus_t bus)
{
	return i2c_send_reset();
}