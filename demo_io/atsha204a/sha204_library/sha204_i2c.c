/** \file
 *  \brief  Functions for I2C Physical Hardware Independent Layer of ATCA Library
 *  this module implements the API in sha204_protocol_adapter.h
 * 
 * \author Atmel Crypto Products
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
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
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
 *
 * \todo Develop solution to allow i2c, swi, and atphy to all live together in harmony. 
 *       Right now, you have to choose one
 */

#include <string.h>
#include "sha204_config.h"
#include "sha204_lib_return_codes.h"					// declarations of function return codes
#include "sha204_timer_utilities.h"						// modify by tww
//#include "i2c_phys.h"													// modify by tww
#include "sha204_physical.h"
#include "sha204_port.h"
/** \brief This enumeration lists all packet types sent to a ATCA device.
 *
 * The following byte stream is sent to a ATCA I2C device:
 *    {I2C start} {I2C address} {word address} [{data}] {I2C stop}.
 * Data are only sent after a word address of value #SHA204_I2C_PACKET_FUNCTION_NORMAL.
 */
enum i2c_word_address {
	SHA204_I2C_PACKET_FUNCTION_RESET,  //!< Reset device.
	SHA204_I2C_PACKET_FUNCTION_SLEEP,  //!< Put device into Sleep mode.
	SHA204_I2C_PACKET_FUNCTION_IDLE,   //!< Put device into Idle mode.
	SHA204_I2C_PACKET_FUNCTION_NORMAL  //!< Write / evaluate data that follow this word address byte.
};


/** \brief This enumeration lists flags for I2C read or write addressing. */
enum i2c_read_write_flag {
	I2C_WRITE = (uint8_t) 0x00,  //!< write command flag
	I2C_READ  = (uint8_t) 0x01   //!< read command flag
};

#define ATSHA204A_STUCK_TIME	0xFFFF

static uint8_t device_address;


//初始化I2C
void sha204p_init(void)
{
	i2c_init();
	device_address = SHA204_I2C_DEFAULT_ADDRESS;
}

//禁用I2C
void sha204p_disable(void)
{
	SDA_GPIO_OUT_HIGH();
	SCL_GPIO_OUT_HIGH();
}

//发送数据的函数
//word_address指示了这个数据包的作用
static uint8_t sha204p_i2c_send(uint8_t word_address, uint8_t count, uint8_t *buffer)
{
	uint8_t i2c_status = sha204p_send_slave_address(I2C_WRITE);
	if (i2c_status != I2C_SUCCESS)
		return SHA204_COMM_FAIL;

	i2c_status = sha204p_send_bytes(1, &word_address);
	if (i2c_status != I2C_SUCCESS)
		return SHA204_COMM_FAIL;
	if (count == 0) 
	{
		i2c_send_stop();
		return SHA204_SUCCESS;
	}
	i2c_status = sha204p_send_bytes(count, buffer);
	i2c_send_stop();
	sha204_delay_ms(1);
	if (i2c_status != I2C_SUCCESS)
		return SHA204_COMM_FAIL;
	else
		return SHA204_SUCCESS;
}

//使ATSHA204A进入空闲状态
uint8_t sha204p_idle(void)
{
	return sha204p_i2c_send(SHA204_I2C_PACKET_FUNCTION_IDLE,0,NULL);
}
//使ATSHA204A进入休眠状态
uint8_t sha204p_sleep(void)
{
	return sha204p_i2c_send(SHA204_I2C_PACKET_FUNCTION_SLEEP,0,NULL);
}
//复位IO BUFFER
uint8_t sha204p_reset_io(void)
{
	return sha204p_i2c_send(SHA204_I2C_PACKET_FUNCTION_RESET,0,NULL);
}
//发送命令包
uint8_t sha204p_send_command(uint8_t count, uint8_t *command)
{		
	return sha204p_i2c_send(SHA204_I2C_PACKET_FUNCTION_NORMAL,count,command);
}

//接收数据
uint8_t sha204p_receive_response(uint8_t size, uint8_t *response)
{
	uint8_t count;
	uint8_t i2c_status = sha204p_send_slave_address(I2C_READ);
	if (i2c_status != I2C_SUCCESS) 
	{
		if (i2c_status == I2C_NACK)
			i2c_status = SHA204_RX_NO_RESPONSE;
		return i2c_status;
	}

	i2c_status = sha204p_receive_byte(response);
	if (i2c_status != I2C_SUCCESS)
		return SHA204_COMM_FAIL;

	count = response[SHA204_BUFFER_POS_COUNT];
	if ((count < SHA204_RSP_SIZE_MIN) || (count > size)) 
	{
		i2c_send_stop();
		return SHA204_INVALID_SIZE;
	}		

	i2c_status = sha204p_receive_bytes(count - 1, &response[SHA204_BUFFER_POS_DATA]);
	sha204_delay_little(10);
	if (i2c_status != I2C_SUCCESS)
		return SHA204_COMM_FAIL;
	else
		return SHA204_SUCCESS;
}
//发送一个字节
uint8_t sha204p_send_byte(uint8_t data)
{
	uint8_t byte_bit_count = 0;
	Set_SDA_Output();
	for(byte_bit_count = 8; byte_bit_count > 0; byte_bit_count--)
	{
		SCL_GPIO_OUT_LOW();		
		if((data >> (byte_bit_count - 1)) & 0x01)
		{
			SDA_GPIO_OUT_HIGH();//SDA输出高电平/	
		}
		else
		{
			SDA_GPIO_OUT_LOW();//SDA输出低电平
		}		
		SCL_GPIO_OUT_HIGH();
	}
	return I2C_SUCCESS;
}

//发送若干字节
uint8_t sha204p_send_bytes(uint8_t count, uint8_t *data)
{
	uint8_t ack_nack;
	uint8_t temp;
	for(temp = 0; temp < count; temp++)
	{
		sha204p_send_byte(*data++);
		ack_nack = i2c_read_ack();
		if(NACK == ack_nack)
		{
			return I2C_NACK;
		}
	}
	return I2C_SUCCESS;
}

//接收一个字节
uint8_t sha204p_receive_byte(uint8_t *data)
{
	*data = i2c_read_byte();
	i2c_send_ack_nack(ACK);
	return I2C_SUCCESS;
}

//接收若干字节
uint8_t sha204p_receive_bytes(uint8_t count, uint8_t *data)
{
	uint8_t temp;
	for(temp = 0;temp < count -1;temp++)
	{
		*data++ = i2c_read_byte();
		i2c_send_ack_nack(ACK);
	}
	*data = i2c_read_byte();
	i2c_send_ack_nack(NACK);
	return i2c_send_stop();
}



uint8_t sha204p_send_slave_address(uint8_t read)
{
	uint8_t sla = device_address | read;
	uint8_t ret_code = i2c_send_start();
	if (ret_code != I2C_SUCCESS)
	{
		return ret_code;
	}
	ret_code = sha204p_send_bytes(1, &sla);

	if (ret_code != I2C_SUCCESS)
	{
		i2c_send_stop();
	}
	return ret_code;
}

//唤醒设备
uint8_t sha204p_wakeup(void)
{	
	uint8_t dummy_byte = 0;
	uint8_t i2c_status = i2c_send_start();	
	sha204_delay_10us(SHA204_WAKEUP_PULSE_WIDTH);//60us
	sha204p_send_bytes(1,&dummy_byte);
	i2c_status |= i2c_send_stop();
	sha204_delay_ms(SHA204_WAKEUP_DELAY);
	return SHA204_SUCCESS;
}
//I2C同步
uint8_t sha204p_resync(uint8_t size, uint8_t *response)
{
	uint8_t nine_clocks = 0xFF;
	uint8_t ret_code = i2c_send_start();
	sha204p_send_bytes(1, &nine_clocks);

	ret_code = sha204p_send_slave_address(I2C_READ);
	if (ret_code == I2C_SUCCESS)
		ret_code = i2c_send_stop();

	if (ret_code != I2C_SUCCESS)
		return SHA204_COMM_FAIL;

	return sha204p_reset_io();

}

/****************IO口模拟函数****************/
uint8_t i2c_send_start(void)
{
	SCL_GPIO_OUT_LOW();
	Set_SDA_Output();
	SDA_GPIO_OUT_HIGH();
	SCL_GPIO_OUT_HIGH();
	SDA_GPIO_OUT_LOW();
	SCL_GPIO_OUT_LOW();
	return SHA204_SUCCESS;
}
uint8_t i2c_send_stop(void)
{
	SCL_GPIO_OUT_LOW();//SCL out low
	Set_SDA_Output();
	SDA_GPIO_OUT_LOW();//SDA out low
	SCL_GPIO_OUT_HIGH();	//SCL out high
	SDA_GPIO_OUT_HIGH();//SDA out high	
	return SHA204_SUCCESS;
}
uint8_t i2c_read_byte(void)
{
	uint8_t byte_bit_count = 0;
	uint8_t data = 0;
	Set_SDA_Input();
	for(byte_bit_count = 0;byte_bit_count < 8;byte_bit_count++)
	{
		SCL_GPIO_OUT_LOW();
		SCL_GPIO_OUT_HIGH();
		data = data << 1;
		if(READ_SDA_GPIO())
		{
			data |= 0x01;
		}
	}
	SCL_GPIO_OUT_LOW();	
	return data;
}

uint8_t i2c_read_ack(void)
{
	uint8_t error_times = 0;	
	SCL_GPIO_OUT_LOW();
	Set_SDA_Input();
	SCL_GPIO_OUT_HIGH();
	while(READ_SDA_GPIO() == NACK)
	{
		if(error_times >= 4)
		{
			SCL_GPIO_OUT_LOW();
			return NACK;
		}
		error_times++;
		sha204_delay_us(1);
	}
	SCL_GPIO_OUT_LOW();	
	return ACK;	
}

void i2c_send_ack_nack(uint8_t ack_nack)
{
	SCL_GPIO_OUT_LOW();
	Set_SDA_Output();	
	if(NACK==ack_nack)
	{
		SDA_GPIO_OUT_HIGH();//SDA out high
	}
	else
	{
		SDA_GPIO_OUT_LOW();//SDA out low
	}	
	SCL_GPIO_OUT_HIGH();
	SCL_GPIO_OUT_LOW();
}

