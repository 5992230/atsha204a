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
#include "stm32f10x_conf.h"
#include "sha204_physical.h"

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

#define ATSHA204A_STUCK_TIME	(50*8000)

static uint8_t device_address;
static	GPIO_InitTypeDef 	I2C2_GPIO_InitStructure;
static 	I2C_InitTypeDef 	I2C2_InitStructure;

#define NACK   TRUE
#define ACK    FALSE

#define SDA_GPIO_OUT_LOW() GPIO_ResetBits(GPIOB, GPIO_Pin_11)  //PB11 output low		
#define SDA_GPIO_OUT_HIGH() GPIO_SetBits(GPIOB, GPIO_Pin_11)  //PB11 output high

#define SCL_GPIO_OUT_LOW() GPIO_ResetBits(GPIOB, GPIO_Pin_10)  //PB10 output low
#define SCL_GPIO_OUT_HIGH() GPIO_SetBits(GPIOB, GPIO_Pin_10)  //PB10 output high


//初始化I2C
void sha204p_init(void)
{
	device_address = CRYPTOAUTH_SLAVE_ADDRESS;
	RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOB,ENABLE);
	RCC_APB1PeriphClockCmd(RCC_APB1Periph_I2C2, ENABLE);
	I2C_DeInit(I2C2);
	
	I2C2_GPIO_InitStructure.GPIO_Pin = GPIO_Pin_10|GPIO_Pin_11;
	I2C2_GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
	I2C2_GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF_OD;
	GPIO_Init(GPIOB,&I2C2_GPIO_InitStructure);
	
	I2C_StructInit(&I2C2_InitStructure);
	I2C2_InitStructure.I2C_OwnAddress1 = 0xA0;  
	I2C2_InitStructure.I2C_Ack = I2C_Ack_Enable; 
	I2C2_InitStructure.I2C_ClockSpeed =	100000;
	I2C_Init(I2C2,&I2C2_InitStructure);
	I2C_Cmd(I2C2,ENABLE);
}

//禁用I2C
void sha204p_disable(void)
{
	I2C_Cmd(I2C2,DISABLE);
	I2C2_GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
	GPIO_Init(GPIOB,&I2C2_GPIO_InitStructure);
}

//复位
void sha204_i2c_reset(void)
{
	GPIO_InitTypeDef GPIO_InitStructure;
	RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOB,ENABLE);	
	GPIO_InitStructure.GPIO_Pin = GPIO_Pin_10|GPIO_Pin_11;
	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_OD;
	GPIO_Init(GPIOB,&GPIO_InitStructure);
	SDA_GPIO_OUT_HIGH();
	SCL_GPIO_OUT_HIGH();
	
	I2C_SoftwareResetCmd(I2C2,ENABLE);
	I2C_SoftwareResetCmd(I2C2,DISABLE);
	
	SDA_GPIO_OUT_LOW();
	sha204_delay_ms(10);
	SCL_GPIO_OUT_LOW();
}

static uint32_t Timeout_CallBack(void)
{	
	/*
	I2C_Cmd(I2C2,DISABLE);
	I2C_DeInit(I2C2);
	sha204_i2c_reset();
	sha204p_init();
	*/
	I2C_SoftwareResetCmd(I2C2,ENABLE);
	sha204_delay_ms(10);
	I2C_SoftwareResetCmd(I2C2,DISABLE);
	sha204p_init();
	/*
	GPIO_InitTypeDef 	GPIO_InitStructure;
	I2C2_GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
	GPIO_Init(GPIOB,&I2C2_GPIO_InitStructure);
	GPIO_ResetBits(GPIOB,GPIO_Pin_11);
	sha204_delay_ms(10);
	I2C_SoftwareResetCmd(I2C2,ENABLE);
	I2C_SoftwareResetCmd(I2C2,DISABLE);
	sha204p_init();
	*/
	return 0;
}

//发送数据的函数
//word_address指示了这个数据包的作用
static uint8_t sha204p_i2c_send(uint8_t word_address, uint8_t count, uint8_t *buffer)
{
	uint32_t Timeout_Stucktime = ATSHA204A_STUCK_TIME;
	int8_t i = 0;
	while(I2C_GetFlagStatus(I2C2,I2C_FLAG_BUSY))
	{
		if(Timeout_Stucktime--==0)
		{
			Timeout_CallBack();
			return SHA204_COMM_FAIL;
		}
	}
	I2C_GenerateSTART(I2C2,ENABLE);
	
	Timeout_Stucktime = ATSHA204A_STUCK_TIME;
	while(!I2C_CheckEvent(I2C2,I2C_EVENT_MASTER_MODE_SELECT))	
	{
		if(Timeout_Stucktime--==0)
		{
			Timeout_CallBack();
			return SHA204_COMM_FAIL;
		}
	}
	I2C_Send7bitAddress(I2C2,device_address,I2C_Direction_Transmitter);	
	
	Timeout_Stucktime = ATSHA204A_STUCK_TIME;
	while(!I2C_CheckEvent(I2C2,I2C_EVENT_MASTER_TRANSMITTER_MODE_SELECTED))
	{
		if(Timeout_Stucktime--==0)
		{
			Timeout_CallBack();
			return SHA204_COMM_FAIL;
		}
	}
	sha204p_send_byte(word_address);
	
	for(i=0;i<count;i++)
	{
		I2C_SendData(I2C2,*buffer);
		buffer++;
		Timeout_Stucktime = ATSHA204A_STUCK_TIME;
		while(!I2C_CheckEvent(I2C2,I2C_EVENT_MASTER_BYTE_TRANSMITTED))
		{
			if(Timeout_Stucktime--==0)
			{
				Timeout_CallBack();
				return SHA204_COMM_FAIL;
			}
		}
	}
	
	I2C_GenerateSTOP(I2C2,ENABLE);
	I2C_AcknowledgeConfig(I2C2,ENABLE);
	sha204_delay_ms(1);
	return I2C_SUCCESS;
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
	uint8_t count = 0;
	uint32_t Timeout_Stucktime = ATSHA204A_STUCK_TIME;
	uint8_t i = 0;
	I2C_GenerateSTART(I2C2,ENABLE);
	
	Timeout_Stucktime = ATSHA204A_STUCK_TIME;
	while(!I2C_CheckEvent(I2C2,I2C_EVENT_MASTER_MODE_SELECT))//是否已经选中总线
	{		
		if(Timeout_Stucktime--==0)
		{
			Timeout_CallBack();
			return SHA204_COMM_FAIL;
		}
	}
	I2C_Send7bitAddress(I2C2,device_address,I2C_Direction_Receiver);
	
	Timeout_Stucktime = ATSHA204A_STUCK_TIME;
	__disable_irq();
	while(!I2C_CheckEvent(I2C2,I2C_EVENT_MASTER_RECEIVER_MODE_SELECTED))
	{
		if(Timeout_Stucktime--==0)
		{
			__enable_irq();
			Timeout_CallBack();
			return SHA204_RX_NO_RESPONSE;
		}
	}	
	
	if(I2C_SUCCESS!=sha204p_receive_byte(response))
	{
			__enable_irq();
			return SHA204_RX_FAIL;
	}	
	count = response[SHA204_BUFFER_POS_COUNT];
	if ((count < SHA204_RSP_SIZE_MIN) || (count > size)) 
	{
			__enable_irq();
			I2C_GenerateSTOP(I2C2,ENABLE);
			return SHA204_INVALID_SIZE;
	}		
	
	for(i = 0;i<count;i++)
	{
		if(i == count-1)
		{
			I2C_AcknowledgeConfig(I2C2,DISABLE);
			I2C_GenerateSTOP(I2C2,ENABLE);//必须加到此处
		}
		Timeout_Stucktime = ATSHA204A_STUCK_TIME;
		while(!I2C_CheckEvent(I2C2,I2C_EVENT_MASTER_BYTE_RECEIVED))
		{
			if(Timeout_Stucktime--==0)
			{
				__enable_irq();
				Timeout_CallBack();
				return SHA204_RX_FAIL;
			}
		}
		response[i+1] = I2C_ReceiveData(I2C2);
	}
	__enable_irq();
	I2C_AcknowledgeConfig(I2C2,ENABLE);
	sha204_delay_little(10);
	return I2C_SUCCESS;
}
//发送一个字节
uint8_t sha204p_send_byte(uint8_t data)
{
	uint32_t Timeout_Stucktime = ATSHA204A_STUCK_TIME;
	I2C_SendData(I2C2,data);
	Timeout_Stucktime = ATSHA204A_STUCK_TIME;
	while(!I2C_CheckEvent(I2C2,I2C_EVENT_MASTER_BYTE_TRANSMITTED))
	{
		if(Timeout_Stucktime--==0)
		{			
			Timeout_CallBack();
			return SHA204_COMM_FAIL;
		}
	}
	return I2C_SUCCESS;
}

//发送一个字节,不检查错误
uint8_t sha204p_send_byte_notcheck(uint8_t data)
{
	uint32_t Timeout_Stucktime = ATSHA204A_STUCK_TIME;
	I2C_SendData(I2C2,data);
	Timeout_Stucktime = ATSHA204A_STUCK_TIME;
	while(!I2C_CheckEvent(I2C2,I2C_EVENT_MASTER_BYTE_TRANSMITTED))
	{
		if(Timeout_Stucktime--==0)
		{			
			return I2C_SUCCESS;
		}
	}
	return I2C_SUCCESS;
}

//接收一个字节
uint8_t sha204p_receive_byte(uint8_t *data)
{
	uint32_t Timeout_Stucktime = ATSHA204A_STUCK_TIME;
	while(!I2C_CheckEvent(I2C2,I2C_EVENT_MASTER_BYTE_RECEIVED))
	{
		if(Timeout_Stucktime--==0)
		{
			Timeout_CallBack();
			return SHA204_COMM_FAIL;
		}
	}
	*data = I2C_ReceiveData(I2C2);
	return I2C_SUCCESS;
}

//唤醒设备
uint8_t sha204p_wakeup(void)
{
	
	uint8_t i2c_status = I2C_SUCCESS;
	I2C_GenerateSTART(I2C2,ENABLE);
	sha204_delay_10us(60);
	
	i2c_status |= sha204p_send_byte_notcheck(0x00);
	I2C_GenerateSTOP(I2C2,ENABLE);
	
	sha204_delay_ms(SHA204_WAKEUP_DELAY);

	return I2C_SUCCESS;
}
//I2C同步
uint8_t sha204p_resync(uint8_t size, uint8_t *response)
{
	/*
	I2C_Cmd(I2C2,DISABLE);
	I2C2_GPIO_InitStructure.GPIO_Pin = GPIO_Pin_10|GPIO_Pin_11;
	I2C2_GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
	I2C2_GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP;
	GPIO_Init(GPIOB,&I2C2_GPIO_InitStructure);
	SDA_GPIO_OUT_HIGH();
	SCL_GPIO_OUT_HIGH();
	I2C_SoftwareResetCmd(I2C2,ENABLE);
	I2C_SoftwareResetCmd(I2C2,DISABLE);
	sha204_delay_ms(10);
	
	sha204p_init();

	return sha204p_reset_io();
	*/
	uint8_t i2c_status = I2C_SUCCESS;
	I2C_GenerateSTART(I2C2,ENABLE);
	i2c_status = sha204p_send_byte_notcheck(0xFF);
	i2c_status = sha204p_send_byte_notcheck(device_address | I2C_READ);
	if (i2c_status == I2C_SUCCESS)
		I2C_GenerateSTOP(I2C2,ENABLE);

	return sha204p_reset_io();
	

}

//IO口初始化
void sha204p_i2c_soft_init(void)
{
	GPIO_InitTypeDef GPIO_InitStructure;
	RCC_APB2PeriphClockCmd(	RCC_APB2Periph_GPIOB, ENABLE );	
	   
	GPIO_InitStructure.GPIO_Pin = GPIO_Pin_10|GPIO_Pin_11;
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP ; //推挽输出
	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
	
	GPIO_SetBits(GPIOB,GPIO_Pin_10|GPIO_Pin_11); //PB6,PB7 输出高		
	GPIO_Init(GPIOB, &GPIO_InitStructure);
}
//发送开始
uint8_t sha204p_i2c_send_start(void)
{
	/*
	scl_out_low();//SCL out low

	set_sda_pin_output();
	SDA_GPIO_OUT_HIGH();//SDA out high

	scl_out_high();	//SCL out high
	
	SDA_GPIO_OUT_LOW();	//SDA out low

	scl_out_low();//SCL out low
	
	return I2C_FUNCTION_RETCODE_SUCCESS;
	*/
	return SHA204_SUCCESS;
}
//发送stop
uint8_t sha204p_i2c_send_stop(void)
{
	return SHA204_SUCCESS;
}

//发送地址
uint8_t sha204p_i2c_send_address(uint8_t address)
{
	return SHA204_SUCCESS;
}

//发送一个字节
uint8_t sha204p_i2c_soft_sendbyte(uint8_t b)
{
	return SHA204_SUCCESS;
}

//接收一个字节
uint8_t sha204p_i2c_soft_receivebyte(uint8_t* data)
{
	return SHA204_SUCCESS;
}

//接收一个ack
uint8_t sha204p_i2c_read_ack(void)
{
	return SHA204_SUCCESS;
}

//发送一个ack
uint8_t sha204p_i2c_send_ack(void)
{
	return SHA204_SUCCESS;
}

void sha204p_set_device_id(uint8_t i2caddr)
{
	return;
}

void sha204p_i2c_set_spd(uint32_t spd_in_khz)
{
	return;
}
