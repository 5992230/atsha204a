/** \file
 *  \brief  Definitions and Prototypes for Physical Layer Interface of SHA204 Library
 *  \author Atmel Crypto Products
 *  \date 	October 25, 2013

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
#ifndef SHA204_PHYSICAL_H
#   define SHA204_PHYSICAL_H

#include <stdint.h>			// data type definitions

#include "sha204_config.h"	// configuration values


/** \defgroup atsha204_physical Module 03: Header File for Interface Abstraction Modules
 *
 * \brief This header file contains definitions and function prototypes for SWI and I2C.
 * The prototypes are the same for both interfaces but are of course implemented differently.
 * Always include this file no matter whether you use SWI or I2C.
@{ */

#define SHA204_RSP_SIZE_MIN			((uint8_t)  4)	//!< minimum number of bytes in response
#define SHA204_RSP_SIZE_MAX			((uint8_t) 35)	//!< maximum size of response packet

#define SHA204_BUFFER_POS_COUNT		(0)				//!< buffer index of count byte in command or response
#define SHA204_BUFFER_POS_DATA		(1)				//!< buffer index of data in response

//! width of Wakeup pulse in 10 us units
#define SHA204_WAKEUP_PULSE_WIDTH	(uint8_t) (6.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5)

//! delay between Wakeup pulse and communication in ms
#define SHA204_WAKEUP_DELAY			(uint8_t) (3.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5)


typedef enum {
	I2C_SPEED_100KHZ = 100000,
	I2C_SPEED_400KHZ = 400000,
	I2C_SPEED_1MHZ =  1000000
} i2c_speed_t;

typedef enum {
	I2CBUS_0,
	I2CBUS_1
} i2c_bus_t;


//#define CRYPTOAUTH_SLAVE_ADDRESS 0xC0
#define CRYPTOAUTH_SLAVE_ADDRESS 0xC8
//#define CRYPTOAUTH_SLAVE_ADDRESS 0xCA
#define CRYPTOAUTH_BUS I2CBUS_0

// Error codes for physical hardware dependent module
#define I2C_SUCCESS     ((uint8_t) 0x00) //!< Communication with device succeeded.
#define I2C_COMM_FAIL   ((uint8_t) 0xF0) //!< Communication with device failed.
#define I2C_TIMEOUT     ((uint8_t) 0xF1) //!< Communication timed out.
#define I2C_NACK        ((uint8_t) 0xF8) //!< I2C nack


//初始化I2C
void	sha204p_init(void);
//禁用I2C
void	sha204p_disable(void);

/****************I2C硬件相关函数******************/
//发送数据
static uint8_t sha204p_i2c_send(uint8_t word_address, uint8_t count, uint8_t *buffer);
//发送I2C从地址
uint8_t	sha204p_send_slave_address(i2c_bus_t bus, uint8_t read);
//接收响应数据
uint8_t	sha204p_receive_response(uint8_t size, uint8_t *response);
//发送一个字节
uint8_t sha204p_send_byte(uint8_t data);
//发送一个字节,不检查错误
uint8_t sha204p_send_byte_notcheck(uint8_t data);
//接收一个字节
uint8_t sha204p_receive_byte(uint8_t *data);


/*****************唤醒与同步I2C*************/
//唤醒ATSHA204A
uint8_t	sha204p_wakeup(void);
//同步ATSHA204A
uint8_t	sha204p_resync(uint8_t size, uint8_t *response);

/****************功能I2C函数****************/
//复位IO BUFFER
uint8_t	sha204p_reset_io(void);
//使ATSHA204A进入空闲状态
uint8_t	sha204p_idle(void);
//使ATSHA204A进入休眠状态
uint8_t	sha204p_sleep(void);
//发送命令包
uint8_t	sha204p_send_command(uint8_t count, uint8_t *command);

//下面两个函数不需要调用
void	sha204p_set_device_id(uint8_t i2caddr);
void	sha204p_i2c_set_spd(uint32_t spd_in_khz);


#endif
