#ifndef _SHA204_PORT_H_
#define _SHA204_PORT_H_
#include <stdint.h>			// data type definitions
#include "sha204_config.h"	// configuration values
#include "sha204_timer_utilities.h"
#include "stm32f10x_conf.h"

//IO�ڳ�ʼ��
void i2c_init(void);

//����SDA����
void Set_SDA_Input(void);

//����SDA���
void Set_SDA_Output(void);

//SDA����
#define SDA_GPIO_OUT_LOW() GPIO_ResetBits(GPIOB, GPIO_Pin_11)	
//SDA����
#define SDA_GPIO_OUT_HIGH() GPIO_SetBits(GPIOB, GPIO_Pin_11)

//SCL������ʱ
#define SCL_GPIO_OUT_LOW()  do {\
	sha204_delay_us(1);\
	GPIO_ResetBits(GPIOB, GPIO_Pin_10);\
	sha204_delay_us(1);\
}while(0)

//SCL������ʱ
#define SCL_GPIO_OUT_HIGH() do {\
	sha204_delay_us(1);\
	GPIO_SetBits(GPIOB, GPIO_Pin_10);\
	sha204_delay_us(1);\
}while(0)

#define READ_SDA_GPIO()		GPIO_ReadInputDataBit(GPIOB, GPIO_Pin_11)	//SDA data

#define NACK   1
#define ACK    0


#endif

