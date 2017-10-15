#include "sha204_port.h"
#include "stm32f10x_conf.h"
#include "sha204_lib_return_codes.h"

void i2c_init(void)
{
	GPIO_InitTypeDef GPIO_InitStructure;
	RCC_APB2PeriphClockCmd(	RCC_APB2Periph_GPIOB, ENABLE );	
	GPIO_InitStructure.GPIO_Pin = GPIO_Pin_10|GPIO_Pin_11;
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP ; //推挽输出
	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
	GPIO_SetBits(GPIOB,GPIO_Pin_10|GPIO_Pin_11);
	GPIO_Init(GPIOB, &GPIO_InitStructure);
}

//设置SDA输入
void Set_SDA_Input(void)
{
	GPIO_InitTypeDef GPIO_InitStructure;	   
	GPIO_InitStructure.GPIO_Pin = GPIO_Pin_11;
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_IN_FLOATING ; //推挽输入
	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;	
	GPIO_Init(GPIOB, &GPIO_InitStructure);
}

//设置SDA输出
void Set_SDA_Output(void)
{
	GPIO_InitTypeDef GPIO_InitStructure;	   
	GPIO_InitStructure.GPIO_Pin = GPIO_Pin_11;
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_Out_PP ; //推挽输出
	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;	
	GPIO_Init(GPIOB, &GPIO_InitStructure);
}
