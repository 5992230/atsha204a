#ifndef __USART1_H
#define	__USART1_H

#include "stm32f10x.h"
#include "stm32f10x_usart.h"
#include <stdio.h>

void USART1_Config(void);
int fputc(int ch, FILE *f);
void USART1_printf(USART_TypeDef* USARTx, uint8_t *Data,...);
void printf_array(char *ptr_array_name,uint8_t *ptr_buffer,uint8_t buffer_size);

#endif /* __USART1_H */
