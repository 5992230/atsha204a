#include "stm32f10x_conf.h"
#include "sha204_command.h"
#include "sha204_test.h"
#include "usart1.h"
#include "sha204_timer_utilities.h"

int main()
{
	sha204p_init();
	USART1_Config();
	//TestReadConfig();
	TestMac();
	while(1)
	{
	}
	return 0;
}
