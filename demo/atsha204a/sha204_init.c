#include "sha204_init.h"

static uint8_t wakeup_response_buffer[4] = {0};
static uint8_t tx_buffer[SHA204_CMD_SIZE_MAX] = {0};
static uint8_t rx_buffer[SHA204_RSP_SIZE_MAX] = {0};

static atsha204a_config at_config;
static atsha204a_slot at_slot;
static atsha204a_otp at_otp;
static uint8_t slot_and_otp[sizeof(atsha204a_slot) + sizeof(atsha204a_otp)];

const atsha204a_config at_default_config = 
{
	.i2caddress = {0xC8,0x00,0x55,0x00},
	.slotcfg01 =  {0x8F,0x80,0x80,0xA1},
	.slotcfg23 = {0x82,0xE0,0xA3,0x60},	
	.slotcfg45 = {0x94 ,0x40 ,0xA0 ,0x85},
	.slotcfg67 = {0x86 ,0x40 ,0x87 ,0x07},
	.slotcfg89 = {0x0F ,0x00 ,0x89 ,0xF2},
	.slotcfg1011 = {0x8A ,0x7A ,0x0B ,0x8B},	
	.slotcfg1213 = {0x0C ,0x4C ,0xDD ,0x4D},
	.slotcfg1415 = {0xC2 ,0x42 ,0xAF ,0x8F},
	.useflag01 = {0xFF ,0x00 ,0xFF ,0x00},	
	.useflag23 = {0xFF ,0x00 ,0xFF ,0x00},	
	.useflag45 = {0xFF ,0x00 ,0xFF ,0x00},
	.useflag67 = {0xFF ,0x00 ,0xFF ,0x00},	
	.lastkey0 = {0xFF ,0xFF ,0xFF ,0xFF},
	.lastkey4 = {0xFF ,0xFF ,0xFF ,0xFF},
	.lastkey8 = {0xFF ,0xFF ,0xFF ,0xFF},
	.lastkey12 = {0xFF ,0xFF ,0xFF ,0xFF},
};

//写配置
uint8_t WriteConfig(atsha204a_config* cfg)
{
	uint8_t state = 0;
	uint8_t i = 0;
	uint8_t words = 0;
	uint32_t index = 4*4;
	uint8_t *buffer = (uint8_t*)cfg;

	//先查看是否已经锁定
	state = sha204m_execute(SHA204_READ,
													0x00,			//4字节读取
													0x15,
													0,0,0,0,0,0,
													SHA204_CMD_SIZE_MIN,
													tx_buffer,
													READ_32_RSP_SIZE,
													rx_buffer
													);
	if(I2C_SUCCESS != state)
	{
		return state;
	}
	if(rx_buffer[SHA204_BUFFER_POS_DATA+3] != 0x55)
	{
		return CONFIG_LOCK;
	}	

	for(i = 0;i<4;i++)
	{
		state = sha204m_execute(SHA204_WRITE,
														0x00,			//4字节写入
														i+4,			//
														4,&buffer[index],0,0,0,0,
														SHA204_CMD_SIZE_MIN,
														tx_buffer,
														READ_32_RSP_SIZE,
														rx_buffer
														);
		if(SHA204_SUCCESS != state)
		{
			return state;
		}
		index += 4;
	}
	
	words = 0x08;
	state = sha204m_execute(SHA204_WRITE,
													0x80,			//32字节写入
													words,		//
													32,&buffer[index],0,0,0,0,
													SHA204_CMD_SIZE_MIN,
													tx_buffer,
													READ_32_RSP_SIZE,
													rx_buffer
													);
	if(SHA204_SUCCESS != state)
	{		
		return state;
	}
	index += 32;
	words = 0x10;
	for(i = 0;i<5;i++)
	{
		state = sha204m_execute(SHA204_WRITE,
														0x00,			//4字节写入
														i+words,		//写哪一块(配置区一共0x00-0x15,每一块4字节)
														4,&buffer[index],0,0,0,0,
														SHA204_CMD_SIZE_MIN,
														tx_buffer,
														READ_32_RSP_SIZE,
														rx_buffer
														);
		if(SHA204_SUCCESS != state)
		{
			return state;
		}
		index+=4;
	}
	memcpy(&at_config.i2caddress[0],&buffer[4*4],sizeof(atsha204a_config) - 20);	
	return SHA204_SUCCESS;
}

//读部分配置(用于校验)
uint8_t ReadSomeConfig(atsha204a_config* cfg)
{
	uint8_t state = 0;
	uint8_t words = 0;
	
	state = sha204m_execute(SHA204_READ,
													0x80,			//32字节读取
													words,		//
													0,0,0,0,0,0,
													SHA204_CMD_SIZE_MIN,
													tx_buffer,
													READ_32_RSP_SIZE,
													rx_buffer
													);
	if(SHA204_SUCCESS != state)
	{
		return state;
	}
	memcpy(cfg,&rx_buffer[SHA204_BUFFER_POS_DATA],16);
	
	words = 0x15;
	state = sha204m_execute(SHA204_READ,
													0x00,			//4字节读取
													words,		//读哪一块(配置区一共0x00-0x15,每一块4字节)
													0,0,0,0,0,0,
													SHA204_CMD_SIZE_MIN,
													tx_buffer,
													READ_32_RSP_SIZE,
													rx_buffer
													);
	if(SHA204_SUCCESS != state)
	{
		return state;
	}
	memcpy(&cfg->userextra,&rx_buffer[SHA204_BUFFER_POS_DATA],4);
	
	return SHA204_SUCCESS;
}

//写slot
uint8_t WriteSlot(atsha204a_slot* slot)
{
	uint8_t state = 0;
	uint8_t i = 0;
	uint32_t index = 0;
	uint8_t* buffer = (uint8_t*)slot;
	
	//先查看是否已经锁定
	state = sha204m_execute(SHA204_READ,
													0x00,			//4字节读取
													0x15,
													0,0,0,0,0,0,
													SHA204_CMD_SIZE_MIN,
													tx_buffer,
													READ_32_RSP_SIZE,
													rx_buffer
													);
	if(I2C_SUCCESS != state)
	{
		return state;
	}
	if(rx_buffer[SHA204_BUFFER_POS_DATA+3] == 0x55)
	{
		return CONFIG_UNLOCK;
	}
	if(rx_buffer[SHA204_BUFFER_POS_DATA+2] == 0x00)
	{
		return DATA_LOCK;
	}
	
	for(i = 0;i<16;i++)
	{		
			state = sha204m_execute(SHA204_WRITE,
															0x80|0x02,			//32字节写入
															i<<3,
															32,&buffer[index],0,0,0,0,
															SHA204_CMD_SIZE_MIN,
															tx_buffer,
															READ_32_RSP_SIZE,
															rx_buffer
															);
			if(SHA204_SUCCESS != state)
			{
				return state;
			}		
		index+=32;
	}
	memcpy(&at_slot,slot,sizeof(atsha204a_slot));
	return SHA204_SUCCESS;
}

//写otp
uint8_t WriteOtp(atsha204a_otp* otp)
{
	uint8_t state = 0;
	uint8_t i = 0;
	uint32_t index = 0;
	uint8_t* buffer = (uint8_t*)otp;
	
	//先查看是否已经锁定
	state = sha204m_execute(SHA204_READ,
													0x00,			//4字节读取
													0x15,
													0,0,0,0,0,0,
													SHA204_CMD_SIZE_MIN,
													tx_buffer,
													READ_32_RSP_SIZE,
													rx_buffer
													);
	if(I2C_SUCCESS != state)
	{
		return state;
	}
	if(rx_buffer[SHA204_BUFFER_POS_DATA+3] == 0x55)
	{
		return CONFIG_UNLOCK;
	}
	if(rx_buffer[SHA204_BUFFER_POS_DATA+2] == 0x00)
	{
		return DATA_LOCK;
	}
	//查看OTP模式
	state = sha204m_execute(SHA204_READ,
													0x00,			//4字节读取
													0x04,
													0,0,0,0,0,0,
													SHA204_CMD_SIZE_MIN,
													tx_buffer,
													READ_32_RSP_SIZE,
													rx_buffer
													);
	if(I2C_SUCCESS != state)
	{
		return state;
	}
	if(rx_buffer[SHA204_BUFFER_POS_DATA+2] == 0x00)
	{
		return DATA_LOCK;
	}
	for(i = 0;i<2;i++)
	{
		state = sha204m_execute(SHA204_WRITE,
														0x80|0x01,			//32字节写入
														i<<3,
														32,&buffer[index],0,0,0,0,
														SHA204_CMD_SIZE_MIN,
														tx_buffer,
														READ_32_RSP_SIZE,
														rx_buffer
														);
		if(SHA204_SUCCESS != state)
		{
			return state;
		}
		index+=32;
	}
	
	memcpy(&at_otp,otp,sizeof(atsha204a_otp));
	return SHA204_SUCCESS;
}

//锁配置
uint8_t LockConfig(void)
{
	uint8_t state = 0;
	uint8_t crc[2] = {0};
	uint16_t crc16 = 0;
	//先查看是否已经锁定
	state = sha204m_execute(SHA204_READ,
													0x00,			//4字节读取
													0x15,
													0,0,0,0,0,0,
													SHA204_CMD_SIZE_MIN,
													tx_buffer,
													READ_32_RSP_SIZE,
													rx_buffer
													);
	if(I2C_SUCCESS != state)
	{
		return state;
	}
	if(rx_buffer[SHA204_BUFFER_POS_DATA+3] != 0x55)
	{
		return LOCKFAIL_CFG_LOCK;
	}
		
	sha204c_calculate_crc(sizeof(atsha204a_config),(uint8_t*)&at_config,crc);
	crc16 = ((uint16_t)crc[1]<<8) + crc[0];
	state = sha204m_execute(SHA204_LOCK,
														0,
														crc16,
														0,0,0,0,0,0,
														SHA204_CMD_SIZE_MIN,
														tx_buffer,
														READ_32_RSP_SIZE,
														rx_buffer
														);
		if(SHA204_SUCCESS != state)
		{
			return state;
		}
	
	return SHA204_SUCCESS;
}

//锁数据
uint8_t LockData(void)
{
	uint8_t state = 0;
	uint8_t crc[2] = {0};
	uint16_t crc16 = 0;

	//先查看是否已经锁定
	state = sha204m_execute(SHA204_READ,
													0x00,			//4字节读取
													0x15,
													0,0,0,0,0,0,
													SHA204_CMD_SIZE_MIN,
													tx_buffer,
													READ_32_RSP_SIZE,
													rx_buffer
													);
	if(I2C_SUCCESS != state)
	{
		return state;
	}
	if(rx_buffer[SHA204_BUFFER_POS_DATA+2] != 0x55)
	{
		return LOCKFAIL_DATA_LOCK;
	}
	
	
	memcpy(slot_and_otp,&at_slot,sizeof(atsha204a_slot));
	memcpy(slot_and_otp+sizeof(atsha204a_slot),&at_otp,sizeof(atsha204a_otp));
	
	
	sha204c_calculate_crc(sizeof(atsha204a_slot)+sizeof(atsha204a_otp),slot_and_otp,crc);
	crc16 = ((uint16_t)crc[1]<<8) + crc[0];
	state = sha204m_execute(SHA204_LOCK,
													1,
													crc16,
													0,0,0,0,0,0,
													SHA204_CMD_SIZE_MIN,
													tx_buffer,
													READ_32_RSP_SIZE,
													rx_buffer
													);
	if(SHA204_SUCCESS != state)
	{
		return state;
	}
	
	return SHA204_SUCCESS;
}

//全部写入
uint8_t AllConfig(atsha204a_config* cfg,atsha204a_slot* slot,atsha204a_otp* otp)
{
	uint8_t state = 0;
	state = sha204c_wakeup(wakeup_response_buffer);
	if(state != SHA204_SUCCESS)
		return state;
	
	state = WriteConfig(cfg);
	if(state != SHA204_SUCCESS)
		return state;
	
	state = ReadSomeConfig(&at_config);
	if(state != SHA204_SUCCESS)
		return state;
	
	state = LockConfig();
	if(state != SHA204_SUCCESS)
		return state;
	
	state = WriteSlot(slot);
	if(state != SHA204_SUCCESS)
		return state;
	
	state = WriteOtp(otp);
	if(state != SHA204_SUCCESS)
		return state;
	
	state = LockData();
	if(state != SHA204_SUCCESS)
		return state;
		
	return state;
}
