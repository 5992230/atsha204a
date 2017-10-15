#ifndef _SHA204_INIT_H_
#define _SHA204_INIT_H_
#include "sha204_command.h"
#include <stdint.h>

#define CONFIG_UNLOCK		0x81
#define DATA_UNLOCK			0x82
#define OTP_MODE_ERR		0x83
#define CONFIG_LOCK			0x84
#define DATA_LOCK				0x85
#define INVAILD_CODE		0x86
#define CRC_ERROR				0x87
#define LOCKFAIL_IC_CHANGE	0x89
#define LOCKFAIL_CFG_NO_WRITE	0x8A
#define LOCKFAIL_CFG_NO_READ	0x8A
#define LOCKFAIL_SLOT_NO_WRITE 0x8B
#define LOCKFAIL_OTP_NO_WRITE  0x8C
#define LOCKFAIL_CFG_LOCK			 0x8D
#define LOCKFAIL_DATA_LOCK		 0x8E

typedef struct atsha204a_config
{
	uint8_t serial0_3[4];
	uint8_t revision[4];
	uint8_t serial4_7[4];
	uint8_t sn8[4];
	uint8_t i2caddress[4];
	uint8_t slotcfg01[4];
	uint8_t slotcfg23[4];
	uint8_t slotcfg45[4];
	uint8_t slotcfg67[4];
	uint8_t slotcfg89[4];
	uint8_t slotcfg1011[4];
	uint8_t slotcfg1213[4];
	uint8_t slotcfg1415[4];
	uint8_t useflag01[4];
	uint8_t useflag23[4];
	uint8_t useflag45[4];
	uint8_t useflag67[4];
	uint8_t lastkey0[4];
	uint8_t lastkey4[4];
	uint8_t lastkey8[4];
	uint8_t lastkey12[4];
	uint8_t userextra[4];
}atsha204a_config;

typedef struct atsha204a_otp
{
	uint8_t otp[16][4];
}atsha204a_otp;

typedef struct atsha204a_slot
{
	uint8_t slot[16][32];
}atsha204a_slot;

//写配置
uint8_t WriteConfig(atsha204a_config* cfg);

//读部分配置(用于校验)
uint8_t ReadSomeConfig(atsha204a_config* cfg);

//写slot
uint8_t WriteSlot(atsha204a_slot* slot);

//写otp
uint8_t WriteOtp(atsha204a_otp* otp);

//锁配置
uint8_t LockConfig(void);

//锁数据
uint8_t LockData(void);

//全部写入
uint8_t AllConfig(atsha204a_config* cfg,atsha204a_slot* slot,atsha204a_otp* otp);
#endif
