#include "sha204_command.h"

//获取SN
uint8_t sha204_readsn(uint8_t *txbuf,uint8_t* rxbuf,uint8_t* snbuf)
{
	uint8_t state = 0;
	state = sha204m_execute(0x02,
													0x80,
													0x00,
													0,0,0,0,0,0,
													SHA204_CMD_SIZE_MIN,
													txbuf,
													READ_32_RSP_SIZE,rxbuf
													);
	if(SHA204_SUCCESS != state)
	{
		return state;
	}
	memcpy(snbuf , &rxbuf[SHA204_BUFFER_POS_DATA], 4);
	memcpy(&snbuf[4] , &rxbuf[SHA204_BUFFER_POS_DATA + 8], 5);
	return SHA204_SUCCESS;
}

//发送nonce命令,获取的随机数保存在p->randout里面
uint8_t sha204_nonce(uint8_t *txbuf,uint8_t* rxbuf,NoncePara *p)
{
	uint8_t state = 0;
	uint8_t datalen = ((p->mode&0x02) ==0)?20:32;
	state = sha204m_execute(0x16,
									p->mode,
									p->zero,
									datalen,
									p->numin,
									0,0,0,0,
									SHA204_CMD_SIZE_MAX,
									txbuf,
									NONCE_RSP_SIZE_LONG,
									rxbuf
									);
	if(state != SHA204_SUCCESS)
	{
		return state;
	}
	memcpy(p->randout,&rxbuf[SHA204_BUFFER_POS_DATA],32);
	
	return SHA204_SUCCESS;
}

//发送checkmac命令
uint8_t sha204_checkmac(uint8_t *txbuf,uint8_t* rxbuf,CheckMacPara *p)
{
	uint8_t state = 0;
	state = sha204m_execute(SHA204_CHECKMAC,
									p->mode,
									p->slotid,
									32,
									p->clientchal,
									32,
									p->clientresp,
									13,
									p->otherdata,
									SHA204_CMD_SIZE_MAX,
									txbuf,
									READ_32_RSP_SIZE,
									rxbuf
									);
	if(state != SHA204_SUCCESS)
	{
		return state;
	}
	return SHA204_SUCCESS;
}

uint8_t sha204_gendig(uint8_t *txbuf,uint8_t* rxbuf,GenDigPara *p)
{
	uint8_t state = 0;
	state = sha204m_execute(SHA204_GENDIG,
													p->zone,
													p->slotid,
													p->otherdata?4:0,
													p->otherdata,													
													0,0,0,0,
													SHA204_CMD_SIZE_MAX,
													txbuf,
													READ_32_RSP_SIZE,
													rxbuf
													);
	if(state != SHA204_SUCCESS)
	{
		return state;
	}
	
	return SHA204_SUCCESS;
}

//发送mac命令,获取的摘要保存在p->digest里面
uint8_t sha204_mac(uint8_t *txbuf,uint8_t* rxbuf,MacPara *p)
{
	uint8_t state = 0;
	state = sha204m_execute(SHA204_MAC,
													p->mode,
													p->slotid,
													p->mode&0x01?0:32,
													p->challenge,
													0,0,0,0,
													SHA204_CMD_SIZE_MAX,
													txbuf,
													READ_32_RSP_SIZE,
													rxbuf
													);
	if(state != SHA204_SUCCESS)
	{
		return state;
	}
	memcpy(p->digest,&rxbuf[SHA204_BUFFER_POS_DATA],32);
	
	return SHA204_SUCCESS;
}
/*
//加密读取slot区数据
uint8_t sha204_encryptread(uint8_t *txbuf,uint8_t* rxbuf,uint8_t slot)
{
	uint8_t state = 0;
	static NoncePara nonce;
	static GenDigPara gendig;
	static struct sha204h_gen_dig_in_out host_gendig;
	static struct sha204h_temp_key host_tempkey;
	
	nonce.mode = 0x03;
	memset(nonce.numin,0xf0,32);
	nonce.zero = 0x0000;
	
	state = sha204_nonce(txbuf,rxbuf,&nonce);
	if(state != SHA204_SUCCESS)
	{
		return state;
	}
	
	host_gendig.key_id = slot;
	host_gendig.stored_value = nonce.numin;
	host_gendig.zone = 0x02;
	host_gendig.temp_key = &host_tempkey;
	
	state =  sha204h_gen_dig(&host_gendig);
	if(state != SHA204_SUCCESS)
	{
		return state;
	}
	gendig.zone = 0x02;
	gendig.slotid = slot;
	
	
	return SHA204_SUCCESS;
}
*/
