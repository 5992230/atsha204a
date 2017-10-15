#include "sha204_test.h"
#include "usart1.h"
#include "sha204_timer_utilities.h"
//存放key的slotid
uint8_t secret_key_id = 0;
//秘钥key
uint8_t secret_key[32] = 
{
	0x11,0x77,0x16,0x20,0x82,0xde,0xad,0x8c,
	0xe9,0x14,0x21,0x87,0xf5,0x94,0x6e,0xcd,
	0x0c,0x75,0x5c,0xd5,0x57,0x3c,0x3a,0x40,
	0x9a,0xdf,0xdb,0x83,0x55,0x1b,0xd0,0xd1
};
//挑战协议的32个字节
uint8_t challenge_key[32] = 
{
	0x13,0x68,0x72,0x20,0x82,0xde,0xad,0x8c,
	0xe9,0x14,0x21,0x87,0xf5,0x94,0x24,0xcd,
	0xdd,0xaa,0x5c,0xd5,0x44,0x3c,0x08,0x40,
	0x35,0xdf,0xdb,0x13,0x67,0x1b,0xd3,0x2f
};

static uint8_t wakeup_response_buffer[4] = {0};
static uint8_t tx_buffer[SHA204_CMD_SIZE_MAX] = {0};
static uint8_t rx_buffer[SHA204_RSP_SIZE_MAX] = {0};
static uint8_t sn_number[9] = {0};

//测试nonce命令
uint8_t TestNonce(void)
{
	uint8_t state = 0;
	struct sha204h_nonce_in_out host_nonce;
	static NoncePara nonce;
	struct sha204h_temp_key temp_key;
	nonce.mode = 0x01;		//If one, then combine the new random number with NumIn, store in TempKey. Generate random number using
												//existing EEPROM seed, do not update EEPROM seed.
	nonce.zero = 0x0000;
	memcpy(&nonce.numin,&challenge_key,32);	//随机数
	
	//自己MCU也要计算一遍TempKey中的Value
	host_nonce.temp_key = &temp_key;
	host_nonce.mode = nonce.mode;
	host_nonce.num_in = nonce.numin;
	host_nonce.rand_out = nonce.randout;
	
	//发送nonce命令
	state = sha204_nonce(tx_buffer,rx_buffer,&nonce);
	if(state != SHA204_SUCCESS)
	{
		printf("sha204_nonce fail,code:0x%02X!\n",state);
		return state;
	}
	
	//自己MCU计算TempKey
	state = sha204h_nonce(&host_nonce);
	if(state != SHA204_SUCCESS)
	{
		printf("sha204h_nonce fail,code:0x%02X!\n",state);
		return state;
	}
	
	//至此，产生的随机数就存在了TempKey里面
	
	return SHA204_SUCCESS;
}

//测试CheckMac命令
uint8_t TestCheckMac(void)
{
	uint8_t state = 0;
	uint8_t i = 0;
	NoncePara nonce;
	static CheckMacPara  chmac;
	struct sha204h_check_mac_in_out host_mac;
	struct sha204h_temp_key temp_key;
	
	//首先唤醒设备
	state = sha204c_wakeup(wakeup_response_buffer);
	if(I2C_SUCCESS != state)
	{
		printf("wakeup fail!\n");
		return state;
	}
	
	//然后读取SN
	state = sha204_readsn(tx_buffer,rx_buffer,sn_number);
	if(I2C_SUCCESS != state)
	{
		printf("read sn fail!\n");
		return state;
	}
	for(i = 0;i<9;i++)
	{
		printf("SN[%d]:0x%02X\n",i,sn_number[i]);
	}
	//如果要用到TempKey做计算,则这里要发送nonce命令,为方便起见,这里不用TempKey
	
	//构建CheckMacPara结构体(根据手册上来设置)
	memset(&chmac,0,sizeof(CheckMacPara));
	//选择挑战协议中32字节来计算SHA;选择slot中的KEY来计算SHA;其余为0
	chmac.mode = (0)|(0<<1);
	//slotid
	chmac.slotid = secret_key_id;
	//挑战秘钥
	memcpy(&chmac.clientchal,&challenge_key,32);
	//other的设置见手册46页
	chmac.otherdata[0] = 0x08;				//MAC 的 opcode
	chmac.otherdata[1] = chmac.mode;
	chmac.otherdata[2] = 0;
	chmac.otherdata[3] = 1;						//slotid
	memset(&chmac.otherdata[4],0,3);	//OTP(设为0)
	memcpy(&chmac.otherdata[7],&sn_number[4],4);//SN[4,7]
	memcpy(&chmac.otherdata[11],&sn_number[2],2);//SN[2,3]
	
	//我们还要自己算一次SHA,放在chmac.clientresp里面,然后再发给client作对比
	/*
	memcpy(&temp_key.value,&challenge_key,32);
	temp_key.check_flag = 0;
	temp_key.source_flag = 0;
	temp_key.valid = 1;
	*/
	host_mac.mode = chmac.mode;
	host_mac.password = secret_key;
	host_mac.other_data = chmac.otherdata;
	host_mac.otp = 0;		//没用上OTP区
	host_mac.temp_key = 0;//不用tempkey
	host_mac.client_resp = chmac.clientresp;
	host_mac.client_chl = challenge_key;
	host_mac.target_key = secret_key;	//比较成功后会把目标slot区域内容拷贝至tempkey
	state = sha204h_check_mac(&host_mac);
	if(state != SHA204_SUCCESS)
	{
		printf("sha204h_check_mac fail,code:0x%02X!\n",state);
		return state;
	}
	
	//运行了sha204h_check_mac函数后,ClientResp保存在了chmac.clientresp里面

	state = sha204_checkmac(tx_buffer,rx_buffer,&chmac);
	
	if(state != SHA204_SUCCESS)
	{
		printf("sha204m_execute fail!\n");
		return state;
	}
	printf("count:%d\n",rx_buffer[0]);
	if(rx_buffer[1] == 0)
	{
		printf("Check MAC match!\n");
	}
	else
	{
		printf("Check MAC dismatch!\n");
	}
	return I2C_SUCCESS;
}

//测试Mac命令
uint8_t	TestMac(void)
{
	//首先依然要获取SN(参与计算SHA-256)
	//首先要发送nonce命令,更新tempkey中的值
	//然后自己mcu也计算tempkey中的值
	//然后根据SN和Tempkey中的值计算SHA-256得到摘要1
	//然后发送MAC命令获取摘要2
	//比较摘要1和摘要2
	
	uint8_t state = 0;
	uint8_t i = 0;
	
	static NoncePara nonce;		//需要发送的nonce
	static MacPara	 mac;			//需要发送的mac
	struct sha204h_mac_in_out host_mac;	//自己计算的摘要
	struct sha204h_nonce_in_out host_nonce;	//自己计算的nonce
	struct sha204h_temp_key temp_key;//tempkey
	
	static uint8_t digest[32] = {0};	//芯片返回的摘要
	
	//首先唤醒设备
	state = sha204c_wakeup(wakeup_response_buffer);
	if(I2C_SUCCESS != state)
	{
		printf("wakeup fail!\n");
		return state;
	}
	
	//然后读取SN
	state = sha204_readsn(tx_buffer,rx_buffer,sn_number);
	if(I2C_SUCCESS != state)
	{
		printf("read sn fail!\n");
		return state;
	}
	for(i = 0;i<9;i++)
	{
		printf("SN[%d]:0x%02X\n",i,sn_number[i]);
	}
	
	//发送nonce命令更新芯片中tempkey的值
	nonce.mode = 0x01;		//If one, then combine the new random number with NumIn, store in TempKey. Generate random number using
												//existing EEPROM seed, do not update EEPROM seed.
	nonce.zero = 0x0000;
	memcpy(&nonce.numin,&challenge_key,32);	//把challenge_key当成随机数,也可以自己生成
	state = sha204_nonce(tx_buffer,rx_buffer,&nonce);
	if(state != SHA204_SUCCESS)
	{
		printf("sha204_nonce fail,code:0x%02X!\n",state);
		return state;
	}
	
	//自己MCU也要计算一遍TempKey中的Value
	host_nonce.temp_key = &temp_key;
	host_nonce.mode = nonce.mode;
	host_nonce.num_in = nonce.numin;
	host_nonce.rand_out = nonce.randout;//这里的randout是执行nonce命令后传回来的随机数
	state = sha204h_nonce(&host_nonce);
	if(state != SHA204_SUCCESS)
	{
		printf("sha204h_nonce fail,code:0x%02X!\n",state);
		return state;
	}
	
	//自己的mcu计算摘要
	host_mac.mode = MAC_MODE_BLOCK2_TEMPKEY|MAC_MODE_INCLUDE_SN;
	host_mac.key_id = secret_key_id;
	host_mac.temp_key = &temp_key;
	host_mac.sn = sn_number;
	host_mac.response = digest;
	host_mac.key = secret_key;
	state = sha204h_mac(&host_mac);
	if(state != SHA204_SUCCESS)
	{
		printf("sha204h_mac fail,code:0x%02X!\n",state);
		return state;
	}
	
	//发送给芯片计算摘要
	mac.mode = host_mac.mode;
	mac.slotid = host_mac.key_id;
	state = sha204_mac(tx_buffer,rx_buffer,&mac);
	if(state != SHA204_SUCCESS)
	{
		printf("sha204_mac fail,code:0x%02X!\n",state);
		return state;
	}
	
	if( memcmp(digest,mac.digest,32) == 0)
	{
		printf("mac success!\n");
	}
	else
	{
		printf("mac faile!\n");
	}
	return state;
}

//测试读命令
uint8_t TestReadConfig(void)
{
	uint8_t state = SHA204_SUCCESS;
	uint8_t words = 0;
	uint8_t index = 0;
	
	state = sha204c_wakeup(wakeup_response_buffer);
	if(I2C_SUCCESS != state)
	{
		printf("wakeup fail!\n");
		return state;
	}
	state = sha204m_execute(SHA204_READ,
													0x80,			//32字节读取
													words,		//读哪一块(配置区一共0x00-0x15,每一块4字节)
													0,0,0,0,0,0,
													SHA204_CMD_SIZE_MIN,
													tx_buffer,
													READ_32_RSP_SIZE,
													rx_buffer
													);
	if(SHA204_SUCCESS != state)
	{
		printf("Read %d Fail!\n",words);
		return state;
	}
	
	index = SHA204_BUFFER_POS_DATA;
	
	printf("Serial Number[0:3]:0x%02X,0x%02X,0x%02X,0x%02X\n",
	rx_buffer[SHA204_BUFFER_POS_DATA],
	rx_buffer[SHA204_BUFFER_POS_DATA+1],
	rx_buffer[SHA204_BUFFER_POS_DATA+2],
	rx_buffer[SHA204_BUFFER_POS_DATA+3]);
	
	printf("Revision Number:0x%02X,0x%02X,0x%02X,0x%02X\n",
	rx_buffer[SHA204_BUFFER_POS_DATA+4],
	rx_buffer[SHA204_BUFFER_POS_DATA+5],
	rx_buffer[SHA204_BUFFER_POS_DATA+6],
	rx_buffer[SHA204_BUFFER_POS_DATA+7]);
	
	printf("Serial Number[4:7]:0x%02X,0x%02X,0x%02X,0x%02X\n",
	rx_buffer[SHA204_BUFFER_POS_DATA+8],
	rx_buffer[SHA204_BUFFER_POS_DATA+9],
	rx_buffer[SHA204_BUFFER_POS_DATA+10],
	rx_buffer[SHA204_BUFFER_POS_DATA+11]);
	
	printf("SN[8]:0x%02X | Reserved:%d | I2C Enable:%d | Reserved:%d\n",
	rx_buffer[SHA204_BUFFER_POS_DATA + 12],
	rx_buffer[SHA204_BUFFER_POS_DATA+13],
	rx_buffer[SHA204_BUFFER_POS_DATA+14],
	rx_buffer[SHA204_BUFFER_POS_DATA+15]);
	
	printf("I2C Address:0x%02X | CheckMacConfig:0x%02X | OTP Mode:0x%02X | Selector Mode:0x%02X\n",
	rx_buffer[SHA204_BUFFER_POS_DATA+16],
	rx_buffer[SHA204_BUFFER_POS_DATA+17],
	rx_buffer[SHA204_BUFFER_POS_DATA+18],
	rx_buffer[SHA204_BUFFER_POS_DATA+19]);
	
	printf("Slot Configuration 0:0x%02X 0x%02X,Slot Configuration 1:0x%02X 0x%02X\n",
	rx_buffer[SHA204_BUFFER_POS_DATA+20],
	rx_buffer[SHA204_BUFFER_POS_DATA+21],
	rx_buffer[SHA204_BUFFER_POS_DATA+22],
	rx_buffer[SHA204_BUFFER_POS_DATA+23]);
	
	printf("Slot Configuration 2:0x%02X 0x%02X,Slot Configuration 3:0x%02X 0x%02X\n",
	rx_buffer[SHA204_BUFFER_POS_DATA+24],
	rx_buffer[SHA204_BUFFER_POS_DATA+25],
	rx_buffer[SHA204_BUFFER_POS_DATA+26],
	rx_buffer[SHA204_BUFFER_POS_DATA+27]);
	
	printf("Slot Configuration 4:0x%02X 0x%02X,Slot Configuration 5:0x%02X 0x%02X\n",
	rx_buffer[SHA204_BUFFER_POS_DATA+28],
	rx_buffer[SHA204_BUFFER_POS_DATA+29],
	rx_buffer[SHA204_BUFFER_POS_DATA+30],
	rx_buffer[SHA204_BUFFER_POS_DATA+31]);
	

	words=0x08;
	
	state = sha204m_execute(SHA204_READ,
													0x80,			//32字节读取
													words,		//读哪一块(配置区一共0x00-0x15,每一块4字节)
													0,0,0,0,0,0,
													SHA204_CMD_SIZE_MIN,
													tx_buffer,
													READ_32_RSP_SIZE,
													rx_buffer
													);
	if(SHA204_SUCCESS != state)
	{
		printf("Read %d Fail!\n",words);
		return state;
	}
	printf("Slot Configuration 6:0x%02X 0x%02X,Slot Configuration 7:0x%02X 0x%02X\n",
	rx_buffer[SHA204_BUFFER_POS_DATA],
	rx_buffer[SHA204_BUFFER_POS_DATA+1],
	rx_buffer[SHA204_BUFFER_POS_DATA+2],
	rx_buffer[SHA204_BUFFER_POS_DATA+3]);
	
	printf("Slot Configuration 8:0x%02X 0x%02X,Slot Configuration 9:0x%02X 0x%02X\n",
	rx_buffer[SHA204_BUFFER_POS_DATA+4],
	rx_buffer[SHA204_BUFFER_POS_DATA+5],
	rx_buffer[SHA204_BUFFER_POS_DATA+6],
	rx_buffer[SHA204_BUFFER_POS_DATA+7]);
	
	printf("Slot Configuration 10:0x%02X 0x%02X,Slot Configuration 11:0x%02X 0x%02X\n",
	rx_buffer[SHA204_BUFFER_POS_DATA+8],
	rx_buffer[SHA204_BUFFER_POS_DATA+9],
	rx_buffer[SHA204_BUFFER_POS_DATA+10],
	rx_buffer[SHA204_BUFFER_POS_DATA+11]);
	
	printf("Slot Configuration 12:0x%02X 0x%02X,Slot Configuration 13:0x%02X 0x%02X\n",
	rx_buffer[SHA204_BUFFER_POS_DATA+12],
	rx_buffer[SHA204_BUFFER_POS_DATA+13],
	rx_buffer[SHA204_BUFFER_POS_DATA+14],
	rx_buffer[SHA204_BUFFER_POS_DATA+15]);
	
	printf("Slot Configuration 14:0x%02X 0x%02X,Slot Configuration 15:0x%02X 0x%02X\n",
	rx_buffer[SHA204_BUFFER_POS_DATA+16],
	rx_buffer[SHA204_BUFFER_POS_DATA+17],
	rx_buffer[SHA204_BUFFER_POS_DATA+18],
	rx_buffer[SHA204_BUFFER_POS_DATA+19]);
	
	//大于0x10的必须用4字节读
	words=0x15;
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
		printf("Read %d Fail!\n",words);
		return state;
	}
	printf("User Extra:0x%02X | Selector:0x%02X | Lock Data:0x%02X | Lock Config:0x%02X\n",
	rx_buffer[SHA204_BUFFER_POS_DATA],
	rx_buffer[SHA204_BUFFER_POS_DATA+1],
	rx_buffer[SHA204_BUFFER_POS_DATA+2],
	rx_buffer[SHA204_BUFFER_POS_DATA+3]);
	
}
