#ifndef _SHA204_COMMAND_H_
#define _SHA204_COMMAND_H_
#include <stdint.h>
#include <string.h>
#include "sha204_comm_marshaling.h"
#include "sha204_lib_return_codes.h"
#include "sha204_helper.h"

//获取SN(有很多计算都涉及到SN号,所以这个SN号最好一开始就取回来)
uint8_t sha204_readsn(uint8_t *txbuf,uint8_t* rxbuf,uint8_t* snbuf);

//nonce命令所需要参数
typedef struct NoncePara
{
	uint8_t mode;		//控制tempkey里面存放的是何种随机数
	uint16_t zero;	//必须为0
	uint8_t numin[32];	//host生成的随机数输入
	uint8_t randout[32];	//返回的randout
}NoncePara;
uint8_t sha204_nonce(uint8_t *txbuf,uint8_t* rxbuf,NoncePara *p);

//checkmac命令所需要的参数
typedef struct CheckMacPara
{
	uint8_t mode;			//计算sha256参数的选择
	uint16_t slotid;		//要用到的slotid
	uint8_t clientchal[32];	//发给client的挑战协议(32字节)
	uint8_t clientresp[32];	//host这边的计算结果(也就是密码)
	uint8_t otherdata[13];		//其他用于计算sha256的参数
}CheckMacPara;
uint8_t sha204_checkmac(uint8_t *txbuf,uint8_t* rxbuf,CheckMacPara *p);

//MAC命令所需要的参数
typedef struct MacPara
{
	uint8_t mode;		//选择使用challenge 还是TempKey
	uint16_t slotid;	//使用哪个slot来进行校验
	uint8_t challenge[32];	//用challenge
	uint8_t  digest[32];	//返回的摘要
}MacPara;
uint8_t sha204_mac(uint8_t *txbuf,uint8_t* rxbuf,MacPara *p);

//GenDig命令所需要的参数
typedef struct GenDigPara
{
	uint8_t zone;		//选择哪个区来计算新的TempKey(config,slot,otp)
	uint8_t slotid;	//
	uint8_t otherdata[4];	//其他数据,如果对应的slot.checkonly位置一，这里需要4个字节的数据，否则不需要
}GenDigPara;
uint8_t sha204_gendig(uint8_t *txbuf,uint8_t* rxbuf,GenDigPara *p);

#endif
