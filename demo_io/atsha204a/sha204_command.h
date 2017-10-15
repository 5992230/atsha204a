#ifndef _SHA204_COMMAND_H_
#define _SHA204_COMMAND_H_
#include <stdint.h>
#include <string.h>
#include "sha204_comm_marshaling.h"
#include "sha204_lib_return_codes.h"
#include "sha204_helper.h"

//��ȡSN(�кܶ���㶼�漰��SN��,�������SN�����һ��ʼ��ȡ����)
uint8_t sha204_readsn(uint8_t *txbuf,uint8_t* rxbuf,uint8_t* snbuf);

//nonce��������Ҫ����
typedef struct NoncePara
{
	uint8_t mode;		//����tempkey�����ŵ��Ǻ��������
	uint16_t zero;	//����Ϊ0
	uint8_t numin[32];	//host���ɵ����������
	uint8_t randout[32];	//���ص�randout
}NoncePara;
uint8_t sha204_nonce(uint8_t *txbuf,uint8_t* rxbuf,NoncePara *p);

//checkmac��������Ҫ�Ĳ���
typedef struct CheckMacPara
{
	uint8_t mode;			//����sha256������ѡ��
	uint16_t slotid;		//Ҫ�õ���slotid
	uint8_t clientchal[32];	//����client����սЭ��(32�ֽ�)
	uint8_t clientresp[32];	//host��ߵļ�����(Ҳ��������)
	uint8_t otherdata[13];		//�������ڼ���sha256�Ĳ���
}CheckMacPara;
uint8_t sha204_checkmac(uint8_t *txbuf,uint8_t* rxbuf,CheckMacPara *p);

//MAC��������Ҫ�Ĳ���
typedef struct MacPara
{
	uint8_t mode;		//ѡ��ʹ��challenge ����TempKey
	uint16_t slotid;	//ʹ���ĸ�slot������У��
	uint8_t challenge[32];	//��challenge
	uint8_t  digest[32];	//���ص�ժҪ
}MacPara;
uint8_t sha204_mac(uint8_t *txbuf,uint8_t* rxbuf,MacPara *p);

//GenDig��������Ҫ�Ĳ���
typedef struct GenDigPara
{
	uint8_t zone;		//ѡ���ĸ����������µ�TempKey(config,slot,otp)
	uint8_t slotid;	//
	uint8_t otherdata[4];	//��������,�����Ӧ��slot.checkonlyλ��һ��������Ҫ4���ֽڵ����ݣ�������Ҫ
}GenDigPara;
uint8_t sha204_gendig(uint8_t *txbuf,uint8_t* rxbuf,GenDigPara *p);

#endif
