package purse;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public class PenCipher {
	private Cipher desEngine;
	private Key deskey;
	/**
	 * ���캯��
	 */
	public PenCipher(){
		desEngine = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);//��ü���ʵ��
		deskey = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);//����DES��Կʵ��
	}
	/**
	 * DES����
	 * @param key ��Կ
	 * @param kOff ��Կ��ƫ����
	 * @param data ��Ҫ���мӽ��ܵ�����
	 * @param dOff ����ƫ����
	 * @param dLen ���ݵĳ���
	 * @param res	�ӽ��ܺ�����
	 * @param rOff �������ƫ����
	 * @param mode ���ܻ��������ģʽ
	 */
	public final void des(byte[] key, short kOff, byte[] data, short dOff, short dLen, byte[] res, short rOff, byte mode){
		((DESKey)deskey).setKey(key, kOff);	//����DES��Կ
		desEngine.init(deskey, mode);//��ʼ����Կ������ģʽ
		desEngine.doFinal(data, dOff, dLen, res, rOff);//����
	}
	/**
	 * ���ɹ�����Կ
	 * @param key ��Կ
	 * @param data ����ܵ�����
	 * @param dOff ����ƫ����
	 * @param dLen ���ݳ���
	 * @param res ���ܺ�����
	 * @param rOff ���ܺ�����ƫ����
	 */
	public final void gen_SESPK(byte[] key, byte[]data, short dOff, short dLen, byte[] res, short rOff){
		byte[] tmp1 = JCSystem.makeTransientByteArray(dLen, JCSystem.CLEAR_ON_DESELECT);
		byte[] tmp2 = JCSystem.makeTransientByteArray(dLen, JCSystem.CLEAR_ON_DESELECT);
		des(key,(short)0,data,dOff,dLen,tmp1,rOff,Cipher.MODE_ENCRYPT);
		des(key,(short)8,tmp1,dOff,dLen,tmp2,rOff,Cipher.MODE_DECRYPT);
		des(key,(short)0,tmp2,dOff,dLen,res,rOff,Cipher.MODE_ENCRYPT);
	}
	/**
	 * ���ֽڵ����������������ݿ�������������������ݿ�d1��
	 * @param data1 ����1
	 * @param data2 ����2
	 * @param d2off ����2��ƫ����
	 */
	public final void xorblock8(byte[] data1, byte[] data2, short d2off){
		for(short i = 0; i < 8; i++)
			data1[i]^=data2[i+d2off];
	}
	/**
	 * MAC��TAC������
	 * @param key ��Կ
	 * @param data ����ܵ�����
	 * @param len ���ݳ���
	 * @param res �õ���MAC��TAC��
	 */
	public final void gmac4(byte[] key, byte[] data, short len, byte[]  res){
		byte[] tmp1 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		byte[] tmp2 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		Util.arrayFillNonAtomic(tmp1, (short)0, (short)8, (byte)0x00);//��ֵΪ0x0000 0000 0000 0000
		data[len++] = (byte)0x80;
		if(len%8!=0){//�����8�ı���
			Util.arrayFillNonAtomic(data, len, (short)(8-len%8), (byte)0x00);
			len+=(8-len%8);
		}
		for(short off = 0; off < len; off+=8){//���des����
			xorblock8(tmp1, data, off);
			des(key, (short)0, tmp1, (short)0, (short)8, tmp2, (short)0, Cipher.MODE_ENCRYPT);
			Util.arrayCopyNonAtomic(tmp2, (short)0, tmp1, (short)0, (short)8);
		}
		Util.arrayCopyNonAtomic(tmp2, (short)0, res, (short)0, (short)4);//MAC��TAC����Ϊ4byte
	}

}
