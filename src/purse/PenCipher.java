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
	 * 构造函数
	 */
	public PenCipher(){
		desEngine = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);//获得加密实例
		deskey = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);//生成DES密钥实例
	}
	/**
	 * DES运算
	 * @param key 密钥
	 * @param kOff 密钥的偏移量
	 * @param data 需要进行加解密的数据
	 * @param dOff 数据偏移量
	 * @param dLen 数据的长度
	 * @param res	加解密后数据
	 * @param rOff 结果数据偏移量
	 * @param mode 加密或解密运算模式
	 */
	public final void des(byte[] key, short kOff, byte[] data, short dOff, short dLen, byte[] res, short rOff, byte mode){
		((DESKey)deskey).setKey(key, kOff);	//设置DES密钥
		desEngine.init(deskey, mode);//初始化密钥及加密模式
		desEngine.doFinal(data, dOff, dLen, res, rOff);//加密
	}
	/**
	 * 生成过程密钥
	 * @param key 密钥
	 * @param data 需加密的数据
	 * @param dOff 数据偏移量
	 * @param dLen 数据长度
	 * @param res 加密后数据
	 * @param rOff 加密后数据偏移量
	 */
	public final void gen_SESPK(byte[] key, byte[]data, short dOff, short dLen, byte[] res, short rOff){
		byte[] tmp1 = JCSystem.makeTransientByteArray(dLen, JCSystem.CLEAR_ON_DESELECT);
		byte[] tmp2 = JCSystem.makeTransientByteArray(dLen, JCSystem.CLEAR_ON_DESELECT);
		des(key,(short)0,data,dOff,dLen,tmp1,rOff,Cipher.MODE_ENCRYPT);
		des(key,(short)8,tmp1,dOff,dLen,tmp2,rOff,Cipher.MODE_DECRYPT);
		des(key,(short)0,tmp2,dOff,dLen,res,rOff,Cipher.MODE_ENCRYPT);
	}
	/**
	 * 个字节的异或操作，两个数据块进行异或，异或结果存入数据块d1中
	 * @param data1 数据1
	 * @param data2 数据2
	 * @param d2off 数据2的偏移量
	 */
	public final void xorblock8(byte[] data1, byte[] data2, short d2off){
		for(short i = 0; i < 8; i++)
			data1[i]^=data2[i+d2off];
	}
	/**
	 * MAC、TAC的生成
	 * @param key 密钥
	 * @param data 需加密的数据
	 * @param len 数据长度
	 * @param res 得到的MAC和TAC码
	 */
	public final void gmac4(byte[] key, byte[] data, short len, byte[]  res){
		byte[] tmp1 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		byte[] tmp2 = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
		Util.arrayFillNonAtomic(tmp1, (short)0, (short)8, (byte)0x00);//初值为0x0000 0000 0000 0000
		data[len++] = (byte)0x80;
		if(len%8!=0){//填充至8的倍数
			Util.arrayFillNonAtomic(data, len, (short)(8-len%8), (byte)0x00);
			len+=(8-len%8);
		}
		for(short off = 0; off < len; off+=8){//异或、des加密
			xorblock8(tmp1, data, off);
			des(key, (short)0, tmp1, (short)0, (short)8, tmp2, (short)0, Cipher.MODE_ENCRYPT);
			Util.arrayCopyNonAtomic(tmp2, (short)0, tmp1, (short)0, (short)8);
		}
		Util.arrayCopyNonAtomic(tmp2, (short)0, res, (short)0, (short)4);//MAC、TAC长度为4byte
	}

}
