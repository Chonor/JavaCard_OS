package purse;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;

public class Randgenerator {
	private byte len;		//随机数的长度
	private byte[] value;	//随机数的值
	private RandomData randomdata;	//随机数生成
	
	/**
	 * 构造函数
	 */
	public Randgenerator(){
		len = (byte)4;
		value = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
		randomdata = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
	}
	
	/**
	 * 生成随机数
	 */
	public final void GenerateSecureRnd(){
		/* //调试用
		value[0] = (byte)0xB1;   
		value[1]= (byte)0xEE;
		value[2] = (byte)0x18;
		value[3] = (byte)0x0C; 
		// */
		randomdata.generateData(value, (short)0, (short)len);
	}
	/**
	 * 获取随机数
	 * @param bf 数据的值
	 * @param bOff 数据的偏移量
	 * @return 随机数长度
	 */
	public final byte getRndValue(byte[] bf, short bOff){
		Util.arrayCopyNonAtomic(value, (short)0, bf, bOff, (short)len);
		return len;
	}
	/**
	 * 获取随机数的长度
	 * @return 随机数的长度
	 */
	public final byte lenofRnd(){
		return len;
	}
}
