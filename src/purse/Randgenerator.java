package purse;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;

public class Randgenerator {
	private byte len;		//������ĳ���
	private byte[] value;	//�������ֵ
	private RandomData randomdata;	//���������
	
	/**
	 * ���캯��
	 */
	public Randgenerator(){
		len = (byte)4;
		value = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
		randomdata = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
	}
	
	/**
	 * ���������
	 */
	public final void GenerateSecureRnd(){
		/* //������
		value[0] = (byte)0xB1;   
		value[1]= (byte)0xEE;
		value[2] = (byte)0x18;
		value[3] = (byte)0x0C; 
		// */
		randomdata.generateData(value, (short)0, (short)len);
	}
	/**
	 * ��ȡ�����
	 * @param bf ���ݵ�ֵ
	 * @param bOff ���ݵ�ƫ����
	 * @return ���������
	 */
	public final byte getRndValue(byte[] bf, short bOff){
		Util.arrayCopyNonAtomic(value, (short)0, bf, bOff, (short)len);
		return len;
	}
	/**
	 * ��ȡ������ĳ���
	 * @return ������ĳ���
	 */
	public final byte lenofRnd(){
		return len;
	}
}
