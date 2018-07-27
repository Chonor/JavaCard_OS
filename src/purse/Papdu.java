package purse;

import javacard.framework.JCSystem;

public class Papdu {
	public byte cla, ins, p1, p2;
	public short lc, le;
	public byte[] pdata;
	
	/**
	 * 构造函数
	 */
	public Papdu(){
		pdata = JCSystem.makeTransientByteArray((short)255, JCSystem.CLEAR_ON_DESELECT);
	}
	
	/**
	 * 判断APDU命令是否包含数据
	 * @return 是否包含数据
	 */
	public boolean APDUContainData(){
		switch(ins){
		case condef.INS_CREATE_FILE:		
		case condef.INS_WRITE_KEY:
		case condef.INS_WRITE_BIN:
		case condef.INS_INIT_TRANS:
		case condef.INS_LOAD:
		case condef.INS_PURCHASE:
		case condef.INS_GET_SESPK:
		case condef.INS_GET_MAC:
			return true;
		}
		return false;
	}
}