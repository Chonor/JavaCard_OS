package purse;


import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class purse extends Applet {
    private Papdu papdu;                
    //文件系统
    private KeyFile keyfile;		//密钥文件
    private BinaryFile cardfile;	//应用基本文件
    private BinaryFile personfile;	//持卡人基本文件
    private EPFile epfile;			//电子钱包文件
    
    /**
     * 构造函数 注册
     * @param bArray
     * @param bOffset
     * @param bLength
     */
    public purse(byte[] bArray, short bOffset, byte bLength){
        papdu = new Papdu();
        byte aidLen = bArray[bOffset];
        if(aidLen == (byte)0x00)
            register();
        else
            register(bArray, (short)(bOffset + 1), aidLen);
    }
	/**
	 * 安装
	 * @param bArray
	 * @param bOffset
	 * @param bLength
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new purse(bArray, bOffset, bLength);
	}
	/**
     * 分析命令预处理
     * @param apdu 命令
     */
	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}
		//取APDU缓冲区数组引用并将之赋给新建数组
        byte[] buf= apdu.getBuffer();
        //取APDU缓冲区中数据放到变量papdu
        short lc = apdu.setIncomingAndReceive(); //接收数据
        papdu.cla = buf[ISO7816.OFFSET_CLA];
        papdu.ins = buf[ISO7816.OFFSET_INS];
        papdu.p1 = buf[ISO7816.OFFSET_P1];
        papdu.p2 = buf[ISO7816.OFFSET_P2];
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, papdu.pdata, (short)0, lc);
        //判断命令APDU是否包含数据段
        boolean hasData = (papdu.APDUContainData());
        if(hasData){//有数据获取数据长度 le赋值
            papdu.lc = buf[ISO7816.OFFSET_LC];
            papdu.le = buf[ISO7816.OFFSET_CDATA+lc];
        }
        else{//无数据不需要lc 缓冲区此时为le
            papdu.le = buf[ISO7816.OFFSET_LC];
            papdu.lc = 0;
        }
        boolean flag = handleEvent();//是否成功处理了命令
        if(flag && papdu.le!=0){//需要返回数据
            Util.arrayCopyNonAtomic(papdu.pdata, (short)0, buf, (short)0, (short)papdu.le);//设置缓冲区
            apdu.setOutgoingAndSend((short)0, (short)papdu.le);
        }
	}
	/**
     * 分命令执行
     * @return 是否成功执行命令
     */
    private boolean handleEvent(){
        switch(papdu.ins){
            case condef.INS_CREATE_FILE:       return create_file();
            case condef.INS_WRITE_KEY:		   return write_key();
            case condef.INS_WRITE_BIN:		   return write_bin();
            case condef.INS_INIT_TRANS:
                if(papdu.p1 == (byte)0x00)     return init_load();
                if(papdu.p1 == (byte)0x01)     return init_purchase();
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2); //不存在的操作
            case condef.INS_LOAD:              return load();
            case condef.INS_PURCHASE:          return purchase();
            case condef.INS_GET_BALANCE:       return get_balance();
            case condef.INS_READ_BIN:		   return read_bin();
            case condef.INS_GET_SESPK:		   return get_sespk();
            case condef.INS_GET_MAC:		   return get_mac();
        }
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        return false;
    }
    /**
     * 创建文件
     * @return 是否成功创建
     */
    private boolean create_file() {
        switch(papdu.pdata[0]){
            case condef.KEY_FILE:       return KEY_file(); //创建密钥文件
            case condef.CARD_FILE:      return CARD_file(); //创建应用基本文件
            case condef.PERSON_FILE:    return PERSON_file(); //创建持卡人基本文件
            case condef.EP_FILE:        return EP_file(); //创建电子钱包文件
            default:
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        return true;
    }
    /**
     * 创建密钥文件
     * @return 是否成功创建
     */
    private boolean KEY_file() {
        if(papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);//CLA错误
        if(papdu.p1 != (byte)0x00 || papdu.p2 != (byte)0x00)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);//文件类型错误
        if(papdu.lc != (byte)0x07)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);//错误的长度
        if(keyfile != null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);//文件已存在
        keyfile = new KeyFile();
        return true;
    }
    /**
     * 创建应用基本文件
     * @return 是否成功创建
     */
    private boolean CARD_file() {
        if(papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if(papdu.p1 != (byte)0x00 || papdu.p2 != (byte)0x16)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        if(papdu.lc != (byte)0x07)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if(cardfile != null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        cardfile = new BinaryFile(papdu.pdata);
        return true;
    }
    /**
     * 持卡人基本文件
     * @return 是否成功创建
     */
    private boolean PERSON_file() {
        if(papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if(papdu.p1 != (byte)0x00 || papdu.p2 != (byte)0x17)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        if(papdu.lc != (byte)0x07)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if(personfile != null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        personfile = new BinaryFile(papdu.pdata);
        return true;
    }
    /**
     * 创建电子钱包文件
     * @return 是否成功创建
     */
    private boolean EP_file() {
        if(papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if(papdu.p1 != (byte)0x00 || papdu.p2 != (byte)0x18)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        if(papdu.lc != (byte)0x07)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if(epfile != null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        epfile = new EPFile(keyfile);
        return true;
    }
    /**
     * 增加或修改密钥
     * @return 是否成功执行
     */
    private boolean write_key(){
        if(papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);//CLA错误
        if(papdu.p1 != (byte)0x00 && papdu.p1 != (byte)0x01)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);//参数类型错误
        if(papdu.lc != (byte)0x15)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);//错误的长度
        if(keyfile == null)//密钥文件不存在
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        if(papdu.p1 == (byte)0x00 && keyfile.recNum == keyfile.size)//密钥已满
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        keyfile.addkey(papdu.p2, papdu.lc, papdu.pdata);
        return true;
    }
    /**
     * 写入二进制文件
     * @return 是否成功执行
     */
    private boolean write_bin(){
        if(papdu.cla != (byte)0x00)//CLA错误
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if(papdu.p1 == (byte)0x17){ //写入持卡人基本文件
            if(personfile == null) //文件不存在
            	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            else if(papdu.p2 + papdu.lc>personfile.get_size())//错误的长度
            	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            else 
            	personfile.write_bineary(papdu.p2, papdu.lc, papdu.pdata);
        }
        else if(papdu.p1 == (byte)0x16){//写入基本应用文件
            if(cardfile == null)//文件不存在
            	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            else if(papdu.p2 + papdu.lc>cardfile.get_size())//错误的长度
            	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        	else 
        		cardfile.write_bineary(papdu.p2, papdu.lc, papdu.pdata);
        }
        else
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        return true;
    }
    /**
     * 读取二进制文件
     * @return 是否成功执行
     */
    private boolean read_bin(){
        if(papdu.cla != (byte)0x00)//CLA错误
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if(papdu.p1 == (byte)0x17){//读取持卡人基本文件
        	if(personfile == null) //文件不存在
             	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        	else if(papdu.p2 + papdu.le>personfile.get_size())//错误的长度
            	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        	else
        		personfile.read_binary(papdu.p2, papdu.le, papdu.pdata);
        }
        else if(papdu.p1 == (byte)0x16) {//读取基本应用文件
        	if(cardfile == null)//文件不存在
            	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            else if(papdu.p2 + papdu.le>cardfile.get_size())//错误的长度
            	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            else
        	cardfile.read_binary(papdu.p2, papdu.le, papdu.pdata);
        }
        else
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        return true;
    }
    /**
     * 圈存初始化
     * @return 是否成功初始化
     */
    private boolean init_load() {
        short num,rc;
        if(papdu.cla != (byte)0x80)//CLA错误
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if(papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x02)//参数错误
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        if(papdu.lc != (short)0x0B)//长度错误
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if(epfile == null)//文件不存在
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        num = keyfile.findkey(papdu.pdata[0]);//寻找密钥的记录号
        if(num == 0x00)//找不到相应密钥
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        rc = epfile.init4load(num, papdu.pdata);
        if(rc == 2)//圈存超过最大值
            ISOException.throwIt((condef.SW_LOAD_FULL));
        papdu.le = (short)0x10;
        return true;
    }
    /**
     * 消费初始化
     * @return  是否成功初始化
     */
    private boolean init_purchase(){
        short num,rc;
        if(papdu.cla != (byte)0x80)//CLA错误
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if(papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x02)//参数错误
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        if(papdu.lc != (short)0x0B)//长度错误
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if(epfile == null)//文件不存在
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        num = keyfile.findkey(papdu.pdata[0]);//寻找密钥的记录号
        if(num == 0x00)//找不到相应密钥
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        rc = epfile.init4purchase(num, papdu.pdata);
        if(rc == 2)//余额不足
            ISOException.throwIt((condef.SW_BALANCE_NOT_ENOUGH));
        papdu.le = (short)15;
        return true;
    }
    /**
     * 圈存命令
     * @return 是否成功执行
     */
    private boolean load() {
        short rc;
        if(papdu.cla != (byte)0x80)//CLA错误
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if(papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x00)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        if(epfile == null)//文件不存在
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        if(papdu.lc != (short)0x0B)//长度错误
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        rc = epfile.load(papdu.pdata);
        if(rc == 1)//MAC校验错误
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        else if(rc == 2)//圈存超额	
            ISOException.throwIt(condef.SW_LOAD_FULL);
        else if(rc == 3)//密钥未找到
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        papdu.le = (short)4;
        return true;
    }
    /**
     * 消费命令的实现
     * @return
     */
    private boolean purchase(){
        short rc;
        if(papdu.cla != (byte)0x80)//CLA错误
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if(papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x00)//参数错误
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        if(epfile == null)//文件不存在
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        if(papdu.lc != (short)0x0F)//长度错误
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        rc = epfile.purchase(papdu.pdata);
        if(rc == 1)//MAC校验错误
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        else if(rc == 2)//余额不足
            ISOException.throwIt((condef.SW_BALANCE_NOT_ENOUGH));
        else if(rc == 3)//密钥未找到
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        papdu.le = (short)8;
        return true;
    }

    /**
     * 余额查询
     * @return 是否成功执行
     */
    private boolean get_balance(){
    	short res;
    	byte[] balance = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
        if(papdu.cla != (byte)0x80)//CLA错误
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if(papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x02)//参数错误
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2); 
        if(epfile == null)//文件不存在
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        res = epfile.get_balance(balance);
        if(res != (short)0)//返回电子钱包余额
            Util.arrayCopyNonAtomic(balance, (short)0, papdu.pdata, (short)0, (short)4);
        papdu.le = (short)0x04;
        return true;
    }
    /**
     * 生成过程密钥
     * @return 是否成功执行
     */
    private boolean get_sespk(){
        PenCipher pencipher = new PenCipher();
        byte[] key = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        byte[] data = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopyNonAtomic(papdu.pdata, (short)0, key, (short)0, (short)16);
        Util.arrayCopyNonAtomic(papdu.pdata, (short)16, data, (short)0, (short)8);
        pencipher.gen_SESPK(key, data, (short)0, (short)8, papdu.pdata, (short)0);
        return true;
    }
    /**
     * MAC和TAC生成
     * @return 是否成功执行
     */
    private boolean get_mac(){
        PenCipher pencipher = new PenCipher();
        byte[] key = JCSystem.makeTransientByteArray((short)8, JCSystem.CLEAR_ON_DESELECT);
        byte[] data = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopyNonAtomic(papdu.pdata, (short)0, key, (short)0, (short)8);
        Util.arrayCopyNonAtomic(papdu.pdata, (short)8, data, (short)0, (short)(papdu.lc-8));
        pencipher.gmac4(key, data, (short)(papdu.lc-8), papdu.pdata);
        return true;
    }
    
}
