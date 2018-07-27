package purse;


import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class purse extends Applet {
    private Papdu papdu;                
    //�ļ�ϵͳ
    private KeyFile keyfile;		//��Կ�ļ�
    private BinaryFile cardfile;	//Ӧ�û����ļ�
    private BinaryFile personfile;	//�ֿ��˻����ļ�
    private EPFile epfile;			//����Ǯ���ļ�
    
    /**
     * ���캯�� ע��
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
	 * ��װ
	 * @param bArray
	 * @param bOffset
	 * @param bLength
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new purse(bArray, bOffset, bLength);
	}
	/**
     * ��������Ԥ����
     * @param apdu ����
     */
	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}
		//ȡAPDU�������������ò���֮�����½�����
        byte[] buf= apdu.getBuffer();
        //ȡAPDU�����������ݷŵ�����papdu
        short lc = apdu.setIncomingAndReceive(); //��������
        papdu.cla = buf[ISO7816.OFFSET_CLA];
        papdu.ins = buf[ISO7816.OFFSET_INS];
        papdu.p1 = buf[ISO7816.OFFSET_P1];
        papdu.p2 = buf[ISO7816.OFFSET_P2];
        Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA, papdu.pdata, (short)0, lc);
        //�ж�����APDU�Ƿ�������ݶ�
        boolean hasData = (papdu.APDUContainData());
        if(hasData){//�����ݻ�ȡ���ݳ��� le��ֵ
            papdu.lc = buf[ISO7816.OFFSET_LC];
            papdu.le = buf[ISO7816.OFFSET_CDATA+lc];
        }
        else{//�����ݲ���Ҫlc ��������ʱΪle
            papdu.le = buf[ISO7816.OFFSET_LC];
            papdu.lc = 0;
        }
        boolean flag = handleEvent();//�Ƿ�ɹ�����������
        if(flag && papdu.le!=0){//��Ҫ��������
            Util.arrayCopyNonAtomic(papdu.pdata, (short)0, buf, (short)0, (short)papdu.le);//���û�����
            apdu.setOutgoingAndSend((short)0, (short)papdu.le);
        }
	}
	/**
     * ������ִ��
     * @return �Ƿ�ɹ�ִ������
     */
    private boolean handleEvent(){
        switch(papdu.ins){
            case condef.INS_CREATE_FILE:       return create_file();
            case condef.INS_WRITE_KEY:		   return write_key();
            case condef.INS_WRITE_BIN:		   return write_bin();
            case condef.INS_INIT_TRANS:
                if(papdu.p1 == (byte)0x00)     return init_load();
                if(papdu.p1 == (byte)0x01)     return init_purchase();
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2); //�����ڵĲ���
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
     * �����ļ�
     * @return �Ƿ�ɹ�����
     */
    private boolean create_file() {
        switch(papdu.pdata[0]){
            case condef.KEY_FILE:       return KEY_file(); //������Կ�ļ�
            case condef.CARD_FILE:      return CARD_file(); //����Ӧ�û����ļ�
            case condef.PERSON_FILE:    return PERSON_file(); //�����ֿ��˻����ļ�
            case condef.EP_FILE:        return EP_file(); //��������Ǯ���ļ�
            default:
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        return true;
    }
    /**
     * ������Կ�ļ�
     * @return �Ƿ�ɹ�����
     */
    private boolean KEY_file() {
        if(papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);//CLA����
        if(papdu.p1 != (byte)0x00 || papdu.p2 != (byte)0x00)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);//�ļ����ʹ���
        if(papdu.lc != (byte)0x07)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);//����ĳ���
        if(keyfile != null)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);//�ļ��Ѵ���
        keyfile = new KeyFile();
        return true;
    }
    /**
     * ����Ӧ�û����ļ�
     * @return �Ƿ�ɹ�����
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
     * �ֿ��˻����ļ�
     * @return �Ƿ�ɹ�����
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
     * ��������Ǯ���ļ�
     * @return �Ƿ�ɹ�����
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
     * ���ӻ��޸���Կ
     * @return �Ƿ�ɹ�ִ��
     */
    private boolean write_key(){
        if(papdu.cla != (byte)0x80)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);//CLA����
        if(papdu.p1 != (byte)0x00 && papdu.p1 != (byte)0x01)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);//�������ʹ���
        if(papdu.lc != (byte)0x15)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);//����ĳ���
        if(keyfile == null)//��Կ�ļ�������
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        if(papdu.p1 == (byte)0x00 && keyfile.recNum == keyfile.size)//��Կ����
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        keyfile.addkey(papdu.p2, papdu.lc, papdu.pdata);
        return true;
    }
    /**
     * д��������ļ�
     * @return �Ƿ�ɹ�ִ��
     */
    private boolean write_bin(){
        if(papdu.cla != (byte)0x00)//CLA����
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if(papdu.p1 == (byte)0x17){ //д��ֿ��˻����ļ�
            if(personfile == null) //�ļ�������
            	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            else if(papdu.p2 + papdu.lc>personfile.get_size())//����ĳ���
            	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            else 
            	personfile.write_bineary(papdu.p2, papdu.lc, papdu.pdata);
        }
        else if(papdu.p1 == (byte)0x16){//д�����Ӧ���ļ�
            if(cardfile == null)//�ļ�������
            	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            else if(papdu.p2 + papdu.lc>cardfile.get_size())//����ĳ���
            	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        	else 
        		cardfile.write_bineary(papdu.p2, papdu.lc, papdu.pdata);
        }
        else
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        return true;
    }
    /**
     * ��ȡ�������ļ�
     * @return �Ƿ�ɹ�ִ��
     */
    private boolean read_bin(){
        if(papdu.cla != (byte)0x00)//CLA����
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if(papdu.p1 == (byte)0x17){//��ȡ�ֿ��˻����ļ�
        	if(personfile == null) //�ļ�������
             	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        	else if(papdu.p2 + papdu.le>personfile.get_size())//����ĳ���
            	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        	else
        		personfile.read_binary(papdu.p2, papdu.le, papdu.pdata);
        }
        else if(papdu.p1 == (byte)0x16) {//��ȡ����Ӧ���ļ�
        	if(cardfile == null)//�ļ�������
            	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            else if(papdu.p2 + papdu.le>cardfile.get_size())//����ĳ���
            	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            else
        	cardfile.read_binary(papdu.p2, papdu.le, papdu.pdata);
        }
        else
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        return true;
    }
    /**
     * Ȧ���ʼ��
     * @return �Ƿ�ɹ���ʼ��
     */
    private boolean init_load() {
        short num,rc;
        if(papdu.cla != (byte)0x80)//CLA����
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if(papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x02)//��������
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        if(papdu.lc != (short)0x0B)//���ȴ���
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if(epfile == null)//�ļ�������
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        num = keyfile.findkey(papdu.pdata[0]);//Ѱ����Կ�ļ�¼��
        if(num == 0x00)//�Ҳ�����Ӧ��Կ
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        rc = epfile.init4load(num, papdu.pdata);
        if(rc == 2)//Ȧ�泬�����ֵ
            ISOException.throwIt((condef.SW_LOAD_FULL));
        papdu.le = (short)0x10;
        return true;
    }
    /**
     * ���ѳ�ʼ��
     * @return  �Ƿ�ɹ���ʼ��
     */
    private boolean init_purchase(){
        short num,rc;
        if(papdu.cla != (byte)0x80)//CLA����
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if(papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x02)//��������
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        if(papdu.lc != (short)0x0B)//���ȴ���
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if(epfile == null)//�ļ�������
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        num = keyfile.findkey(papdu.pdata[0]);//Ѱ����Կ�ļ�¼��
        if(num == 0x00)//�Ҳ�����Ӧ��Կ
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        rc = epfile.init4purchase(num, papdu.pdata);
        if(rc == 2)//����
            ISOException.throwIt((condef.SW_BALANCE_NOT_ENOUGH));
        papdu.le = (short)15;
        return true;
    }
    /**
     * Ȧ������
     * @return �Ƿ�ɹ�ִ��
     */
    private boolean load() {
        short rc;
        if(papdu.cla != (byte)0x80)//CLA����
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if(papdu.p1 != (byte)0x00 && papdu.p2 != (byte)0x00)
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        if(epfile == null)//�ļ�������
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        if(papdu.lc != (short)0x0B)//���ȴ���
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        rc = epfile.load(papdu.pdata);
        if(rc == 1)//MACУ�����
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        else if(rc == 2)//Ȧ�泬��	
            ISOException.throwIt(condef.SW_LOAD_FULL);
        else if(rc == 3)//��Կδ�ҵ�
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        papdu.le = (short)4;
        return true;
    }
    /**
     * ���������ʵ��
     * @return
     */
    private boolean purchase(){
        short rc;
        if(papdu.cla != (byte)0x80)//CLA����
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if(papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x00)//��������
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        if(epfile == null)//�ļ�������
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        if(papdu.lc != (short)0x0F)//���ȴ���
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        rc = epfile.purchase(papdu.pdata);
        if(rc == 1)//MACУ�����
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        else if(rc == 2)//����
            ISOException.throwIt((condef.SW_BALANCE_NOT_ENOUGH));
        else if(rc == 3)//��Կδ�ҵ�
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        papdu.le = (short)8;
        return true;
    }

    /**
     * ����ѯ
     * @return �Ƿ�ɹ�ִ��
     */
    private boolean get_balance(){
    	short res;
    	byte[] balance = JCSystem.makeTransientByteArray((short)4, JCSystem.CLEAR_ON_DESELECT);
        if(papdu.cla != (byte)0x80)//CLA����
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        if(papdu.p1 != (byte)0x01 && papdu.p2 != (byte)0x02)//��������
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2); 
        if(epfile == null)//�ļ�������
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        res = epfile.get_balance(balance);
        if(res != (short)0)//���ص���Ǯ�����
            Util.arrayCopyNonAtomic(balance, (short)0, papdu.pdata, (short)0, (short)4);
        papdu.le = (short)0x04;
        return true;
    }
    /**
     * ���ɹ�����Կ
     * @return �Ƿ�ɹ�ִ��
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
     * MAC��TAC����
     * @return �Ƿ�ɹ�ִ��
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
