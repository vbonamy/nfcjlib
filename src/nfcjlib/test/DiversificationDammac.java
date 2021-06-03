package nfcjlib.test;

import nfcjlib.core.DESFireEV2;
import nfcjlib.core.util.DesfireUtils;

public class DiversificationDammac {

    static byte[] damMacKey = DesfireUtils.hexStringToByteArray("41F23FB097ADDABE1195C0E096204A2F");

    static int aid = 0xF58542; //0xF58540;
    static int damSlotNo = 0x0000;
    static byte damSlotVersion = (byte) 0xFF;
    static int quotaLimit = 0x0010;
    static byte KS1 = 0x0B;
    static byte KS2 = (byte) 0xA3;
    static byte KS3 = 0x00;
    static byte aksVersion = 0x00;
    static byte noKeySet = 0x00;
    static byte maxKeySize = 0x00;
    static byte RollKey = 0x00;
    static int iso_df_id = 0x1000;
    static byte[] iso_df_name = new byte[]{(byte) 0xA0, 0x00, 0x00, 0x06, 0x14, 0x04, (byte) 0xF5, (byte) 0x85, 0x42};
    static byte[] EncK = DesfireUtils.hexStringToByteArray("353BA660E6B923837AFBC70BAF6B1CAFEB697124F822D25C01C89AF48611F8E0");

    static byte[] response = DesfireUtils.hexStringToByteArray("18ADC01C98E4627F3031C799A663E6A7491701D075BD4FBC8EBAE27848FE1977FED60357E06768303B3DFC6BD62FBDC66B3B0B1A3DADD74F228AA0A3547D4ABE");
    public static void main(String[] args) throws Exception {

        DESFireEV2 desFireEV2 = new DESFireEV2();

        byte[] dammac = desFireEV2.calcDAMMAC(damMacKey, (byte) 0xC9, aid, damSlotNo, damSlotVersion, quotaLimit, KS1, KS2,
                KS3, aksVersion, noKeySet, maxKeySize, RollKey, iso_df_id, iso_df_name, EncK);

        System.out.println("Dammac out correct : " + DesfireUtils.byteArrayToHexString(response));

    }
}
