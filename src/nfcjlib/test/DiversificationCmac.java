package nfcjlib.test;

import nfcjlib.core.DESFireEV2;
import nfcjlib.core.util.DesfireUtils;

import java.util.Arrays;

public class DiversificationCmac {

    static byte[] damkey = DesfireUtils.hexStringToByteArray("41F23FB097ADDABE1195C0E096204A2F");
    static byte[] IV = DesfireUtils.hexStringToByteArray("00000000000000000000000000000000");
    static byte[] input = DesfireUtils.hexStringToByteArray("C94285F50000FF10000BA30010A00000061404F58542353BA660E6B923837AFBC70BAF6B1CAFEB697124F822D25C01C89AF48611F8E0");

    public static void main(String[] args) throws Exception {

        DESFireEV2 desFireEV2 = new DESFireEV2();

        byte[] dammac = desFireEV2.CalculateCMAC(damkey, IV, input);

    }
}
