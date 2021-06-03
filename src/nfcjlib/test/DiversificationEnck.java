package nfcjlib.test;

import nfcjlib.core.DESFireEV1;
import nfcjlib.core.DESFireEV2;
import nfcjlib.core.util.DesfireDiversification;
import nfcjlib.core.util.DesfireUtils;

import java.util.Random;

public class DiversificationEnck {

    static byte[] input = DesfireUtils.hexStringToByteArray("91ED6509221AFD0000000000000000000000000000000000".concat("0000000000000000"));
    static byte[] PICCDAMENCKey = DesfireUtils.hexStringToByteArray("A580B1A4D014DB32219F756F3A2B3471");
    static byte[] IV = DesfireUtils.hexStringToByteArray("00000000000000000000000000000000");

    static byte[] response = DesfireUtils.hexStringToByteArray("353BA660E6B923837AFBC70BAF6B1CAFEB697124F822D25C01C89AF48611F8E0");


    public static void main(String[] args) throws Exception {

        DesfireDiversification desfireDiversification = new DesfireDiversification();

        byte[] EncK = desfireDiversification.encrypt(PICCDAMENCKey, input, IV);

        System.out.println("ENCK correct : " + DesfireUtils.byteArrayToHexString(response));
        System.out.println("ENCK  out " + DesfireUtils.byteArrayToHexString(EncK));

    }
}
