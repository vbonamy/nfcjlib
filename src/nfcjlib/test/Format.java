package nfcjlib.test;

import nfcjlib.core.DESFireEV1;
import nfcjlib.core.util.DesfireUtils;

public class Format {

    public static void main(String[] args) {
        DESFireEV1 desfire = new DESFireEV1();
        desfire.connect();

        desfire.selectApplication(new byte[] {0x00, 0x00, 0x00});
        desfire.authenticate(new byte[16], (byte) 0x00, DESFireEV1.KeyType.AES);

        desfire.formatPICC();

        if (desfire.getCardUID() != null) {
            System.out.println("CSN = " + DesfireUtils.byteArrayToHexString(desfire.getCardUID()));
        }

        desfire.disconnect();
    }
}
