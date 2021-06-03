package nfcjlib.test;

import nfcjlib.core.DESFireEV1;
import nfcjlib.core.util.DesfireUtils;

public class Sum {

    public static void main(String[] args) {
        byte un = 0x11;
        byte deux = 0x0F;
        byte[] result = new byte[1];
        result[0] = (byte) (un & deux);
        System.out.println(DesfireUtils.byteArrayToHexString(result));
    }
}
