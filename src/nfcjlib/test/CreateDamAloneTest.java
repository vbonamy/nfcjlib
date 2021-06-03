package nfcjlib.test;

import nfcjlib.core.DESFireEV1;
import nfcjlib.core.DESFireEV2;
import nfcjlib.core.util.DesfireUtils;

public class CreateDamAloneTest {

    public static void main(String[] args) throws Exception {
        DESFireEV2 desFireEV2 = new DESFireEV2();
        byte[][] result = desFireEV2.createDamKeys();
        byte[] damAuthKey = result[0];
        byte[] damMacKey = result[1];
        byte[] damEnckey = result[2];
        desFireEV2.createDamAlone(damAuthKey, damMacKey, damEnckey);
    }
}
