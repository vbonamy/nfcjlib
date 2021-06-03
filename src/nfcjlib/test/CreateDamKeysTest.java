package nfcjlib.test;

import nfcjlib.core.DESFireEV1;
import nfcjlib.core.DESFireEV2;
import nfcjlib.core.util.DesfireUtils;

public class CreateDamKeysTest {

    public static void main(String[] args) throws Exception {
        DESFireEV2 desFireEV2 = new DESFireEV2();
        desFireEV2.createDamKeys();
    }
}
