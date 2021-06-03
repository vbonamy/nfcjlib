package nfcjlib.core;

import nfcjlib.core.util.CRC16;
import nfcjlib.core.util.CRC32;
import nfcjlib.core.util.DesfireDiversification;
import nfcjlib.core.util.DesfireUtils;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Random;

public class DESFireEV2 extends DESFireEV1 {

    public int xfer_length;

    public byte[] xfer_buffer = new byte[1000000];

    public final static byte INF = 0;

    DesfireDiversification desfireDiversification =  new DesfireDiversification();

    public enum CommandEv2 {

        DF_CREATE_DELEGATED_APPLICATION ((byte) 0xC9),
        UNKNOWN_COMMAND                 ((byte) 1001),
        DF_GET_DELEGATED_INFO           ((byte) 0x69);

        private final byte code;

        private CommandEv2(byte code) {
            this.code = code;
        }

        private byte getCode() {
            return code;
        }

        private static CommandEv2 getCommand(int code) {
            for (CommandEv2 c : CommandEv2.values())
                if (code == c.getCode())
                    return c;
            return UNKNOWN_COMMAND;
        }
    }

    public enum ResponseEv2 {

        CARD_ERROR              (-1000),
        DFCARD_LIB_CALL_ERROR   (-999);

        private final int code;

        private ResponseEv2(int code) {
            this.code = code;
        }

        private int getCode() {
            return code;
        }

        private static ResponseEv2 getCommand(int code) {
            for (ResponseEv2 c : ResponseEv2.values())
                if (code == c.getCode())
                    return c;
            return null;
        }
    }

    @Override
    public boolean changeKey(byte keyNo, KeyType newType, byte[] newKey, byte[] oldKey) {
        return changeKey(keyNo, (byte) 0x00, newType, newKey, oldKey, this.skey);
    }

    private boolean changeKey(byte keyNo, byte keyVersion, KeyType type, byte[] newKey, byte[] oldKey, byte[] sessionKey) {
        if (!validateKey(newKey, type)
                || kno != (keyNo & 0x3F)
                && (oldKey == null
                || ktype == KeyType.DES && oldKey.length != 8
                || ktype == KeyType.TDES && oldKey.length != 16
                || ktype == KeyType.TKTDES && oldKey.length != 24
                || ktype == KeyType.AES && oldKey.length != 16)) {
            // basic checks to mitigate the possibility of messing up the keys
            System.err.println("You're doing it wrong, chief! (changeKey: check your args)");
            this.code = Response.WRONG_ARGUMENT.getCode();
            return false;
        }

        byte[] plaintext = null;
        byte[] ciphertext = null;
        int nklen = type == KeyType.TKTDES ? 24 : 16;  // length of new key

        switch (ktype) {
            case DES:
            case TDES:
                plaintext = type == KeyType.TKTDES ? new byte[32] : new byte[24];
                break;
            case TKTDES:
            case AES:
                plaintext = new byte[32];
                break;
            default:
                assert false : ktype; // this point should never be reached
        }
        if (type == KeyType.AES) {
            plaintext[16] = keyVersion;
        } else {
            setKeyVersion(newKey, 0, newKey.length, keyVersion);
        }
        System.arraycopy(newKey, 0, plaintext, 0, newKey.length);
        if (type == KeyType.DES) {
            // 8-byte DES keys accepted: internally have to be handled w/ 16 bytes
            System.arraycopy(newKey, 0, plaintext, 8, newKey.length);
            newKey = Arrays.copyOfRange(plaintext, 0, 16);
        }

        // tweak for when changing PICC master key
        if (Arrays.equals(aid, new byte[3]) && (keyNo & 0x3F) == 0x00) {
            switch (type) {
                case TKTDES:
                    keyNo = 0x40;
                    break;
                case AES:
                    keyNo = (byte) 0x80;
                    break;
                default:
                    break;
            }
        }

        if ((keyNo & 0x3F) != kno) {
            for (int i = 0; i < newKey.length; i++) {
                plaintext[i] ^= oldKey[i % oldKey.length];
            }
        }

        byte[] tmpForCRC;
        byte[] crc;
        int addAesKeyVersionByte = type == KeyType.AES ? 1 : 0;

        switch (ktype) {
            case DES:
            case TDES:
                crc = CRC16.get(plaintext, 0, nklen + addAesKeyVersionByte);
                System.arraycopy(crc, 0, plaintext, nklen + addAesKeyVersionByte, 2);

                if ((keyNo & 0x3F) != kno) {
                    crc = CRC16.get(newKey);
                    System.arraycopy(crc, 0, plaintext, nklen + addAesKeyVersionByte + 2, 2);
                }

                ciphertext = send(sessionKey, plaintext, ktype, null);
                break;
            case TKTDES:
            case AES:
                tmpForCRC = new byte[1 + 1 + nklen + addAesKeyVersionByte];
                tmpForCRC[0] = (byte) Command.CHANGE_KEY.getCode();
                tmpForCRC[1] = keyNo;
                System.arraycopy(plaintext, 0, tmpForCRC, 2, nklen + addAesKeyVersionByte);
                crc = CRC32.get(tmpForCRC);
                System.arraycopy(crc, 0, plaintext, nklen + addAesKeyVersionByte, crc.length);

                if ((keyNo & 0x3F) != kno) {
                    crc = CRC32.get(newKey);
                    System.arraycopy(crc, 0, plaintext, nklen + addAesKeyVersionByte + 4, crc.length);
                }

                ciphertext = send(sessionKey, plaintext, ktype, iv);
                this.iv = Arrays.copyOfRange(ciphertext, ciphertext.length - iv.length, ciphertext.length);
                break;
            default:
                assert false : ktype; // should never be reached
        }

        byte[] apdu = new byte[5 + 1 + ciphertext.length + 1];
        apdu[0] = (byte) 0x90;
        apdu[1] = (byte) Command.CHANGE_KEY.getCode();
        apdu[4] = (byte) (1 + plaintext.length);
        apdu[5] = keyNo;
        System.arraycopy(ciphertext, 0, apdu, 6, ciphertext.length);
        CommandAPDU command = new CommandAPDU(apdu);
        ResponseAPDU response = transmit(command);
        this.code = response.getSW2();
        feedback(command, response);

        if (this.code != 0x00)
            return false;
        if ((keyNo & 0x3F) == kno) {
            this.reset();
        } else {
            return postprocess(response.getBytes(), CommunicationSetting.PLAIN) != null;
        }

        return true;
    }

    public byte[][] createDamKeys() throws Exception {
        this.connect();

        byte[][] result = new byte[3][16];
        this.selectApplication(new byte[] {0x00, 0x00, 0x00});
        this.authenticate(new byte[16], (byte) 0x00, KeyType.AES);

        byte[] uid = this.getCardUID();
        byte[] divertKey = DesfireUtils.hexStringToByteArray("00112233445566778899101112131415");

        byte[] damAuthKey = desfireDiversification.diversificationAES128(divertKey, uid, uid.length);
        System.out.println("damAuthKey = " + DesfireUtils.byteArrayToHexString(damAuthKey));
        this.changeKey((byte) 0x10, KeyType.AES, damAuthKey, new byte[16]);

        System.arraycopy(damAuthKey, 0, result[0], 0, 16);

        byte[] encUid = this.getCardUID();
        encUid[0] = (byte) 0x00;
        byte[] damEncKey = desfireDiversification.diversificationAES128(divertKey, encUid, encUid.length);
        System.out.println("damEncKey = " + DesfireUtils.byteArrayToHexString(damEncKey));
        this.changeKey((byte) 0x12, KeyType.AES, damEncKey, new byte[16]);

        System.arraycopy(damEncKey, 0, result[2], 0, 16);

        byte[] macUid = this.getCardUID();
        macUid[0] = (byte) 0xFF;
        byte[] damMacKey = desfireDiversification.diversificationAES128(divertKey, macUid, macUid.length);
        System.out.println("damMacKey = " + DesfireUtils.byteArrayToHexString(damMacKey));
        this.changeKey((byte) 0x11, KeyType.AES, damMacKey, new byte[16]);

        System.arraycopy(damMacKey, 0, result[1], 0, 16);

        //desfire.authenticate(new byte[16], (byte) 0x10, KeyType.AES);
        //desfire.authenticate(DesfireUtils.hexStringToByteArray("39F1EBF9872B3E999C7062F2E2252DF1"), (byte) 0x10, KeyType.AES);

        this.disconnect();

        return result;
    }

    public void resetDamKeys(byte[] damAuthKey, byte[] damMacKey, byte[] damEncKey) {

        this.selectApplication(new byte[] {0x00, 0x00, 0x00});
        this.authenticate(new byte[16], (byte) 0x00, KeyType.AES);

        System.out.println("damAuthKey was " + DesfireUtils.byteArrayToHexString(damAuthKey));
        this.changeKey((byte) 0x10, KeyType.AES, new byte[16], damAuthKey);

        System.out.println("damMacKey was " + DesfireUtils.byteArrayToHexString(damMacKey));
        this.changeKey((byte) 0x11, KeyType.AES, new byte[16], damMacKey);

        System.out.println("damEncKey was " + DesfireUtils.byteArrayToHexString(damEncKey));
        this.changeKey((byte) 0x12, KeyType.AES, new byte[16], damEncKey);

        //desfire.authenticate(new byte[16], (byte) 0x10, KeyType.AES);
        //desfire.authenticate(DesfireUtils.hexStringToByteArray("39F1EBF9872B3E999C7062F2E2252DF1"), (byte) 0x10, KeyType.AES);

    }

    public void createDamAlone(byte[] damAuthKey, byte[] damMacKey, byte[] damEncKey) throws Exception {
        this.connect();

        System.out.println("[INFO] Create delegated application alone...");

        System.out.println("[INFO] Create DAM ...");
        if (createDAMApplication(damAuthKey, damMacKey, damEncKey)) {
            System.out.println("[INFO] DAM is created ...");
        }

        this.disconnect();
    }

    private boolean createDAMApplication(byte[] damAuthKey, byte[] damMacKey, byte[] damEncKey) throws Exception {
        boolean rc;

        byte file_id = 0x00;

        /* communication plain text for clear access */
        byte comm_mode = 0x00;

        /* read access clear 'E' */
        /* write access '0' master key only */
        /* read/write access clear '0' */
        /* change access rights '0' master key only */
        int access_rights = 0xE000;
        int aid = 0xF58542; //0xF58540;
        byte[] aidByteArray = new byte[]{(byte) 0x42, (byte) 0x85, (byte) 0xF5};
        int damSlotNo = 0x0000;
        byte damSlotVersion = (byte) 0xFF;
        int quotaLimit = 0x0010;

        int iso_df_id = 0x1000;
        byte[] iso_df_name = new byte[]{(byte) 0xA0, 0x00, 0x00, 0x06, 0x14, 0x04, (byte) 0xF5, (byte) 0x85, 0x42};
        /* AppKeySettings changeable, App master key changeable*/
        byte KS1 = 0x0B;
        /* AES, 3 keys, Use of 2 byte ISO/IEC 7816-4 File Identifiers*/
        byte KS2 = (byte) 0xA3;

        byte KS3 = 0x00;
        byte aksVersion = 0x00;
        byte noKeySet = 0x00;
        byte maxKeySize = 0x00;
        byte RollKey = 0x00;
        /* default key used for creation of delegated application */
        byte[] damDefaultKey = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte damDefaultKeyVersion = 0x00;

        System.out.println("--- Create Delegated application ---");

        /* select master application */
        rc = this.selectApplication(new byte[]{0x00, 0x00, 0x00});
        if (!rc) {
            System.out.println("DesfireEv2 'SelectApplication' DAMAuthKey command failed - rc= " + (0xFFFF - (0xFFFF + 1000)));
            return false;
        }

        /* Authentification via PICCDAMAuthKey */
        if (this.authenticate(damAuthKey, (byte) 0x10, DESFireEV1.KeyType.AES) == null) {
            System.out.println("DesfireEv2 'AuthenticateAes' DAMAuthKey command failed - rc= " + (0xFFFF - (0xFFFF + 1000)));
            return false;
        }

        /* read rest of memory for information */
        byte [] response = DesfireUtils.swapPairsByte(this.freeMemory());
        System.out.println(MessageFormat.format("DesfireEv2 'FreeMem' {0}", DesfireUtils.byteArrayToHexString(response)));


        /*
         * start of issuer card job
         */

        /*Calculate EncK*/
        byte[] EncK = calcEncK(damEncKey, damDefaultKey, damDefaultKeyVersion);
        //byte[] EncK = DesfireUtils.hexStringToByteArray("63cee71d7350e41a4fa9b04f0a03176ccb38b2b11f2f596c7506469b2268cae7");

        /* Calculate DAMMAC */
        //byte[] dammac = DesfireUtils.hexStringToByteArray("710ad38edc0f511b");
        byte[] dammac = calcDAMMAC(damMacKey, CommandEv2.DF_CREATE_DELEGATED_APPLICATION.getCode(), aid, damSlotNo, damSlotVersion, quotaLimit, KS1, KS2, KS3, aksVersion, noKeySet, maxKeySize, RollKey, iso_df_id, iso_df_name, EncK);

        /*
         * stop of issuer card job
         */

        /* Authentification via PICCDAMAuthKey */

        if (this.authenticate(damAuthKey, (byte) 0x10, DESFireEV1.KeyType.AES) == null) {
            System.out.println("DesfireEv2 'AuthenticateAes' DAMAuthKey command failed - rc= " + (0xFFFF - (0xFFFF + 1000)));
            return false;
        }

        /*
         * start of application provider job
         */

        /* Create Delegated application */
        if (!this.CreateDelegatedApplication_Ex(aid, damSlotNo, damSlotVersion, quotaLimit, KS1, KS2, KS3, aksVersion, noKeySet, maxKeySize, RollKey,
                iso_df_id, iso_df_name, iso_df_name.length, EncK, dammac)) {
            System.out.println("DesfireEv2 'CreateDelegatedApplication' command failed - rc= " + (0xFFFF - (0xFFFF + 1000)));
            return false;
        }

        response = DesfireUtils.swapPairsByte(this.freeMemory());
        /* read rest of memory for information */
        System.out.println(MessageFormat.format("DesfireEv2 'FreeMem' {0}", DesfireUtils.byteArrayToHexString(response)));


        /* select DAM application */
        if (!this.selectApplication(aidByteArray)) {
            System.out.println("DesfireEv2 'SelectApplication' Delegated command failed - rc= " + (0xFFFF - (0xFFFF + 1000)));
            return false;
        }

        /* Authentification via  DamDefaultKey temporary key */

        if (this.authenticate(damDefaultKey, (byte) 0x00, DESFireEV1.KeyType.AES) == null) {
            System.out.println("DesfireEv2 'AuthenticateAes' DamDefaultKey command failed - rc= " + (0xFFFF - (0xFFFF + 1000)));
            return false;
        }

        System.out.println("DesfireEv2 check key settings");
        byte key_settings = 0x00;
        byte key_count = 0x00;

        byte[] keySettingsResponse = this.getKeySettings();
        if (keySettingsResponse == null) {
            System.out.println("DesfireEv2 'GetKeySettings' command failed - rc= " + (0xFFFF - (0xFFFF + 1000)));
            return false;
        }

        key_settings = keySettingsResponse[0];
        key_count = keySettingsResponse[1];

        System.out.println("DesfireEv2 key_settings " + key_settings + " key_count " + key_count);
        /*Delegated applications can be deleted permanently using Cmd.DeleteApplication. If b2 of PICCKeySettings is set to 0 */
        key_settings &= 0xFD;

        if (!this.changeKeySettings(key_settings)) {
            System.out.println("DesfireEv2 'GetKeySettings' command failed - rc= " + (0xFFFF - (0xFFFF + 1000)));
            return false;
        }

        keySettingsResponse = this.getKeySettings();

        if (keySettingsResponse == null) {
            System.out.println("DesfireEv2 'GetKeySettings' command failed - rc= " + (0xFFFF - (0xFFFF + 1000)));
            return false;
        }

        key_settings = keySettingsResponse[0];
        key_count = keySettingsResponse[1];

        System.out.println("DesfireEv2 key_settings " + key_settings + " key_count " + key_count);

        byte[] DefaultKey = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        byte[] AppMasterKey1 = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
        byte[] AppMasterKey2 = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
        byte[] AppMasterKey3 = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03};

        System.out.println("DesfireEv2 'ChangeKeyAes' APP master key");
        if (!this.changeKey((byte) 0x00, (byte) 0x01, DESFireEV1.KeyType.AES, AppMasterKey1, null)) {
            System.out.println("[DEBUG] Desfire 'ChangeKey' command failed - rc= " + (0xFFFF - (0xFFFF + 1000)));
            return false;
        }

        System.out.println("DesfireEv2 'Check Authentificate AES with master App key");
        if (this.authenticate(AppMasterKey1, (byte) 0x00, DESFireEV1.KeyType.AES) == null) {
            System.out.println("DesfireEv2 'Authenticate' command failed - rc= " + (0xFFFF - (0xFFFF + 1000)));
            return false;
        }

        System.out.println("DesfireEv2 'ChangeKeyAes' Key 1");
        if (!this.changeKey((byte) 0x01, (byte) 0x02, DESFireEV1.KeyType.AES, AppMasterKey2, DefaultKey)) {
            System.out.println("[DEBUG] Desfire 'ChangeKey' command failed - rc= " + (0xFFFF - (0xFFFF + 1000)));
            return false;
        }
        System.out.println("DesfireEv2 'ChangeKeyAes' Key 2");
        if (!this.changeKey((byte) 0x02, (byte) 0x03, DESFireEV1.KeyType.AES, AppMasterKey3, DefaultKey)) {
            System.out.println("[DEBUG] Desfire 'ChangeKey' command failed - rc= " + (0xFFFF - (0xFFFF + 1000)));
            return false;
        }

        byte[] provider_data = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};

        /* Create Sample Standards files */
        System.out.println("DesfireEv2 Provider create Standard file");

        byte[] payloadStd = new byte[9];
        byte[] accesRightArray = DesfireUtils.swapPairsByte(DesfireUtils.hexStringToByteArray(leftPad(Integer.toHexString(access_rights), 4, '0')));
        byte[] fileSizeArray = DesfireUtils.swapPairsByte(DesfireUtils.hexStringToByteArray(leftPad(Integer.toHexString(provider_data.length), 6, '0')));
        byte[] dummmyArray = DesfireUtils.swapPairsByte(DesfireUtils.hexStringToByteArray("1001"));
        payloadStd[0] = file_id;
        System.arraycopy(dummmyArray, 0, payloadStd, 1, 2);
        payloadStd[3] = comm_mode;
        payloadStd[4] = accesRightArray[0];
        payloadStd[5] = accesRightArray[1];
        System.arraycopy(fileSizeArray, 0, payloadStd, 6, 3);

        if (!this.createIsoStdDataFile(payloadStd)) {
            System.out.println("DesfireEv2 'CreateStdDataFile' Sample command failed - rc= " + (0xFFFF - (0xFFFF + 1000)));
            return false;
        }
        /* write data inside file */

        System.out.println("DesfireEv2 Provider write its data");

        byte[] payloadWrite = new byte[7 + provider_data.length];
        payloadWrite[0] = file_id;
        System.arraycopy(DesfireUtils.swapPairsByte(DesfireUtils.hexStringToByteArray(leftPad(Integer.toHexString(0), 6, '0'))), 0, payloadWrite, 1, 3);
        System.arraycopy(DesfireUtils.swapPairsByte(DesfireUtils.hexStringToByteArray(leftPad(Integer.toHexString(provider_data.length), 6, '0'))), 0, payloadWrite, 4, 3);
        System.arraycopy(provider_data, 0, payloadWrite, 7, provider_data.length);

        if (!this.writeData(payloadWrite)) {
            System.out.println("DesfireEv2 'WriteData' Sample command failed - rc= " + (0xFFFF - (0xFFFF + 1000)));
            return false;
        }

        /* read data from file */
        int done = 0;
        byte[] local = new byte[600];

        System.out.println("DesfireEv2 Provider read its data");

        byte[] payloadRead = new byte[7];
        payloadRead[0] = file_id;
        System.arraycopy(DesfireUtils.swapPairsByte(DesfireUtils.hexStringToByteArray(leftPad(Integer.toHexString(0), 6, '0'))), 0, payloadRead, 1, 3);
        System.arraycopy(DesfireUtils.swapPairsByte(DesfireUtils.hexStringToByteArray(leftPad(Integer.toHexString(0), 6, '0'))), 0, payloadRead, 4, 3);

        byte[] responseRead = this.readData(payloadRead);
        if (responseRead == null) {
            System.out.println("DesfireEv2 'ReadData' Sample command failed - rc= " + (0xFFFF - (0xFFFF + 1000)));
            return false;
        }
        /*
         * end of application provider job
         */


        /*
         * check delegated application creation
         */
        /* select master application */
        if (!this.selectApplication(new byte[]{0x00, 0x00, 0x00})) {
            System.out.println("DesfireEv2 'SelectApplication' DAMAuthKey command failed - rc= " + (0xFFFF - (0xFFFF + 1000)));
            return false;
        }

        /* Retrieve DAM slot information */
        byte dam_slot_version = 0;
        byte quota_limit = 0;
        byte free_blocks = 0;

        byte[] responseDelegatedInfo = this.GetDelegatedInfo(damSlotNo, aid, dam_slot_version, quota_limit, free_blocks);

        if (responseDelegatedInfo == null) {
            System.out.println("Desfire 'GetDelegatedInfo'command failed - rc= " + (0xFFFF - (0xFFFF + 1000)));
            return false;
        }

        byte[] aidArray = new byte[3];
        System.arraycopy(responseDelegatedInfo, 0, aidArray, 0, 3);
        dam_slot_version = responseDelegatedInfo[3];
        quota_limit = responseDelegatedInfo[4];
        free_blocks = responseDelegatedInfo[5];
        System.out.println("--- Application " + DesfireUtils.byteArrayToHexString(aidArray) + " version " + dam_slot_version + " quota " + quota_limit + " free_blocks " + free_blocks + " ---");

        return true;
    }

    public byte[] calcEncK(byte[] PICCDAMENCKey, byte[] AppDAMDefault, byte KeyVerAppDAMDefault) throws Exception {

        byte[] IV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        Random rand = new Random();
        byte[] random = new byte[7];
        for (int i = 0 ; i < random.length; i++) {
            random[i] = (byte) rand.nextInt(0xFF);
        }
        byte[] input = new byte[AppDAMDefault.length + 16];

        System.arraycopy(random, 0, input, 0, 7);
        System.arraycopy(AppDAMDefault, 0, input, 7, 16);
        input[input.length - 1] = KeyVerAppDAMDefault;

        System.out.println("ENCK in " + DesfireUtils.byteArrayToHexString(input));
        System.out.println("ENCK in " + DesfireUtils.byteArrayToHexString(PICCDAMENCKey));
        System.out.println("ENCK in " + DesfireUtils.byteArrayToHexString(IV));

        byte[] EncK = desfireDiversification.encrypt(PICCDAMENCKey, input, IV);

        System.out.println("ENCK  out" + DesfireUtils.byteArrayToHexString(EncK));

        return EncK;
    }

    public byte[] calcDAMMAC(byte[] PICCDAMMACKey, byte cmd, int aid, int damSlotNo, byte damSlotVersion, int quotaLimit, byte key_setting_1, byte key_setting_2,
                             byte key_setting_3, byte aks_version, byte NoKeySets, byte MaxKeySize, byte Aks, int iso_df_id, byte[] iso_df_name, byte[] ENCK) throws Exception {

        byte[] IV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        byte[] input;
        int input_lenght = 0;

        if ((key_setting_2 & 0x10) == 0x10) {
            input_lenght++;
            if ((key_setting_3 & 0x01) == 0x01) {
                input_lenght++;
                if ((NoKeySets >= 2) && (NoKeySets <= 16)) {
                    input_lenght++;
                    if ((NoKeySets == 0x10) || (NoKeySets == 18)) {
                        input_lenght++;
                    }
                    input_lenght++;
                }
            }
        }

        if (iso_df_name != null)
            input = new byte[11 + ENCK.length + (iso_df_name.length + 2) + input_lenght];
        else
            input = new byte[11 + ENCK.length + input_lenght];

        input_lenght = 0;
        input[input_lenght++] = cmd;
        input[input_lenght++] = (byte) (aid & 0x000000FF);
        input[input_lenght++] = (byte) ((aid >> 8) & 0x00FF);
        input[input_lenght++] = (byte) ((aid >> 16) & 0x00FF);
        input[input_lenght++] = (byte) (damSlotNo & 0x00FF);
        input[input_lenght++] = (byte) (damSlotNo >> 8);
        input[input_lenght++] = damSlotVersion;
        input[input_lenght++] = (byte) (quotaLimit & 0x00FF);
        input[input_lenght++] = (byte) (quotaLimit >> 8);
        input[input_lenght++] = key_setting_1;
        input[input_lenght++] = key_setting_2;

        if ((key_setting_2 & 0x10) == 0x10) {
            input[input_lenght++] = key_setting_3;
            if ((key_setting_3 & 0x01) == 0x01) {
                input[input_lenght++] = aks_version;
                if ((NoKeySets >= 2) && (NoKeySets <= 16)) {
                    input[input_lenght++] = NoKeySets;
                    if ((NoKeySets == 0x10) || (NoKeySets == 18)) {
                        input[input_lenght++] = MaxKeySize;
                    }
                    input[input_lenght++] = Aks;
                }
            }
        }

        if (iso_df_name != null) {
            input[input_lenght++] = (byte) (iso_df_id & 0x00FF);
            input[input_lenght++] = (byte) (iso_df_id >> 8);

            for (int i = 0; i < iso_df_name.length; i++)
                input[input_lenght++] = iso_df_name[i];
        }
        /* add encK at the end */
        for (int i = 0; i < ENCK.length; i++)
            input[input_lenght++] = ENCK[i];

        System.out.println("DAMMAC  in " + DesfireUtils.byteArrayToHexString(input));
        System.out.println("DAMMAC  PICCDAMMACKey " + DesfireUtils.byteArrayToHexString(PICCDAMMACKey));
        System.out.println("DAMMAC  IV " + DesfireUtils.byteArrayToHexString(IV));

        byte[] CMAC_enormous = this.CalculateCMAC(PICCDAMMACKey, IV, input);

        System.out.println("DAMMAC  out " + DesfireUtils.byteArrayToHexString(CMAC_enormous));

        System.out.println("CMAC_enormous calcul soft: " + DesfireUtils.byteArrayToHexString(CMAC_enormous));

        //Console.WriteLine(s);

        byte[] CMAC_full = new byte[16];
        System.arraycopy(CMAC_enormous, CMAC_enormous.length - 16, CMAC_full, 0, 16);

        System.out.println("CMAC_full calcul soft: " + DesfireUtils.byteArrayToHexString(CMAC_full));

        byte[] CMAC = new byte[8];
        int j = 0;

        for (int i = 1; i < CMAC_full.length; ) {
            CMAC[j++] = CMAC_full[i];
            i += 2;
        }

        System.out.println("CMAC calcul soft: " + DesfireUtils.byteArrayToHexString(CMAC));
        //Console.WriteLine(s);

        return CMAC;
    }

    public byte[] CalculateCMAC(byte[] Key, byte[] IV, byte[] input) throws Exception {

        // First : calculate subkey1 and subkey2
        byte[] Zeros = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        //byte[] K = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c } ;

        byte[] L = desfireDiversification.encrypt(Key, Zeros, IV);

        System.out.println(DesfireUtils.byteArrayToHexString(L));

      /*
      Console.WriteLine("CIPHk(0128)=");
      for (int k = 0; k< L.Length; k++)
        Console.Write("-" + String.Format("{0:x02}", L[k]));
      Console.Write("\n");
      */

        byte[] Key1;
        byte[] Key2;
        int i = 0;
        byte Rb = (byte) 0x87;
        byte MSB_L = L[0];
        int decal;

        // calcul de Key 1
        for (i = 0; i < L.length - 1; i++) {
            decal = (L[i] << 1);
            L[i] = (byte) (decal & 0x00FF);
            if ((L[i + 1] & 0x80) == 0x80) {
                L[i] |= 0x01;
            } else {
                L[i] |= 0x00;
            }
        }

        decal = (L[i] << 1);
        L[i] = (byte) (decal & 0x00FF);

        if (MSB_L >= (byte) 0x80) {
            L[L.length - 1] ^= Rb;
        }

        Key1 = L;

        System.out.println(DesfireUtils.byteArrayToHexString(Key1));
      /*
      Console.Write("Key1=");
      for (int k = 0; k< L.Length; k++)
        Console.Write("-" + String.Format("{0:x02}", Key1[k]));
      Console.Write("\n");
      */

        byte[] tmp = new byte[Key1.length];
        System.arraycopy(Key1, 0, tmp, 0, Key1.length);

        // Calcul de key 2
        byte MSB_K1 = Key1[0];
        for (i = 0; i < L.length - 1; i++) {
            decal = (tmp[i] << 1);
            tmp[i] = (byte) (decal & 0x00FF);
            if ((tmp[i + 1] & 0x80) == 0x80) {
                tmp[i] |= 0x01;
            } else {
                tmp[i] |= 0x00;
            }
        }
        decal = (tmp[i] << 1);
        tmp[i] = (byte) (decal & 0x00FF);
        if (MSB_K1 >= (byte) 0x80)
            tmp[tmp.length - 1] ^= Rb;

        Key2 = tmp;

      /*
      Console.Write("Key2=");
      for (int k = 0; k< L.Length; k++)
        Console.Write("-" + String.Format("{0:x02}", Key2[k]));
      Console.Write("\n");
      */
        System.out.println(DesfireUtils.byteArrayToHexString(Key2));

        byte[] result;

        /*-------------------------------------------------*/
        /* Cas 1 : la chaine est vide    */
        /* a- On concatene avec 0x80000000..00  (data) */
        /* b- on X-or avec Key2  (M1)*/
        /* c- on encrypte en AES-128 avec K et IV */
        /**/
        if (input == null) {
            byte[] data = {(byte) 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            byte[] M1 = new byte[16];
            for (int k = 0; k < 16; k++)
                M1[k] = (byte) (data[k] ^ Key2[k]); // input

            result = desfireDiversification.encrypt(Key, M1, IV);

        } else {
            /**/

            /*--------------------------------------------------*/
            /* Cas 2 ! la chaine n'est pas vide et contient 16 octets  */
            /* a- on X-or avec Key 1 (data)  */
            /* b- on encrypte en AES-128 avec K et IV  */
            // byte[] data = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };


            if (input.length == 16) {
                byte[] M1 = new byte[input.length];
                for (int k = 0; k < input.length; k++)
                    M1[k] = (byte) (input[k] ^ Key1[k]);

                result = desfireDiversification.encrypt(Key, M1, IV);
            } else {
                byte[] M = new byte[input.length + 16];
                int offset = 0;
                for (i = 0; i < input.length; i += 16) {
                    if ((i + 16) < input.length) {
                        /* block entier - on ne padde pas */
                        for (int j = 0; j < 16; j++)
                            M[offset++] = (byte) (input[i + j]);// ^ Key1[j]);

                    } else if ((i + 16) == input.length) {
                        /* block entier, on doit padder avec Key 1 */
                        for (int j = 0; j < 16; j++)
                            M[offset++] = (byte) (input[i + j] ^ Key1[j]);

                    } else {
                        /* block terminal */
                        byte remaining = (byte) (input.length - i);
                        byte NbPadd = (byte) (16 - remaining);


                        for (int j = 0; j < remaining; j++)
                            M[offset++] = (byte) (input[i + j] ^ Key2[j]);

                        byte key2_index_when_input_ends = (byte) (input.length % 16);
                        M[offset++] = (byte) (0x80 ^ Key2[key2_index_when_input_ends]);
                        NbPadd--;
                        key2_index_when_input_ends++;
                        for (int j = 1; j <= NbPadd; j++)
                            M[offset++] = Key2[remaining + j];

                    }

                }

                byte[] Message = new byte[offset];
                System.arraycopy(M, 0, Message, 0, offset);

                result = desfireDiversification.encrypt(Key, Message, IV);
            }
        }

        return result;

    }


    private boolean CreateDelegatedApplication_Ex(int aid, int DAMSlotNo, byte damSlotVersion, int quotaLimit, byte key_setting_1, byte key_setting_2, byte key_setting_3,
                                               byte aks_version, byte NoKeySets, byte MaxKeySize, byte Aks, int iso_df_id, byte[] iso_df_name, int iso_df_namelen, byte[] EncK, byte[] Dammac) {
        long status;


        /* Create the info block containing the command code and the given parameters. */
        xfer_length = 0;
        xfer_buffer[xfer_length++] = CommandEv2.DF_CREATE_DELEGATED_APPLICATION.getCode();
        xfer_buffer[xfer_length++] = (byte) (aid & 0x000000FF);
        aid >>= 8;
        xfer_buffer[xfer_length++] = (byte) (aid & 0x000000FF);
        aid >>= 8;
        xfer_buffer[xfer_length++] = (byte) (aid & 0x000000FF);

        xfer_buffer[xfer_length++] = (byte) (DAMSlotNo & 0x00FF);
        DAMSlotNo >>= 8;
        xfer_buffer[xfer_length++] = (byte) (DAMSlotNo & 0x00FF);
        xfer_buffer[xfer_length++] = damSlotVersion;
        xfer_buffer[xfer_length++] = (byte) (quotaLimit & 0x00FF);
        quotaLimit >>= 8;
        xfer_buffer[xfer_length++] = (byte) (quotaLimit & 0x00FF);

        xfer_buffer[xfer_length++] = key_setting_1;
        xfer_buffer[xfer_length++] = key_setting_2;
        if ((key_setting_2 & 0x10) == 0x10)
            xfer_buffer[xfer_length++] = key_setting_3;
        if ((key_setting_3 & 0x01) == 0x01) {
            xfer_buffer[xfer_length++] = aks_version;
            if ((NoKeySets >= 2) && (NoKeySets <= 16)) {
                xfer_buffer[xfer_length++] = NoKeySets;
                if ((NoKeySets == 0x10) || (NoKeySets == 18)) {
                    xfer_buffer[xfer_length++] = MaxKeySize;
                } else
                    return false;

                xfer_buffer[xfer_length++] = Aks;
            } else
                return false;
        }
        if (iso_df_name != null) {
            xfer_buffer[xfer_length++] = (byte) (iso_df_id & 0x00FF);
            xfer_buffer[xfer_length++] = (byte) ((iso_df_id >> 8) & 0x00FF);

            if (iso_df_namelen == 0)
                iso_df_namelen = (byte) iso_df_name.length;
            if (iso_df_namelen > 16)
                return false;

            System.arraycopy(iso_df_name, 0, xfer_buffer, xfer_length, iso_df_namelen);
            xfer_length += iso_df_namelen;
        }


        /* Send the command string to the PICC and get its response (1st frame exchange).
           The PICC has to respond with an DF_ADDITIONAL_FRAME status byte. */

        byte[] apdu = new byte[xfer_length+5];
        apdu[0] = (byte) 0x90;
        apdu[1] = xfer_buffer[0];
        apdu[2] = 0x00;
        apdu[3] = 0x00;
        apdu[4] = (byte) (xfer_length - 1);
        System.arraycopy(xfer_buffer, 1, apdu, 5, xfer_length - 1);
        apdu[xfer_length+4] = 0x00;

        this.preprocess(apdu, CommunicationSetting.PLAIN);
        CommandAPDU command = new CommandAPDU(apdu);
        ResponseAPDU response = transmit(command);
        status = response.getSW2();
        feedback(command, response);

        postprocess(response.getBytes(), CommunicationSetting.PLAIN);

        if (status != Response.ADDITIONAL_FRAME.getCode()) {
            return false;
        }

        xfer_length = 0;
        xfer_buffer[xfer_length++] = (byte) Command.MORE.getCode();
        System.arraycopy(EncK, 0, xfer_buffer, 1, EncK.length);
        xfer_length += EncK.length;
        System.arraycopy(Dammac, 0, xfer_buffer, xfer_length, Dammac.length);
        xfer_length += Dammac.length;

        /* Send the 2nd frame to the PICC and get its response. */
        apdu = new byte[xfer_length+5];
        apdu[0] = (byte) 0x90;
        apdu[1] = xfer_buffer[0];
        apdu[2] = 0x00;
        apdu[3] = 0x00;
        apdu[4] = (byte) (xfer_length - 1);
        System.arraycopy(xfer_buffer, 1, apdu, 5, xfer_length - 1);
        apdu[xfer_length+4] = 0x00;

        this.preprocess(apdu, CommunicationSetting.PLAIN);
        command = new CommandAPDU(apdu);
        response = transmit(command);
        status = response.getSW2();
        feedback(command, response);

        return postprocess(response.getBytes(), CommunicationSetting.PLAIN) != null;
    }

    public byte[] GetDelegatedInfo(int DAMSlotNo, int aid, byte dam_slot_version, byte quota_limit, byte free_blocks) {
        long status;
        byte[] responseArray = new byte[6];
        /* Begin the info block with the command code and the number of the key to be changed. */
        xfer_length = 0;
        xfer_buffer[xfer_length++] = CommandEv2.DF_GET_DELEGATED_INFO.getCode();
        xfer_buffer[xfer_length++] = (byte) (DAMSlotNo & 0x00FF);
        DAMSlotNo >>= 8;
        xfer_buffer[xfer_length++] = (byte) (DAMSlotNo & 0x00FF);


        /* Communicate the info block to the card and check the operation's return status. */

        byte[] apdu = new byte[8];
        apdu[0] = (byte) 0x90;
        apdu[1] = xfer_buffer[0];
        apdu[2] = 0x00;
        apdu[3] = 0x00;
        apdu[4] = 0x02;
        apdu[5] = xfer_buffer[1];
        apdu[6] = xfer_buffer[2];
        apdu[7] = 0x00;

        this.preprocess(apdu, CommunicationSetting.PLAIN);
        CommandAPDU command = new CommandAPDU(apdu);
        ResponseAPDU response = transmit(command);
        status = response.getSW2();
        feedback(command, response);

        postprocess(response.getBytes(), CommunicationSetting.PLAIN);

        if (status != Response.OPERATION_OK.getCode()) {
            return null;
        }

        /* Dam slot version. */
        dam_slot_version = response.getBytes()[0];

        /* QuotaLimit. */
        quota_limit = 0;
        quota_limit += response.getBytes()[2];
        quota_limit <<= 8;
        quota_limit += response.getBytes()[1];

        /* FreeBlocks. */
        free_blocks = 0;
        free_blocks += response.getBytes()[4];
        free_blocks <<= 8;
        free_blocks += response.getBytes()[3];

        /* AID. */
        aid = response.getBytes()[7];
        aid <<= 8;
        aid += response.getBytes()[6];
        aid <<= 8;
        aid += response.getBytes()[5];

        byte[] aidArray = DesfireUtils.swapPairsByte(DesfireUtils.hexStringToByteArray(leftPad(Integer.toHexString(aid), 6, '0')));
        System.arraycopy(aidArray, 0, responseArray, 0, 3);
        responseArray[3] = dam_slot_version;
        responseArray[4] = quota_limit;
        responseArray[5] = free_blocks;

        return responseArray;
    }

    public static String leftPad(String originalString, int length,
                                 char padCharacter) {
        String paddedString = originalString;
        while (paddedString.length() < length) {
            paddedString = padCharacter + paddedString;
        }
        return paddedString;
    }

    /**
     * Create a file for the storage of unformatted user data.
     * Memory is allocated in multiples of 32 bytes.
     *
     * @param payload	9-byte array, with the following content:
     * 					<br>file number (1 byte),
     * 					<br>0x1001 (2 bytes LSB),
     * 					<br>communication settings (1 byte),
     * 					<br>access rights (2 bytes LSB),
     * 					<br>file size (3 bytes LSB)
     * @return			{@code true} on success, {@code false} otherwise
     */
    private boolean createIsoStdDataFile(byte[] payload) {
        byte[] apdu = new byte[15];
        apdu[0] = (byte) 0x90;
        apdu[1] = (byte) Command.CREATE_STD_DATA_FILE.getCode();
        apdu[2] = 0x00;
        apdu[3] = 0x00;
        apdu[4] = 0x09;
        System.arraycopy(payload, 0, apdu, 5, 9);
        apdu[14] = 0x00;

        preprocess(apdu, CommunicationSetting.PLAIN);
        CommandAPDU command = new CommandAPDU(apdu);
        ResponseAPDU response = transmit(command);
        feedback(command, response);

        return postprocess(response.getBytes(), CommunicationSetting.PLAIN) != null;
    }

}
