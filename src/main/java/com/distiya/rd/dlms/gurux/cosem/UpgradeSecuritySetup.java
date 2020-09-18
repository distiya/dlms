package com.distiya.rd.dlms.gurux.cosem;

import gurux.common.GXCommon;
import lombok.extern.slf4j.Slf4j;
import org.distiya.protocol.gdlms.GXDLMSClient;
import org.distiya.protocol.gdlms.GXDLMSSettings;
import org.distiya.protocol.gdlms.ValueEventArgs;
import org.distiya.protocol.gdlms.enums.DataType;
import org.distiya.protocol.gdlms.enums.ErrorCode;
import org.distiya.protocol.gdlms.enums.ObjectType;
import org.distiya.protocol.gdlms.objects.*;
import org.distiya.protocol.gdlms.objects.enums.SecuritySuite;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.stream.XMLStreamException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Slf4j
public class UpgradeSecuritySetup extends GXDLMSObject implements IGXDLMSBase {

    public UpgradeSecuritySetup(){
        this("0.0.96.3.0.255");
    }

    public UpgradeSecuritySetup(String ln){
        this(ln,0);
    }

    public UpgradeSecuritySetup(String ln, int sn){
        super(ObjectType.SECURITY_SETUP, ln, sn);
    }

    @Override
    public int[] getAttributeIndexToRead(boolean b) {
        return new int[0];
    }

    @Override
    public final byte[] invoke(GXDLMSSettings settings, ValueEventArgs e) {
        if (e.getIndex() == 1) {
            GXDLMSSecuritySetup securitySetup = (GXDLMSSecuritySetup)e.getServer().getItems().findByLN(ObjectType.SECURITY_SETUP, "0.0.43.0.0.255");
            byte mode = ((Number) e.getParameters()).byteValue();
            if(mode == 0){
                securitySetup.setSecuritySuite(SecuritySuite.AES_GCM_128);
                settings.getCipher().setSecuritySuite(SecuritySuite.AES_GCM_128);
                log.info("The server symmetric shared secret : {}", GXCommon.bytesToHex(settings.getCipher().getSharedSecret()));
                log.info("Set symmetric encryption");
            }
            else if(mode == 1){
                securitySetup.setSecuritySuite(SecuritySuite.ECDHE_CDSA_AES_GCM_256_SHA_384);
                settings.getCipher().setSecuritySuite(SecuritySuite.ECDHE_CDSA_AES_GCM_256_SHA_384);
                log.info("The server asymmetric shared secret : {}", GXCommon.bytesToHex(settings.getCipher().getSharedSecret()));
                log.info("Set asymmetric encryption");
            }
            else{
                e.setError(ErrorCode.READ_WRITE_DENIED);
            }
        } else {
            e.setError(ErrorCode.READ_WRITE_DENIED);
        }
        return null;
    }

    @Override
    public void load(GXXmlReader gxXmlReader) throws XMLStreamException {

    }

    @Override
    public void save(GXXmlWriter gxXmlWriter) throws XMLStreamException {

    }

    @Override
    public void postLoad(GXXmlReader gxXmlReader) {

    }

    public final byte[][] changeSecurityMode(GXDLMSClient client, Byte method) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        return client.method(this, 1, method, DataType.UINT8);
    }

}
