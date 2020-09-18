package com.distiya.rd.dlms.gurux.client;

import com.distiya.rd.dlms.gurux.cosem.UpgradeSecuritySetup;
import gurux.common.GXCommon;
import gurux.common.IGXMedia;
import gurux.common.ReceiveParameters;
import gurux.net.GXNet;
import gurux.net.enums.NetworkType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.distiya.protocol.gdlms.*;
import org.distiya.protocol.gdlms.asn.GXAsn1Converter;
import org.distiya.protocol.gdlms.asn.GXPkcs10;
import org.distiya.protocol.gdlms.asn.GXx509Certificate;
import org.distiya.protocol.gdlms.asn.enums.KeyUsage;
import org.distiya.protocol.gdlms.enums.*;
import org.distiya.protocol.gdlms.objects.GXDLMSObject;
import org.distiya.protocol.gdlms.objects.GXDLMSRegister;
import org.distiya.protocol.gdlms.objects.GXDLMSSecuritySetup;
import org.distiya.protocol.gdlms.objects.enums.CertificateType;
import org.distiya.protocol.gdlms.objects.enums.GlobalKeyType;
import org.distiya.protocol.gdlms.objects.enums.SecuritySuite;
import org.distiya.protocol.gdlms.secure.GXDLMSSecureClient;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Slf4j
public class GuruxClient {

    private GXDLMSSecureClient client;
    private GXDLMSSecuritySetup securitySetup;
    private UpgradeSecuritySetup upgradeSecuritySetup;
    private IGXMedia media;
    private Integer waitTime = 86400000;
    //private Integer waitTime = 10000;

    public GuruxClient() throws Exception {

        this.securitySetup = new GXDLMSSecuritySetup();
        this.upgradeSecuritySetup = new UpgradeSecuritySetup();
        this.media = new GXNet(NetworkType.TCP,"127.0.0.1",4063);
        this.client = new GXDLMSSecureClient(true,1,1, Authentication.HIGH_GMAC,"Gurux", InterfaceType.WRAPPER);
        this.client.getCiphering().setSecurity(Security.ENCRYPTION);
        this.client.setSecuritySuite(SecuritySuite.ECDHE_CDSA_AES_GCM_256_SHA_384);
        this.client.getCiphering().setSystemTitle(GXCommon.hexToBytes("6D4D4D0000BC614E"));
        this.client.setServerSystemTitle(GXCommon.hexToBytes("6D4D4D0000BC614E"));
        this.client.getCiphering().setRecipientSystemTitle(GXCommon.hexToBytes("3D4D4D0000000001"));

        this.client.getCiphering().setAuthenticationKey(GXCommon.hexToBytes("A0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"));
        this.client.getCiphering().setBlockCipherKey(GXCommon.hexToBytes("100102030405060708090A0B0C0D0E0F"));
        this.client.getProposedConformance().add(Conformance.GENERAL_PROTECTION);
        this.client.getProposedConformance().add(Conformance.GENERAL_BLOCK_TRANSFER);
        this.media.open();
        try{
            initializeConnection();
            exchangeClientCertificate();
            upgradeSecurity();
            readObjects();
        }
        finally {
            close();
        }
    }

    private void initializeConnection() throws Exception{
        GXReplyData reply = new GXReplyData();
        readDataBlock(this.client.aarqRequest(),reply);
        this.client.parseAareResponse(reply.getData());
        reply.clear();
        if(this.client.getAuthentication().getValue() > Authentication.LOW.getValue()){
            for(byte[] it : this.client.getApplicationAssociationRequest()){
                readDLMSPacket(it,reply);
            }
            client.parseApplicationAssociationResponse(reply.getData());
        }
    }

    private void exchangeClientCertificate() throws Exception{
        Map<CertificateType, PublicKey> publicKeyMap = new HashMap<>();
        KeyPair signingKeyPair = GXAsn1Converter.generateKeyPair();
        KeyPair agreementKeyPair = GXAsn1Converter.generateKeyPair();
        KeyPair ephemeralKeyPair = GXAsn1Converter.generateKeyPair();
        GXReplyData reply = new GXReplyData();
        Date from = new Date();
        Date to = new Date(from.getTime() + 365L * 24L * 60L * 60L * 1000L);

        GXx509Certificate clientSigningCertificate = GXx509Certificate
                .createSelfSignedCertificate(signingKeyPair, from,
                        to, this.client.getCiphering().getSystemTitle(),
                        "CN=Test, O=Gurux, L=Tampere, C=FI", KeyUsage.forValue(
                                (KeyUsage.DIGITAL_SIGNATURE.getValue())));

        GXx509Certificate clientKeyAgreementCertificate = GXx509Certificate
                .createSelfSignedCertificate(agreementKeyPair, from,
                        to, this.client.getCiphering().getSystemTitle(),
                        "CN=Test, O=Gurux, L=Tampere, C=FI", KeyUsage.forValue(
                                (KeyUsage.KEY_AGREEMENT.getValue())));


        byte[][] certSigningBytes = this.securitySetup.importCertificate(this.client, clientSigningCertificate); //6
        readDataBlock(certSigningBytes,reply);
        reply.clear();

        byte[][] certAgreementBytes = this.securitySetup.importCertificate(this.client, clientKeyAgreementCertificate); //6
        readDataBlock(certAgreementBytes,reply);
        reply.clear();

        CertificateDataHolder serverKeyAgreementCertificateData = generateServerKeyPairs("CN=Test, O=Gurux, L=Tampere, C=FI", reply, CertificateType.KEY_AGREEMENT, from, to, agreementKeyPair);
        CertificateDataHolder serverKeySigningCertificateData = generateServerKeyPairs("CN=Test, O=Gurux, L=Tampere, C=FI", reply, CertificateType.DIGITAL_SIGNATURE, from, to, signingKeyPair);

        reply.clear();

        this.client.getCiphering().setSigningKeyPair(signingKeyPair);
        this.client.getCiphering().setEphemeralKeyPair(ephemeralKeyPair);

        byte[][] keyAgreement = this.securitySetup.keyAgreement(this.client, GlobalKeyType.UNICAST_ENCRYPTION);//3
        readDataBlock(keyAgreement,reply);
        this.client.getData(reply.getData(),reply);
        this.client.getSharedSecret((byte[])reply.getValue(),serverKeySigningCertificateData.getPublicKeyData().getPublicKey());

        this.client.getCiphering().setKeyAgreementKeyPair(agreementKeyPair);

        this.client.getCiphering().getCertificates().add(serverKeyAgreementCertificateData.getCertificateData());
        this.client.getCiphering().getCertificates().add(serverKeySigningCertificateData.getCertificateData());
        this.client.getCiphering().getCertificates().add(clientSigningCertificate);
        this.client.getCiphering().getCertificates().add(clientKeyAgreementCertificate);

        publicKeyMap.put(CertificateType.KEY_AGREEMENT,serverKeyAgreementCertificateData.getPublicKeyData().getPublicKey());

        this.client.getCiphering().getPublicKeys().addAll(publicKeyMap.entrySet());

        reply.clear();

    }

    private void upgradeSecurity() throws Exception{
        byte[][] upgradeSecurityBytes = this.upgradeSecuritySetup.changeSecurityMode(this.client, (byte) 1);
        GXReplyData reply = new GXReplyData();
        log.info("The client shared secret : {}", GXCommon.bytesToHex(this.client.getCiphering().getSharedSecret()));
        readDataBlock(upgradeSecurityBytes,reply);
        reply.clear();
    }

    private void readObjects() throws Exception {
        GXDLMSRegister temperatureRegister = new GXDLMSRegister("0.0.96.8.0.255");
        Object result = read(temperatureRegister, 2);
        log.info("The value is {}",result.toString());
    }

    void close() throws Exception {
        if (this.media != null && this.media.isOpen()) {
            GXReplyData reply = new GXReplyData();
            try {
                // Release is call only for secured connections.
                // All meters are not supporting Release and it's causing
                // problems.
                if (this.client.getInterfaceType() == InterfaceType.WRAPPER
                        || (this.client.getInterfaceType() == InterfaceType.HDLC
                        && this.client.getCiphering()
                        .getSecurity() != Security.NONE)) {
                    readDataBlock(this.client.releaseRequest(), reply);
                }
            } catch (Exception e) {
                // All meters don't support release.
            }
            reply.clear();
            readDLMSPacket(this.client.disconnectRequest(), reply);
            this.client.getCiphering().reset();
            this.media.close();
            log.info("The client got disconnected by invoking client's close method");
        }
    }

    private CertificateDataHolder generateServerKeyPairs(String issuer,GXReplyData reply, CertificateType certificateType, Date from, Date to, KeyPair signingKeyPair) throws Exception{
        reply.clear();
        byte[][] keyCreateRequestBytes = this.securitySetup.generateKeyPair(this.client, certificateType);// 4
        readDataBlock(keyCreateRequestBytes,reply);
        reply.clear();

        byte[][] certificateCreateRequestBytes = this.securitySetup.generateCertificate(this.client, certificateType); //5
        readDataBlock(certificateCreateRequestBytes,reply);

        this.client.getData(reply.getData(), reply);
        GXPkcs10 cert = new GXPkcs10((byte[]) reply.getValue());

        reply.clear();

        GXx509Certificate serverCertificate = GXx509Certificate.createSelfSignedCertificate(
                signingKeyPair,
                from,
                to,
                cert.getSubject(),
                issuer,
                convertCertificateTypeToKeyUsage(certificateType)
        );
        byte[][] serverCertificateBytes = this.securitySetup.importCertificate(this.client, serverCertificate);
        readDataBlock(serverCertificateBytes,reply);
        reply.clear();
        return new CertificateDataHolder(cert,serverCertificate);
    }

    private Set<KeyUsage> convertCertificateTypeToKeyUsage(CertificateType certificateType){
        switch (certificateType){
            case DIGITAL_SIGNATURE: return KeyUsage.forValue(KeyUsage.DIGITAL_SIGNATURE.getValue());
            case KEY_AGREEMENT:
            default:
                return KeyUsage.forValue(KeyUsage.KEY_AGREEMENT.getValue());
        }
    }

    void readDataBlock(byte[][] data, GXReplyData reply) throws Exception {
        if (data != null) {
            for (byte[] it : data) {
                reply.clear();
                readDataBlock(it, reply);
            }
        }
    }

    void readDataBlock(byte[] data, GXReplyData reply) throws Exception {
        if (data != null && data.length != 0) {
            readDLMSPacket(data, reply);
            while (reply.isMoreData()) {
                if (reply.isStreaming()) {
                    data = null;
                } else {
                    data = this.client.receiverReady(reply);
                }
                readDLMSPacket(data, reply);
            }
        }
    }

    public void readDLMSPacket(byte[][] data) throws Exception {
        GXReplyData reply = new GXReplyData();
        for (byte[] it : data) {
            reply.clear();
            readDLMSPacket(it, reply);
        }
    }

    public void readDLMSPacket(byte[] data, GXReplyData reply)
            throws Exception {
        if (!reply.getStreaming() && (data == null || data.length == 0)) {
            return;
        }
        GXReplyData notify = new GXReplyData();
        reply.setError((short) 0);
        Object eop = (byte) 0x7E;
        // In network connection terminator is not used.
        if (this.client.getInterfaceType() == InterfaceType.WRAPPER
                && this.media instanceof GXNet) {
            eop = null;
        }
        Integer pos = 0;
        boolean succeeded = false;
        ReceiveParameters<byte[]> p =
                new ReceiveParameters<byte[]>(byte[].class);
        p.setEop(eop);
        if (this.client.getInterfaceType() == InterfaceType.WRAPPER) {
            p.setCount(8);
        } else {
            p.setCount(5);
        }
        p.setWaitTime(waitTime);
        GXByteBuffer rd = new GXByteBuffer();
        synchronized (this.media.getSynchronous()) {
            while (!succeeded) {
                if (!reply.isStreaming()) {
                    this.media.send(data, null);
                }
                if (p.getEop() == null) {
                    p.setCount(1);
                }
                succeeded = this.media.receive(p);
                if (!succeeded) {
                    if (p.getEop() == null) {
                        p.setCount(this.client.getFrameSize(rd));
                    }
                    // Try to read again...
                    if (pos++ == 3) {
                        throw new RuntimeException(
                                "Failed to receive reply from the device in given time.");
                    }
                    System.out.println("Data send failed. Try to resend "
                            + pos.toString() + "/3");
                }
            }
            rd = new GXByteBuffer(p.getReply());
            int msgPos = 0;
            // Loop until whole DLMS packet is received.
            try {
                while (!this.client.getData(rd, reply, notify)) {
                    p.setReply(null);
                    if (notify.getData().getData() != null) {
                        // Handle notify.
                        if (!notify.isMoreData()) {
                            // Show received push message as XML.
                            GXDLMSTranslator t = new GXDLMSTranslator(
                                    TranslatorOutputType.SIMPLE_XML);
                            String xml = t.dataToXml(notify.getData());
                            System.out.println(xml);
                            notify.clear();
                            msgPos = rd.position();
                        }
                        continue;
                    }

                    if (p.getEop() == null) {
                        int frameSize = this.client.getFrameSize(rd);
                        p.setCount(frameSize);
                    }
                    while (!this.media.receive(p)) {
                        // If echo.
                        if (reply.isEcho()) {
                            this.media.send(data, null);
                        }
                        // Try to read again...
                        if (++pos == 3) {
                            throw new Exception(
                                    "Failed to receive reply from the device in given time.");
                        }
                        System.out.println("Data send failed. Try to resend "
                                + pos.toString() + "/3");
                    }
                    rd.position(msgPos);
                    rd.set(p.getReply());
                }
            } catch (Exception e) {
                throw e;
            }
        }
        if (reply.getError() != 0) {
            if (reply.getError() == ErrorCode.REJECTED.getValue()) {
                Thread.sleep(1000);
                readDLMSPacket(data, reply);
            } else {
                throw new GXDLMSException(reply.getError());
            }
        }
    }

    Object read(GXDLMSObject item, int attributeIndex) throws Exception{
        byte[] data = this.client.read(item.getName(), item.getObjectType(), attributeIndex)[0];
        GXReplyData reply = new GXReplyData();
        readDataBlock(data,reply);
        if(item.getDataType(attributeIndex) == DataType.NONE){
            item.setDataType(attributeIndex, reply.getValueType());
        }
        return reply.getValue();
    }

    @AllArgsConstructor
    @NoArgsConstructor
    @Setter
    @Getter
    class CertificateDataHolder{
        private GXPkcs10 publicKeyData;
        private GXx509Certificate certificateData;
    }


    public static void main(String as[]) throws Exception {
        GuruxClient guruxClient = new GuruxClient();
    }
}
