package com.distiya.rd.dlms.gurux.server;


import org.distiya.protocol.gdlms.enums.InterfaceType;
import org.distiya.protocol.gdlms.objects.GXDLMSAssociationLogicalName;

/**
 * DLMS Server that uses Logical Name referencing with IEC 62056-47 COSEM
 * transport layers for IPv4 networks. Example Iskraemeco uses this. Note! For
 * serial port communication is used GXDLMSServerLN.
 */
public class GXDLMSServerLN_47 extends GXDLMSBase {
    public GXDLMSServerLN_47() {
        super(new GXDLMSAssociationLogicalName(), InterfaceType.WRAPPER);
    }
}
