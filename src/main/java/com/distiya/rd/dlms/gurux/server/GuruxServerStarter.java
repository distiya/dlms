package com.distiya.rd.dlms.gurux.server;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class GuruxServerStarter {

    public static void main(String[] args) throws Exception {
        try {
            {
                GXDLMSServerLN_47 LN_47Server = new GXDLMSServerLN_47();
                LN_47Server.initialize(4063);
                log.info("DLMS Server started");
                int i = 0;
                while (true) {
                    i = 1;
                }
            }
        } catch (RuntimeException ex) {
            log.error("Error Starting Server");
            throw ex;
        }
    }
}
