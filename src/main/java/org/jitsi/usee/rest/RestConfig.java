package org.jitsi.usee.rest;

import org.jitsi.jicofo.xmpp.FocusComponent;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.logging.Logger;

public class RestConfig {

    private final static org.jitsi.utils.logging.Logger logger = org.jitsi.utils.logging.Logger.getLogger(RestConfig.class);

    public Properties prop;

    public String USEE_CHECK_ROOM_API;

    private RestConfig() {
        try(InputStream in = new FileInputStream("./usee.rest.config.properties")) {
            prop = new Properties();

            prop.load(in);

            logger.info("Usee.Admin Propertie Check : " + prop.getProperty("usee.admin.basic.url"));

            USEE_CHECK_ROOM_API = prop.getProperty("url", "usee.admin.basic") +
                    prop.getProperty("room_api", "usee.admin.basic") +
                    prop.getProperty("room", "usee.admin.basic.room_api.check");

        } catch (FileNotFoundException e) {
            logger.info("Can't find usee.rest.config.properties file");
        } catch (IOException e) {
            logger.info("IO exception Occurred");
        }
    }

    private static class InnerInstanceClazz {
        private static final RestConfig uniqueInstance = new RestConfig();
    }

    public static RestConfig getInstance() {
        return InnerInstanceClazz.uniqueInstance;
    }
}
