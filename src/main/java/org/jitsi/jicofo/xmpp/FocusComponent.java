/*
 * Jicofo, the Jitsi Conference Focus.
 *
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jitsi.jicofo.xmpp;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.HttpParams;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;
import org.apache.http.util.EntityUtils;
import org.eclipse.jetty.http.HttpHeader;
import org.jetbrains.annotations.*;
import org.jitsi.retry.RetryStrategy;
import org.jitsi.retry.SimpleRetryTask;
import org.jitsi.xmpp.extensions.jitsimeet.*;
import org.jitsi.jicofo.*;
import org.jitsi.jicofo.auth.*;
import org.jitsi.jicofo.reservation.*;
import org.jitsi.service.configuration.*;
import org.jitsi.utils.logging.*;
import org.jitsi.xmpp.component.*;
import org.jitsi.xmpp.util.*;

import org.jivesoftware.smack.packet.*;

import org.jivesoftware.whack.ExternalComponentManager;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.jxmpp.jid.*;
import org.xmpp.component.ComponentException;
import org.xmpp.packet.IQ;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static org.apache.commons.lang3.StringUtils.*;

/**
 * XMPP component that listens for {@link ConferenceIq}
 * and allocates {@link org.jitsi.jicofo.JitsiMeetConference}s appropriately.
 *
 * @author Pawel Domas
 */
public class FocusComponent
    extends ComponentBase
{
    /**
     * The logger.
     */
    private final static Logger logger = Logger.getLogger(FocusComponent.class);

    /**
     * Indicates if the focus is anonymous user or authenticated system admin.
     */
    private final boolean isFocusAnonymous;

    /**
     * The JID of focus user that will enter the MUC room. Can be user to
     * recognize real focus of the conference.
     */
    private final String focusAuthJid;

    /**
     * The manager object that creates and expires
     * {@link org.jitsi.jicofo.JitsiMeetConference}s.
     */
    private FocusManager focusManager;

    /**
     * (Optional)Authentication authority used to verify user requests.
     */
    private AuthenticationAuthority authAuthority;

    /**
     * (Optional)Reservation system that manages new rooms allocation.
     * Requires authentication system in order to verify user's identity.
     */
    private ReservationSystem reservationSystem;

    private final Connector connector = new Connector();

    /**
     * Creates new instance of <tt>FocusComponent</tt>.
     */
    public FocusComponent(XmppComponentConfig config, boolean isFocusAnonymous, String focusAuthJid)
    {
        super(config.getHostname(), config.getPort(), config.getDomain(), config.getSubdomain(), config.getSecret());

        this.isFocusAnonymous = isFocusAnonymous;
        this.focusAuthJid = focusAuthJid;
    }

    public void setFocusManager(FocusManager focusManager)
    {
        this.focusManager = focusManager;
    }

    public void setAuthAuthority(AuthenticationAuthority authAuthority)
    {
        this.authAuthority = authAuthority;
    }

    public void setReservationSystem(ReservationSystem reservationSystem)
    {
        this.reservationSystem = reservationSystem;
    }


    public void loadConfig(ConfigurationService config, String configPropertiesBase)
    {
        super.loadConfig(config, configPropertiesBase);
    }

    public void connect()
    {
        if (!isPingTaskStarted())
        {
            startPingTask();
        }

        connector.connect();
    }

    /**
     * Methods will be invoked by OSGi after {@link #dispose()} is called.
     */
    public void disconnect()
    {
        authAuthority = null;
        focusManager = null;
        reservationSystem = null;

        connector.disconnect();
    }

    @Override
    public String getDescription()
    {
        return "Manages Jitsi Meet conferences";
    }

    @Override
    public String getName()
    {
        return "Jitsi Meet Focus";
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected String[] discoInfoFeatureNamespaces()
    {
        return
            new String[]
                {
                    ConferenceIq.NAMESPACE
                };
    }

    @Override
    protected IQ handleIQGetImpl(IQ iq)
        throws Exception
    {
        try
        {
            org.jivesoftware.smack.packet.IQ smackIq = IQUtils.convert(iq);
            if (smackIq instanceof LoginUrlIq)
            {
                org.jivesoftware.smack.packet.IQ result = handleAuthUrlIq((LoginUrlIq) smackIq);
                return IQUtils.convert(result);
            }
            else
            {
                return super.handleIQGetImpl(iq);
            }
        }
        catch (Exception e)
        {
            logger.error(e, e);
            throw e;
        }
    }

    /**
     * Handles an <tt>org.xmpp.packet.IQ</tt> stanza of type <tt>set</tt> which
     * represents a request.
     *
     * @param iq the <tt>org.xmpp.packet.IQ</tt> stanza of type <tt>set</tt>
     * which represents the request to handle
     * @return an <tt>org.xmpp.packet.IQ</tt> stanza which represents the
     * response to the specified request or <tt>null</tt> to reply with
     * <tt>feature-not-implemented</tt>
     * @throws Exception to reply with <tt>internal-server-error</tt> to the
     * specified request
     */
    @Override
    public IQ handleIQSetImpl(IQ iq)
        throws Exception
    {
        logger.info("***** handleIQSetImpl(iq) / iq = "+iq.toString());
        try
        {
            org.jivesoftware.smack.packet.IQ smackIq = IQUtils.convert(iq);
            logger.info("xmpp iq -> smack iq 변환\n ---> "+smackIq);

            if (smackIq instanceof ConferenceIq)
            {
                org.jivesoftware.smack.packet.IQ response = handleConferenceIq((ConferenceIq) smackIq);

                return IQUtils.convert(response);
            }
            else if (smackIq instanceof LogoutIq)
            {
                logger.info("Logout IQ received: " + iq.toXML());

                if (authAuthority == null)
                {
                    // not-implemented
                    return null;
                }

                org.jivesoftware.smack.packet.IQ smackResult = authAuthority.processLogoutIq((LogoutIq) smackIq);

                return smackResult != null ? IQUtils.convert(smackResult) : null;
            }
            else
            {
                return super.handleIQSetImpl(iq);
            }
        }
        catch (Exception e)
        {
            logger.error(e, e);
            throw e;
        }
    }

    /**
     * Additional logic added for conference IQ processing like authentication and room reservation.
     *
     * @param query <tt>ConferenceIq</tt> query
     * @param response <tt>ConferenceIq</tt> response which can be modified during this processing.
     * @param roomExists <tt>true</tt> if room mentioned in the <tt>query</tt> already exists.
     *
     * @return <tt>null</tt> if everything went ok or an error/response IQ
     *         which should be returned to the user
     */
    public org.jivesoftware.smack.packet.IQ processExtensions(
            ConferenceIq query, ConferenceIq response, boolean roomExists)
    {
        Jid peerJid = query.getFrom();
        String identity = null;

        // Authentication
        if (authAuthority != null)
        {
            org.jivesoftware.smack.packet.IQ authErrorOrResponse = authAuthority.processAuthentication(query, response);

            // Checks if authentication module wants to cancel further
            // processing and eventually returns it's response
            if (authErrorOrResponse != null)
            {
                return authErrorOrResponse;
            }
            // Only authenticated users are allowed to create new rooms
            if (!roomExists)
            {
                identity = authAuthority.getUserIdentity(peerJid);
                if (identity == null)
                {
                    // Error not authorized
                    return ErrorFactory.createNotAuthorizedError(query, "not authorized user domain");
                }
            }
        }

        // Check room reservation?
        if (!roomExists && reservationSystem != null)
        {
            EntityBareJid room = query.getRoom();

            ReservationSystem.Result result = reservationSystem.createConference(identity, room);

            logger.info("Create room result: " + result + " for " + room);

            if (result.getCode() != ReservationSystem.RESULT_OK)
            {
                return ErrorFactory.createReservationError(query, result);
            }
        }

        return null;
    }

    @NotNull
    private org.jivesoftware.smack.packet.IQ handleConferenceIq(
            ConferenceIq query)
        throws Exception
    {
        logger.info("***** handleConferenceIq(query) / query = " + query);

        ConferenceIq response = new ConferenceIq();
        EntityBareJid room = query.getRoom();

        logger.info("Focus request for room: " + room);

        List<NameValuePair> postParams = new ArrayList<NameValuePair>();
        //postParams.add(new BasicNameValuePair("room", "eyJhbGciOiJIUzI1NiJ9.eyJyb29tX2lkIjoiZWQ4NTAwMmEtMzMwMC00ZWY0LWJiMjUtNzVkMzc1ZTRiZjc2IiwiaWF0IjoxNjA5OTA5MDY5LCJleHAiOjE2MDk5MTI2Njl9.UVKoUejS5IykqX6pycf7KK5ig62UL56K4H82wShOE-E"));
        postParams.add(new BasicNameValuePair("room", room.getLocalpart().toString()));

        String resultStr = restPost("https://10.0.0.16:8080/Room/Check/RoomToken/Test", postParams);

        log.info("===================" + resultStr);

        if(resultStr.equals("fail")) {
            response.setType(org.jivesoftware.smack.packet.IQ.Type.result);
            response.setStanzaId(query.getStanzaId());
            response.setFrom(query.getTo());
            response.setTo(query.getFrom());
            response.setRoom(query.getRoom());
            response.setReady(false);

            response.setFocusJid(focusAuthJid);
            response.addProperty(
                    new ConferenceIq.Property(
                            "authentication",
                            String.valueOf(authAuthority != null)));

            if (authAuthority != null)
            {
                response.addProperty(
                        new ConferenceIq.Property(
                                "externalAuth",
                                String.valueOf(authAuthority.isExternal())));
            }

            if (focusManager.getJitsiMeetServices().getJigasiDetector() != null)
            {
                response.addProperty(new ConferenceIq.Property("sipGatewayEnabled", "true"));
            }

            return response;
        }

        boolean roomExists = focusManager.getConference(room) != null;
        logger.info("roomExists = "+roomExists);

        // Authentication and reservations system logic
        org.jivesoftware.smack.packet.IQ error = processExtensions(query, response, roomExists);
        if (error != null)
        {
            return error;
        }

        boolean ready = focusManager.conferenceRequest(room, query.getPropertiesMap());
        logger.info("ready = " + ready);

        if (!isFocusAnonymous && authAuthority == null)
        {
            // Focus is authenticated system admin, so we let them in
            // immediately. Focus will get OWNER anyway.
            logger.info("(!isFocusAnonymous && authAuthority == null) == true면 ready = true;");
            ready = true;
        }

        response.setType(org.jivesoftware.smack.packet.IQ.Type.result);
        response.setStanzaId(query.getStanzaId());
        response.setFrom(query.getTo());
        response.setTo(query.getFrom());
        response.setRoom(query.getRoom());
        response.setReady(ready);

        // Config
        response.setFocusJid(focusAuthJid);

        // Authentication module enabled?
        response.addProperty(
            new ConferenceIq.Property(
                    "authentication",
                    String.valueOf(authAuthority != null)));

        if (authAuthority != null)
        {
            response.addProperty(
                new ConferenceIq.Property(
                        "externalAuth",
                        String.valueOf(authAuthority.isExternal())));
        }

        if (focusManager.getJitsiMeetServices().getJigasiDetector() != null)
        {
            response.addProperty(new ConferenceIq.Property("sipGatewayEnabled", "true"));
        }

        logger.info("response = " + response);
        return response;
    }

    private String restPost(String requestURL, List<NameValuePair> postParam) {

        String result = null;

        try {
            TrustStrategy acceptingTrustStrategy = (X509Certificate[] chain, String authType) -> true;

            SSLContext sslContext = SSLContexts.custom().loadTrustMaterial(acceptingTrustStrategy).build();

            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
              sslContext,
              new String[] {"TLSv1", "TLSv1.1", "TLSv1.2"},
              null,
              SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);


            CloseableHttpClient httpClient = HttpClients.custom()
                    .setSSLSocketFactory(sslsf)
                    .build();

            HttpPost postRequest = new HttpPost(requestURL);

            HttpEntity httpEntity = new UrlEncodedFormEntity(postParam, "UTF8");

            postRequest.setEntity(httpEntity);
            CloseableHttpResponse response = httpClient.execute(postRequest);


            if(response.getStatusLine().getStatusCode() == 200) {

                ResponseHandler<String> handler = new BasicResponseHandler();
                String body = handler.handleResponse(response);

                JSONParser jsonParser = new JSONParser();
                Object obj = jsonParser.parse(body);
                JSONObject jsonObject = (JSONObject) obj;

                String state = (String) jsonObject.get("state");
                String msg = (String) jsonObject.get("msg");
                String roomName = (String) jsonObject.get("roomName");

                result = state;
            } else {
                result = null;
            }

        } catch (UnsupportedEncodingException e) {
            log.info("UnsupportedEncodingException Occurred");
            result = null;
        } catch (IOException e) {
            log.info("IO Exception Occurred");
            result = null;
        } catch (Exception e) {
            log.info("IO Exception Occurred");
            result = null;
        } 
        return result;
    }


    private org.jivesoftware.smack.packet.IQ handleAuthUrlIq(
            LoginUrlIq authUrlIq)
    {
        if (authAuthority == null)
        {
            XMPPError.Builder error = XMPPError.getBuilder(XMPPError.Condition.service_unavailable);
            return org.jivesoftware.smack.packet.IQ.createErrorResponse(authUrlIq, error);
        }

        EntityFullJid peerFullJid = authUrlIq.getFrom().asEntityFullJidIfPossible();
        EntityBareJid roomName = authUrlIq.getRoom();
        if (roomName == null)
        {
            XMPPError.Builder error = XMPPError.getBuilder(XMPPError.Condition.not_acceptable);
            return org.jivesoftware.smack.packet.IQ.createErrorResponse(authUrlIq, error);
        }

        LoginUrlIq result = new LoginUrlIq();
        result.setType(org.jivesoftware.smack.packet.IQ.Type.result);
        result.setStanzaId(authUrlIq.getStanzaId());
        result.setTo(authUrlIq.getFrom());

        boolean popup = authUrlIq.getPopup() != null && authUrlIq.getPopup();

        String machineUID = authUrlIq.getMachineUID();
        if (isBlank(machineUID))
        {
            XMPPError.Builder error
                = XMPPError.from(
                    XMPPError.Condition.bad_request,
                    "missing mandatory attribute 'machineUID'");
            return org.jivesoftware.smack.packet.IQ.createErrorResponse(authUrlIq, error);
        }

        String authUrl = authAuthority.createLoginUrl(machineUID, peerFullJid, roomName, popup);

        result.setUrl(authUrl);

        logger.info("Sending url: " + result.toXML());

        return result;
    }

    /**
     * The code responsible for connecting FocusComponent to the XMPP server.
     */
    private class Connector {
        private ExternalComponentManager componentManager;
        private ScheduledExecutorService executorService;
        private RetryStrategy connectRetry;
        private final Object connectSynRoot = new Object();

        void connect()
        {
            componentManager = new ExternalComponentManager(getHostname(), getPort(), false);
            componentManager.setSecretKey(getSubdomain(), getSecret());
            componentManager.setServerName(getDomain());

            executorService = Executors.newScheduledThreadPool(1);

            init();

            connectRetry = new RetryStrategy(executorService);
            connectRetry.runRetryingTask(new SimpleRetryTask(0, 5000, true, () -> {
                try
                {
                    synchronized (connectSynRoot)
                    {
                        if (componentManager == null)
                        {
                            // Task cancelled ?
                            return false;
                        }

                        componentManager.addComponent(getSubdomain(), FocusComponent.this);

                        return false;
                    }
                }
                catch (ComponentException e)
                {
                    logger.error(e.getMessage() + ", host:" + getHostname() + ", port:" + getPort(), e);
                    return true;
                }
            }));
        }

        void disconnect()
        {
            synchronized (connectSynRoot)
            {
                if (componentManager == null)
                {
                    return;
                }

                if (connectRetry != null)
                {
                    connectRetry.cancel();
                    connectRetry = null;
                }

                if (executorService != null)
                {
                    executorService.shutdown();
                }

                shutdown();
                try
                {
                    componentManager.removeComponent(getSubdomain());
                }
                catch (ComponentException e)
                {
                    logger.error(e, e);
                }

                dispose();

                componentManager = null;
            }
        }
    }
}
