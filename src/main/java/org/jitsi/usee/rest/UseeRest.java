package org.jitsi.usee.rest;

import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

public class UseeRest {

    private final static org.jitsi.utils.logging.Logger logger = org.jitsi.utils.logging.Logger.getLogger(RestConfig.class);

    private RestConfig restConfig;

    private String USEE_CHECK_ROOM_API;

    public UseeRest() {
        restConfig = RestConfig.getInstance();

        USEE_CHECK_ROOM_API = restConfig.USEE_CHECK_ROOM_API;
    }

    public String postRoomCheck(List<NameValuePair> postParam) {

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

            HttpPost postRequest = new HttpPost(USEE_CHECK_ROOM_API);

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
            logger.info("UnsupportedEncodingException Occurred");
            result = null;
        } catch (IOException e) {
            logger.info("IO Exception Occurred");
            result = null;
        } catch (Exception e) {
            logger.info("IO Exception Occurred");
            result = null;
        }
        return result;
    }






}
