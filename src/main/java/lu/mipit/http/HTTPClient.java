
package lu.mipit.http;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

public class HTTPClient {

    /**
     * Retourne un context SSL initialisé avec les keystores nécessaires pour mySecu.
     *
     * @param SSL_KEYSTORE_PATH le chemin relatif vers le keystore contenant le clef privée du client
     * @param SSL_KEYSTORE_TYPE le type de keystore du client (JKS ou PKCS12)
     * @param SSL_KEYSTORE_PASSWORD le mot de passe pour accéder le keystore du client
     * @param SSL_TRUSTSTORE_PATH le chemin vers le truststore contenant le certificat du serveur mySecu
     * @param SSL_TRUSTSTORE_TYPE le type du truststore (JKS ou PKCS12)
     * @param SSL_TRUSTSTORE_PASSWORD le mot de passe pour accéder le truststore
     * @return le contexte SSL initialisé
     */
    public static final SSLContext getSSLContext(final String SSL_KEYSTORE_PATH, final String SSL_KEYSTORE_TYPE,
                                                 final String SSL_KEYSTORE_PASSWORD, final String SSL_TRUSTSTORE_PATH, final String SSL_TRUSTSTORE_TYPE,
                                                 final String SSL_TRUSTSTORE_PASSWORD) {
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            KeyManager[] keyManagers = null;
            TrustManager[] trustManagers = null;
            if (SSL_KEYSTORE_PATH != null) {
                // 1.) charger un keystore spécifique qui contient la clef privée du client
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory
                        .getDefaultAlgorithm());
                KeyStore keyStore = KeyStore.getInstance(SSL_KEYSTORE_TYPE);
                keyStore.load(new FileInputStream(SSL_KEYSTORE_PATH), SSL_KEYSTORE_PASSWORD.toCharArray());
                keyManagerFactory.init(keyStore, SSL_KEYSTORE_PASSWORD.toCharArray());
                keyManagers = keyManagerFactory.getKeyManagers();
            }
            if (SSL_TRUSTSTORE_PATH != null) {
                // 2.) charger un truststore spécifique qui contient le certificat SSL du serveur mySecu.
                // sinon, le truststore cacerts de la JVM sera utilisé par défaut
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory
                        .getDefaultAlgorithm());
                KeyStore trustStore = KeyStore.getInstance(SSL_TRUSTSTORE_TYPE);
                trustStore.load(new FileInputStream(SSL_TRUSTSTORE_PATH), SSL_TRUSTSTORE_PASSWORD.toCharArray());
                trustManagerFactory.init(trustStore);
            }
            SecureRandom secureRandom = new SecureRandom();
            sc.init(keyManagers, trustManagers, secureRandom);
            return sc;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Retourne une connection HTTP ou HTTPS envers l'URL spécifiée.
     *
     * @param SSL_KEYSTORE_PATH le chemin relatif vers le keystore contenant le clef privée du client
     * @param SSL_KEYSTORE_TYPE le type de keystore du client (JKS ou PKCS12)
     * @param SSL_KEYSTORE_PASSWORD le mot de passe pour accéder le keystore du client
     * @param SSL_TRUSTSTORE_PATH le chemin vers le truststore contenant le certificat du serveur mySecu
     * @param SSL_TRUSTSTORE_TYPE le type du truststore (JKS ou PKCS12)
     * @param SSL_TRUSTSTORE_PASSWORD le mot de passe pour accéder le truststore
     * @return la connection HTTP ou HTTPS
     * @throws IOException
     */
    public static final HttpURLConnection getHTTPConnection(final URL url, final String SSL_KEYSTORE_PATH,
                                                            final String SSL_KEYSTORE_TYPE,
                                                            final String SSL_KEYSTORE_PASSWORD, final String SSL_TRUSTSTORE_PATH, final String SSL_TRUSTSTORE_TYPE,
                                                            final String SSL_TRUSTSTORE_PASSWORD) throws IOException {
        HttpURLConnection connection = null;
        if ("HTTPS".equals(url.getProtocol().toUpperCase())) {
            // 1.) définir le contexte SSL
            HttpsURLConnection httpsConnection = (HttpsURLConnection) url.openConnection();
            httpsConnection.setSSLSocketFactory(HTTPClient.getSSLContext(SSL_KEYSTORE_PATH, SSL_KEYSTORE_TYPE,
                            SSL_KEYSTORE_PASSWORD, SSL_TRUSTSTORE_PATH, SSL_TRUSTSTORE_TYPE, SSL_TRUSTSTORE_PASSWORD)
                    .getSocketFactory());

            // 2.) pour éviter les problèmes de DNS contourner la vérification du common name
            // Attention: à éviter pour les systèmes de production
            // Solution: ajouter l'adresse IP du serveur mySecu au DNS avec CNAME 'ws.mysecu.lu'
            httpsConnection.setHostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String arg0, SSLSession arg1) {
                    return false;
                }
            });
            connection = httpsConnection;
        }
        else {
            if ("HTTP".equals(url.getProtocol().toUpperCase())) {
                // établir une connexion HTTP simple
                connection = (HttpURLConnection) url.openConnection();
            }
            else {
                // d'autres protocoles ne sont pas permis
                throw new IllegalArgumentException();
            }
        }
        connection.addRequestProperty("User-Agent", "mySecu DEMO");
        return connection;
    }

    /**
     * Envoyer une requête GET moyennant la connection fournie.
     *
     * @param urlConnection connexion envers le serveur
     * @return la réponse de la requête GET
     *
     * @throws IOException
     */
    public static final String doGET(final HttpURLConnection urlConnection) throws IOException {
        // 1.) spécifier le verbe HTTP
        urlConnection.setRequestMethod("GET");

        // 2.) connexion vers l'URL
        urlConnection.connect();
        if ("HTTPS".equals(urlConnection.getURL().getProtocol().toUpperCase())) {
            // 3.) récupérer les certificats du serveur
            Certificate[] certificates = ((HttpsURLConnection) urlConnection).getServerCertificates();

            // 4.) récupérer les certificats du client
            certificates = ((HttpsURLConnection) urlConnection).getLocalCertificates();
        }

        // 5.) récupérer le code de retour HTTP
        int responseCode = urlConnection.getResponseCode();
        if (responseCode == 200 || responseCode == 403 ) {
            // 6.) lire le contenu de la réponse
            BufferedReader responseReader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            StringBuffer response = new StringBuffer();
            String inputLine;
            while ((inputLine = responseReader.readLine()) != null) {
                response.append(inputLine);
            }
            responseReader.close();
            return response.toString();
        }
        else {
            System.err.println("Le serveur a réponse avec le code " + responseCode);
            return null;
        }
    }

    /**
     * Envoyer une requête POST d'un document XML moyennant la connecion fournie
     *
     * @param urlConnection connexion envers le serveur
     * @param xml le document XML à télécharger
     * @return la réponse du serveur
     * @throws IOException
     */
    public static final String doPOST(final HttpURLConnection urlConnection, final Document xml) throws IOException {
        // Transformation du message XML en données binaires
        // Attention: veiller à ne pas modifier la syntaxe XML,
        // histoire de ne pas invalider la signature XML éventuelle
        String soapAction = "http://www.oasis-open.org/committees/securityhttp://www.oasis-open.org/committees/security";
        urlConnection.setRequestProperty("SOAPAction", soapAction);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DOMSource source = new DOMSource(xml);
        StreamResult result = new StreamResult(bos);
        try {
            TransformerFactory.newInstance().newTransformer().transform(source, result);
            return HTTPClient.doPOST(urlConnection, bos.toByteArray(), "text/xml;charset=UTF-8");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Envoyer une requête POST moyennant la connexion fournie
     *
     * @param urlConnection connexion envers le serveur
     * @param content le contenu binaire à envoyer
     * @param contentType le type du contenu fourni
     * @return la réponse du serveur
     * @throws IOException
     */
    public static final String doPOST(final HttpURLConnection urlConnection, final byte[] content,
                                      final String contentType) throws IOException {
        // 1.) spécifier le verbe HTTP
        urlConnection.setRequestMethod("POST");

        // 2.)définir le contenu à envoyer
        urlConnection.addRequestProperty("Content-Type", contentType);
        urlConnection.setDoOutput(true);
        DataOutputStream wr = new DataOutputStream(urlConnection.getOutputStream());
        wr.write(content);
        wr.flush();
        wr.close();

        if ("HTTPS".equals(urlConnection.getURL().getProtocol().toUpperCase())) {
            // 3.) afficher les certificats du serveur
            Certificate[] certificates = ((HttpsURLConnection) urlConnection).getServerCertificates();

            // 4.) afficher les certificats du client
            certificates = ((HttpsURLConnection) urlConnection).getLocalCertificates();
        }

        // 5.) récupérer le code de retour HTTP
        int responseCode = urlConnection.getResponseCode();
        if (responseCode == 200) {
            // 6.) lire le contenu de la réponse
            BufferedReader responseReader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
            StringBuffer response = new StringBuffer();
            String inputLine;
            while ((inputLine = responseReader.readLine()) != null) {
                response.append(inputLine);
            }
            responseReader.close();
            return response.toString();
        }
        else {
            System.err.println("Le serveur a réponse avec le code " + responseCode);
            return null;
        }
    }
}