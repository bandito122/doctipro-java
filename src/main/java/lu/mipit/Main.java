package lu.mipit;

import lu.ciss.mysecu.demo.XmlTools;
import lu.ciss.mysecu.demo.wsse.XmlDSig_Java;
import lu.ciss.mysecu.demo.wsse.XmlDSig_OpenSAML;
import lu.mipit.http.HTTPClient;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import lu.mipit.utils.FichierConfig;
import org.w3c.dom.Document;

import javax.xml.soap.SOAPMessage;

public class Main {

    public static void main(String[] args) throws IOException {

        // Déclaration des variables de classe
        String serverUrl = FichierConfig.getProperty("serverUrl");
        String keyStorePath = FichierConfig.getProperty("keyStorePath");
        String keyStoreType = FichierConfig.getProperty("keyStoreType");
        String keyStorePassword = FichierConfig.getProperty("keyStorePassword");
        String trustStorePath = FichierConfig.getProperty("trustStorePath");
        String trustStoreType = FichierConfig.getProperty("trustStoreType");
        String trustStorePassword = FichierConfig.getProperty("trustStorePassword");
        String xml = FichierConfig.getProperty("xml");
        String privateKey_alias = FichierConfig.getProperty("privateKeyAlias");


        // Print the values to verify
        System.out.println("url=" + serverUrl);
        System.out.println("keyStorePath=" + keyStorePath);
        System.out.println("keyStoreType=" + keyStoreType);
        System.out.println("keyStorePassword=" + keyStorePassword);
        System.out.println("trustStorePath=" + trustStorePath);
        System.out.println("trustStoreType=" + trustStoreType);
        System.out.println("trustStorePassword=" + trustStorePassword);
        System.out.println("xml=" + xml);


        // Création de l'URL de connexion
        URL url = new URL(serverUrl);
        System.out.println("URL spécifiée:" + url);

        HttpURLConnection connection = HTTPClient.getHTTPConnection(url, keyStorePath, keyStoreType,
                keyStorePassword, trustStorePath, trustStoreType, trustStorePassword);



        // Création du binary Security token

        //avec les libs opensaml
        Document xmlDocument = XmlTools.loadFromFile(xml);
        xmlDocument.normalize();
        SOAPMessage message = XmlTools.convertToSoapMessage(xmlDocument);
        xmlDocument = XmlDSig_OpenSAML.signBody(xmlDocument, keyStorePath,keyStoreType, keyStorePassword, privateKey_alias);
        System.out.println(XmlTools.toPrettyString(xmlDocument.getDocumentElement()));

        // avec les lib java
        xmlDocument = XmlTools.loadFromFile(xml);
        xmlDocument.normalize();
        message = XmlTools.convertToSoapMessage(xmlDocument);
        message = XmlDSig_Java.signBody(message, keyStorePath,keyStoreType, keyStorePassword, privateKey_alias);
        xmlDocument = XmlTools.convertToDocument(message);
        System.out.println(XmlTools.toPrettyString(xmlDocument.getDocumentElement()));

        String resultat = HTTPClient.doGET(connection);
        if (resultat != null) {
            System.out.println("Réponse du serveur:");
            System.out.println(resultat);
        } else {
            System.exit(1);
        }
        System.exit(0);
    }
}
