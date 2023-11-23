/*
 * XMLDSig.java
 * Date de cr�ation: 15 juin 2015
 * Auteur: u156gm
 *
 * Copyright (c) 2015 by CISS
 *
 * Modifications:
 * --------------
 *
 * Notes:
 * ------
 *
 */

package lu.ciss.mysecu.demo.inttest;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import lu.ciss.mysecu.demo.wsse.HTTPClient;
import org.apache.xml.security.signature.XMLSignatureException;
import org.opensaml.xml.ConfigurationException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import lu.ciss.mysecu.demo.XmlTools;
import lu.ciss.mysecu.demo.wsse.HTTPClient;
import lu.ciss.mysecu.demo.wsse.XmlDSig_Java;
import lu.ciss.mysecu.demo.wsse.XmlDSig_OpenSAML;

/**
 * D�monstration du test d'int�gration "dsig" de mySecu
 *
 * Il s'agit de tester l'int�gration de la signature XML technique
 *
 * ATTENTION:
 * IL S'AGIT D'UN PROJET DE DEMONSTRATION. IL EST DECONSEILE DE L'UTILISER EN PRODUCTION.
 *
 * Les arguments suivants sont � fournir:
 * <ol>
     * <li> args[0]: l'URL compl�te du serveur </li>
     * <li> args[1]: le chemin vers le keystore contenant la clef priv�e du client </li>
     * <li> args[2]: le type du keystore (JKS || PKCS12) </li>
     * <li> args[3]: le mot de passe pour ouvrir le keystore </li>
     * <li> args[4]: le chemin vers le truststore contenant le certificat du serveur mySecu </li>
     * <li> args[5]: le type du truststore (JKS || PKCS12) </li>
     * <li> args[6]: le mot de passe pour ouvrir le truststore </li>
     * <li> args[7]: l'alias de la clef priv�e dans le keystore </li>
     * <li> args[8]: chemin vers le fichier contenant le message SOAP � envoyer
     * </ol>
 *
 * @author u156gm
 * @version $Id: XMLDSig.java 16672 2015-06-30 14:26:21Z u156gm $
 * @since REL_1-0-0
 */
public class XMLDSig {

    public static void printHeader() {
        System.out.println("*********************************************");
        System.out.println("mySecu D�monstration: Tests d'int�gration");
        System.out.println("/ws/soap/inttest/dsig");
        System.out.println("*********************************************");
    }

    /**
     * <ol>
     * <li> args[0]: l'URL compl�te du serveur </li>
     * <li> args[1]: le chemin vers le keystore contenant la clef priv�e du client </li>
     * <li> args[2]: le type du keystore (JKS || PKCS12) </li>
     * <li> args[3]: le mot de passe pour ouvrir le keystore </li>
     * <li> args[4]: le chemin vers le truststore contenant le certificat du serveur mySecu </li>
     * <li> args[5]: le type du truststore (JKS || PKCS12) </li>
     * <li> args[6]: le mot de passe pour ouvrir le truststore </li>
     * <li> args[7]: l'alias de la clef priv�e dans le keystore </li>
     * <li> args[8]: chemin vers le fichier contenant le message SOAP � envoyer
     * </ol>
     *
     * @param args
     * @throws IOException
     * @throws SAXException
     * @throws ParserConfigurationException
     * @throws XMLSignatureException
     * @throws ConfigurationException
     * @throws SOAPException
     * @throws TransformerFactoryConfigurationError
     * @throws TransformerException
     * @throws TransformerConfigurationException
     */
    public static void main(String[] args) throws IOException, SAXException, ParserConfigurationException,
            XMLSignatureException, ConfigurationException, SOAPException, TransformerConfigurationException,
            TransformerException, TransformerFactoryConfigurationError {

        printHeader();

        // 1.) cr�ation de l'URL de connexion
        URL url = new URL(args[0]);
        System.out.println("URL sp�cifi�e:" + url);
        System.out.println("Message SOAP sp�cifi�: " + args[8]);

        // 2.) chargement du message SOAP � envoyer
        Document xmlDocument = XmlTools.loadFromFile(args[8]);
        xmlDocument.normalize();

        // 3.) g�n�ration de la signature avec les API de Java
        System.out.println("******************************************************");
        System.out.println("Via les API de Java");
        System.out.println("******************************************************");
        SOAPMessage message = XmlTools.convertToSoapMessage(xmlDocument);
        message = XmlDSig_Java.signBody(message, args[1], args[2], args[3], args[7]);
        xmlDocument = XmlTools.convertToDocument(message);
        System.out.println("Le message SOAP suivant est envoy� au serveur:");
        System.out.println(XmlTools.toPrettyString(xmlDocument.getDocumentElement()));
        HttpURLConnection connection = HTTPClient.getHTTPConnection(url, args[1], args[2],
                args[3], args[4], args[5], args[6]);
        String resultat = HTTPClient.doPOST(connection, xmlDocument);
        if (resultat != null) {
            System.out.println("Message retourn� par le serveur:");
            System.out.println(resultat);
        }
        else {
            System.exit(1);
        }

        // 4.) rechargement du message SOAP � envoyer
        xmlDocument = XmlTools.loadFromFile(args[8]);
        xmlDocument.normalize();

        // 5.) via les API d'OpenSAML
        System.out.println("\n\n");
        System.out.println("******************************************************");
        System.out.println("Via les API de OpenSAML");
        System.out.println("******************************************************");
        xmlDocument = XmlDSig_OpenSAML.signBody(xmlDocument, args[1], args[2], args[3],
                args[7]);
        System.out.println("Le message SOAP suivant est envoy� au serveur:");
        System.out.println(XmlTools.toPrettyString(xmlDocument.getDocumentElement()));
        connection = HTTPClient.getHTTPConnection(url, args[1], args[2],
                args[3], args[4], args[5], args[6]);
        resultat = HTTPClient.doPOST(connection, xmlDocument);
        if (resultat != null) {
            System.out.println("Message retourn� par le serveur:");
            System.out.println(resultat);
        }
        else {
            System.exit(1);
        }
        System.exit(0);
    }
}