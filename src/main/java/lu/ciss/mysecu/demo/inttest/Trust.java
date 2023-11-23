/*
 * Trust.java
 * Date de cr�ation: 30 juin 2015
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;

import javax.xml.soap.MessageFactory;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Header;
import org.opensaml.ws.wssecurity.Security;
import org.opensaml.ws.wssecurity.UsernameToken;
import org.opensaml.ws.wstrust.RequestedSecurityToken;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import lu.ciss.mysecu.demo.XmlTools;
import lu.ciss.mysecu.demo.wsse.HTTPClient;
import lu.ciss.mysecu.demo.wsse.UserNameToken;
import lu.ciss.mysecu.demo.wsse.XmlDSig_OpenSAML;
import lu.ciss.mysecu.demo.wst.AuthenticationRequest;

/**
 * D�monstrations des appels au service WS-Trust 1.3 de mySecu.
 *
 * ATTENTION:
 * IL S'AGIT D'UN PROJET DE DEMONSTRATION. IL EST DECONSEILE DE L'UTILISER EN PRODUCTION.
 *
 * Les arguments suivants sont � fournir en argument:
 * <ol>
 * <li> args[0]: l'URL compl�te du service d'authentification </li>
 * <li> args[1]: le chemin vers le keystore contenant la clef priv�e du client </li>
 * <li> args[2]: le type du keystore (JKS || PKCS12) </li>
 * <li> args[3]: le mot de passe pour ouvrir le keystore </li>
 * <li> args[4]: le chemin vers le truststore contenant le certificat du serveur mySecu </li>
 * <li> args[5]: le type du truststore (JKS || PKCS12) </li>
 * <li> args[6]: le mot de passe pour ouvrir le truststore </li>
 * <li> args[7]: l'alias de la clef priv�e
 * <li> args[8]: l'identifiant utilisateur </li>
 * <li> args[9]: le mot de passe de l'utilisateur </li>
 * <li> args[10]: le type de jeton demand� </li>
 * <li> args[11]: l'adresse de connexion </li>
 * </ol>
 *
 * @author u156gm
 * @version $Id: Trust.java 16672 2015-06-30 14:26:21Z u156gm $
 * @since REL_1-0-1
 */
public class Trust {

    /**
     * Bootstrap de la librairie OpenSAML
     */
    static {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            e.printStackTrace();
        }
    }

    public static void printHeader() {
        System.out.println("*********************************************");
        System.out.println("mySecu D�monstration: Appel au service WS-Trust");
        System.out.println("/ws/soap/trust");
        System.out.println("*********************************************");
    }

    /**
     * {@inheritDoc}
     */
    public static void main(String[] args) throws MarshallingException, IOException, SOAPException,
            UnmarshallingException {
        // 1.) cr�ation de l'URL de connexion
        URL url = new URL(args[0]);

        // 2.) cr�ation de la demande d'authentification
        Envelope authenticationRequest = AuthenticationRequest.createIssueRequest(args[10], args[11]);

        // 3.) cr�ation des donn�es d'authentification (username & password)
        UsernameToken userNameToken = UserNameToken.createUserNameToken(args[8], args[9]);

        // 4.) ajout des donn�es d'authentification dans l'ent�te WS-Security de la demande
        Header soapHeader = authenticationRequest.getHeader();
        Security wsseHeader = (Security) soapHeader.getUnknownXMLObjects().get(0);
        wsseHeader.getUnknownXMLObjects().add(userNameToken);

        // 5.) s�rialisation de l'envelope avant signature
        Configuration.getMarshallerFactory().getMarshaller(authenticationRequest).marshall(authenticationRequest);

        // 6.) signature de la demande
        // la signature doit porter sur le body de la demande ET l'�l�ment usernametoken
        Document demande = XmlDSig_OpenSAML.signMessage(authenticationRequest, new XMLObject[] {userNameToken,
                authenticationRequest.getBody()}, args[1], args[2], args[3], args[7]);

        // 7.) r�cup�ration de la connexion vers le serveur
        HttpURLConnection connection = HTTPClient.getHTTPConnection(url, args[1], args[2],
                args[3], args[4], args[5], args[6]);

        // 8.) envoie de la demande au serveur
        String resultat = HTTPClient.doPOST(connection, demande);

        // 9.) convertir la r�ponse en message SOAP
        SOAPMessage message = MessageFactory.newInstance().createMessage(new MimeHeaders(),
                new ByteArrayInputStream(resultat.getBytes(Charset.forName("UTF-8"))));

        // 10.) r�cup�rer le jeton depuis la r�ponse
        NodeList tokens = message.getSOAPBody().getElementsByTagNameNS(
                RequestedSecurityToken.ELEMENT_NAME.getNamespaceURI(),
                RequestedSecurityToken.ELEMENT_NAME.getLocalPart());
        Element authToken = null;
        if (tokens.getLength() > 0) {
            authToken = (Element) tokens.item(0).getFirstChild();
        }
        if (authToken != null) {
            System.out.println(XmlTools.toPrettyString(authToken));
        }
        else {
            System.exit(-1);
        }
    }
}