/*
 * UserNameToken.java
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

package lu.ciss.mysecu.demo.wsse;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.ws.wssecurity.Created;
import org.opensaml.ws.wssecurity.Nonce;
import org.opensaml.ws.wssecurity.Password;
import org.opensaml.ws.wssecurity.Username;
import org.opensaml.ws.wssecurity.UsernameToken;

import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.MarshallingException;
import org.w3c.dom.Element;

import lu.ciss.mysecu.demo.XmlTools;

/**
 * Classe utilitaire pour la g�n�ration d'un wsse:UsernameToken.
 *
 * ATTENTION:
 * IL S'AGIT D'UN PROJET DE DEMONSTRATION. IL EST DECONSEILE DE L'UTILISER EN PRODUCTION.
 *
 * @author u156gm
 * @version $Id: UserNameToken.java 16672 2015-06-30 14:26:21Z u156gm $
 * @since REL_1-0-0
 */
public class UserNameToken {

    /**
     * Bootstrap d'OpenSAML
     */
    static {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * G�n�ration d'un UserNameToken conforme aux sp�cifications de mySecu.
     * Un tel jeton contient:
     * <ol>
     * <li> l'identifiant utilisateur </li>
     * <li> le mot de passe encod�: b64(sha1(password))) </li>
     * <li> un nombre al�atoire (nonce) </li>
     * <li> la date et l'heure (zulu) de cr�ation du jeton en </li>
     * </ol>
     *
     * @param userID
     * @param password
     * @return le usernametoken g�n�r�
     */
    public static UsernameToken createUserNameToken(final String userID, final String password) {
        // 1.) cr�ation de l'objet UsernameToken
        UsernameToken userNameToken = (UsernameToken) Configuration.getBuilderFactory()
                .getBuilder(UsernameToken.ELEMENT_NAME).buildObject(UsernameToken.ELEMENT_NAME);

        // 2.) cr�ation de l'objet userName
        Username userName = (Username) Configuration.getBuilderFactory().getBuilder(Username.ELEMENT_NAME)
                .buildObject(Username.ELEMENT_NAME);
        userName.setValue(userID);
        userNameToken.setUsername(userName);

        // 3.) Cr�ation de l'objet Password
        try {
            Password pass = (Password) Configuration.getBuilderFactory().getBuilder(Password.ELEMENT_NAME)
                    .buildObject(Password.ELEMENT_NAME);
            pass.setType("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText");
            String passwordB64 = Base64.encode(MessageDigest.getInstance("SHA1").digest(password.getBytes("UTF-8")));
            pass.setValue(passwordB64);
            userNameToken.getUnknownXMLObjects().add(pass);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        // 4.) Cr�ation de l'objet Created
        Created created = (Created) Configuration.getBuilderFactory().getBuilder(Created.ELEMENT_NAME)
                .buildObject(Created.ELEMENT_NAME);
        created.setDateTime(new DateTime()); // utiliser plut�t une source NTP
        userNameToken.getUnknownXMLObjects().add(created);

        // 5.) Cr�ation de l'objet Nonce
        Nonce nonce = (Nonce) Configuration.getBuilderFactory().getBuilder(Nonce.ELEMENT_NAME)
                .buildObject(Nonce.ELEMENT_NAME);
        nonce.setEncodingType(Nonce.ENCODING_TYPE_BASE64_BINARY);
        try {
            SecureRandom prng = SecureRandom.getInstance("SHA1PRNG");
            String randomNum = new Integer(prng.nextInt()).toString();
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            byte[] digest = sha.digest(randomNum.getBytes());
            String nonceValue = Base64.encode(digest);
            nonce.setValue(nonceValue);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        userNameToken.getUnknownXMLObjects().add(nonce);

        // 8.) s�rialisation du username token
        try {
            Configuration.getMarshallerFactory().getMarshaller(userNameToken).marshall(userNameToken);
        } catch (MarshallingException e) {
            throw new RuntimeException(e);
        }
        return userNameToken;
    }

    /**
     * Cr�ation d'un usernametoken en fonction des donn�es fournies en argument.
     * args[0] = userID
     * args[1] = password
     *
     * Le jeton est affich� en STDOUT.
     *
     * @param args
     * @throws MarshallingException
     * @throws IOException
     * @throws XMLSecurityException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws XMLSignatureException
     * @throws UnrecoverableKeyException
     * @throws ParserConfigurationException
     * @throws ConfigurationException
     */
    public static void main(String[] args) throws MarshallingException {
        UsernameToken userNameToken = UserNameToken.createUserNameToken(args[0], args[1]);
        Element userNameTokenElement = Configuration.getMarshallerFactory().getMarshaller(UsernameToken.ELEMENT_NAME)
                .marshall(userNameToken);
        System.out.println(XmlTools.toPrettyString(userNameTokenElement));
    }
}