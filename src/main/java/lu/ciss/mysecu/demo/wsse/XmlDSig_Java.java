/*
 * XmlDSig_Java.java
 * Date de cr�ation: 29 juin 2015
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

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;

import org.opensaml.ws.wssecurity.Security;
import org.w3c.dom.Document;

import lu.ciss.mysecu.demo.XmlTools;

/**
 * Impl�mentation de la signature XML d'un message SOAP � travers les API de Java.
 * Notamment JAXWS et Java XML Signature API.
 *
 * ATTENTION:
 * IL S'AGIT D'UN PROJET DE DEMONSTRATION. IL EST DECONSEILE DE L'UTILISER EN PRODUCTION.
 *
 * @author u156gm
 * @version $Id: XmlDSig_Java.java 16672 2015-06-30 14:26:21Z u156gm $
 * @since REL_1-0-1
 */
public class XmlDSig_Java {

    /**
     * QName d'une ent�te WS-Security
     */
    public static final QName WSSE = new QName(
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Security");

    /**
     * QName d'un identifiant WSU
     */
    public static final QName WSU = new QName(
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id", "wsu");

    /**
     * Ajout d'une ent�te WS-Security dans le message SOAP.
     * Aucune ent�te n'est ins�r�e si une telle ent�te WS-Security existe d�j�.
     *
     * @param soapMessage le message SOAP � modifier
     * @return le message SOAP avec ent�te WS-Security
     */
    public static final SOAPMessage addWSSEHeader(SOAPMessage soapMessage) {
        if (soapMessage == null) {
            throw new IllegalArgumentException("SOAP message must not be NULL.");
        }
        try {
            // 1.) r�cup�rer l'envelope du message SOAP
            SOAPEnvelope envelope = soapMessage.getSOAPPart().getEnvelope();
            // 2.) r�cup�rer l'ent�te du message SOAP
            SOAPHeader header = envelope.getHeader();
            // 3.) r�cup�rer l'�l�ment WS-Security
            Iterator<?> wsseElements = header.getChildElements(WSSE);
            if (wsseElements.hasNext()) {
                // il existe d�j� une ent�te WS-Security
                // pas besoin d'en ajouter une nouvelle
                // en production il faut �galement v�rifier qu'il s'agit d'une ent�te
                // �tant destin�e au bon "actor" ou "role"
                return soapMessage;
            }
            // il n'existe pas encore d'ent�te WS-Security
            // il faut alors ajouter une nouvelle
            header.addChildElement(header.addHeaderElement(WSSE));
            return soapMessage;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Signature du body (payload) du message SOAP.
     * Le signature est automatiquement ajout�e dans une ent�te WS-Security.
     *
     * @param soapMessage le message SOAP � signer
     * @param keyStorePath le chemin vers le keystore
     * @param keyStoreType le type du keystore
     * @param keyStorePassword le mot de passe du keystore
     * @param keyAlias l'alias de la clef priv�e pour la signature
     *
     * @return le message SOAP sign�
     */
    public static final SOAPMessage signBody(SOAPMessage soapMessage, final String keyStorePath,
            final String keyStoreType,
            final String keyStorePassword, final String keyAlias) {

        try {
            SOAPBody body = soapMessage.getSOAPPart().getEnvelope().getBody();
            // 1.) d�terminer si le body contient d�j� un identifiant WSU
            // si non, g�n�rer un nouveau identifiant
            String wsuID = body.getAttributeNS(WSU.getNamespaceURI(), WSU.getLocalPart());
            if (wsuID == null || wsuID.isEmpty()) {
                SecureRandom random = new SecureRandom();
                random.setSeed(random.generateSeed(20));
                wsuID = "body" + String.valueOf(random.nextLong());
                body.addAttribute(WSU, wsuID);
                body.setIdAttributeNS(WSU.getNamespaceURI(), WSU.getLocalPart(), true);
            }
            return XmlDSig_Java.signMessage(soapMessage, new String[] {"#" + wsuID},
                    keyStorePath, keyStoreType, keyStorePassword, keyAlias);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Signature d'un message SOAP. Seuls les r�f�r�nces indiqu�s seront incluses dans la signature.
     * Support�s sont les types de r�f�rence suivantes: wsu:Id et xml:ID.
     *
     * @param soapMessage le message SOAP � signer
     * @param references la liste des r�f�rences internes � signer
     * @param keyStorePath le chemin vers le keystore
     * @param keyStoreType le type du keystore
     * @param keyStorePassword le mot de passe du keystore
     * @param keyAlias l'alias de clef priv�e
     *
     * @return le message SOAP sign�
     */
    public static final SOAPMessage signMessage(SOAPMessage soapMessage, final String[] references,
            final String keyStorePath,
            final String keyStoreType,
            final String keyStorePassword, final String keyAlias) {
        SOAPMessage _soapMessage = addWSSEHeader(soapMessage);
        try {
            SOAPElement wsseHeader = (SOAPElement) soapMessage.getSOAPPart().getEnvelope().getHeader()
                    .getChildElements(Security.ELEMENT_NAME).next();

            // 1.) initialiser la factory de signature
            XMLSignatureFactory sigFactory = XMLSignatureFactory.getInstance();

            // 2.) cr�er et ajouter les r�f�rences � signer
            Transform transform = sigFactory.newTransform("http://www.w3.org/2001/10/xml-exc-c14n#",
                    (ExcC14NParameterSpec) null);
            List<Reference> _references = new ArrayList<Reference>();
            for (String reference : references) {
                Reference ref = sigFactory.newReference(reference,
                        sigFactory.newDigestMethod(DigestMethod.SHA1, null), Collections.singletonList(transform),
                        null,
                        null);
                _references.add(ref);
            }

            // 3.) cr�er l'�l�ment SignedInfo
            SignedInfo signedInfo = sigFactory.newSignedInfo(sigFactory.newCanonicalizationMethod(
                    CanonicalizationMethod.EXCLUSIVE, (ExcC14NParameterSpec) null), sigFactory
                    .newSignatureMethod(SignatureMethod.RSA_SHA1, null), _references);

            // 4.) charger le keystore et cr�er les informations de clefs
            KeyStore ks = KeyStore.getInstance(keyStoreType);
            FileInputStream fis = new FileInputStream(keyStorePath);
            ks.load(fis, keyStorePassword.toCharArray());
            PrivateKey privateKey = (PrivateKey) ks.getKey(keyAlias, keyStorePassword.toCharArray());
            X509Certificate certificate = (X509Certificate) ks.getCertificate(keyAlias);
            KeyInfoFactory kif = sigFactory.getKeyInfoFactory();
            KeyInfo keyInfo = kif.newKeyInfo(Collections.singletonList(kif.newX509Data(Collections
                    .singletonList(certificate))));

            // 5.) cr�er l'objet de signature
            XMLSignature sig = sigFactory.newXMLSignature(signedInfo, keyInfo);

            // 6.) cr�er le contexte de signature
            DOMSignContext signatureContext = new DOMSignContext(privateKey, wsseHeader);
            signatureContext.putNamespacePrefix(XMLSignature.XMLNS, "ds");

            // 7.) g�n�rer la signature
            sig.sign(signatureContext);

            return _soapMessage;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * G�n�ration d'une signature d'un message SOAP
     * args[0]: chemin vers le keystore de la clef priv�e
     * args[1]: type du keystore
     * args[2]: le mot de passe du keystore
     * args[3]: l'alias de la clef priv�e dans le keystore
     * args[4]: l'alias du chemin vers le message SOAP � signer
     *
     * @param args les arguments � fournir
     */
    public static void main(String args[]) {
        // chargement du message SOAP depuis un fichier
        Document xmlDocument = XmlTools.loadFromFile(args[4]);
        SOAPMessage soapMessage = XmlTools.convertToSoapMessage(xmlDocument);
        soapMessage = XmlDSig_Java.signBody(soapMessage, args[0], args[1], args[2], args[3]);
        System.out.println(XmlTools.toPrettyString(soapMessage.getSOAPPart().getDocumentElement()));
    }
}