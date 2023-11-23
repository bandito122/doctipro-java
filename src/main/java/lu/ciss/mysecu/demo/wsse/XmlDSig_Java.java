/*
 * XmlDSig_Java.java
 * Date de création: 29 juin 2015
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
 * Implémentation de la signature XML d'un message SOAP à travers les API de Java.
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
     * QName d'une entête WS-Security
     */
    public static final QName WSSE = new QName(
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Security");

    /**
     * QName d'un identifiant WSU
     */
    public static final QName WSU = new QName(
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id", "wsu");

    /**
     * Ajout d'une entête WS-Security dans le message SOAP.
     * Aucune entête n'est insérée si une telle entête WS-Security existe déjà.
     *
     * @param soapMessage le message SOAP à modifier
     * @return le message SOAP avec entête WS-Security
     */
    public static final SOAPMessage addWSSEHeader(SOAPMessage soapMessage) {
        if (soapMessage == null) {
            throw new IllegalArgumentException("SOAP message must not be NULL.");
        }
        try {
            // 1.) récupérer l'envelope du message SOAP
            SOAPEnvelope envelope = soapMessage.getSOAPPart().getEnvelope();
            // 2.) récupérer l'entête du message SOAP
            SOAPHeader header = envelope.getHeader();
            // 3.) récupérer l'élément WS-Security
            Iterator<?> wsseElements = header.getChildElements(WSSE);
            if (wsseElements.hasNext()) {
                // il existe déjà une entête WS-Security
                // pas besoin d'en ajouter une nouvelle
                // en production il faut également vérifier qu'il s'agit d'une entête
                // étant destinée au bon "actor" ou "role"
                return soapMessage;
            }
            // il n'existe pas encore d'entête WS-Security
            // il faut alors ajouter une nouvelle
            header.addChildElement(header.addHeaderElement(WSSE));
            return soapMessage;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Signature du body (payload) du message SOAP.
     * Le signature est automatiquement ajoutée dans une entête WS-Security.
     *
     * @param soapMessage le message SOAP à signer
     * @param keyStorePath le chemin vers le keystore
     * @param keyStoreType le type du keystore
     * @param keyStorePassword le mot de passe du keystore
     * @param keyAlias l'alias de la clef privée pour la signature
     *
     * @return le message SOAP signé
     */
    public static final SOAPMessage signBody(SOAPMessage soapMessage, final String keyStorePath,
            final String keyStoreType,
            final String keyStorePassword, final String keyAlias) {

        try {
            SOAPBody body = soapMessage.getSOAPPart().getEnvelope().getBody();
            // 1.) déterminer si le body contient déjà un identifiant WSU
            // si non, générer un nouveau identifiant
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
     * Signature d'un message SOAP. Seuls les référénces indiqués seront incluses dans la signature.
     * Supportés sont les types de référence suivantes: wsu:Id et xml:ID.
     *
     * @param soapMessage le message SOAP à signer
     * @param references la liste des références internes à signer
     * @param keyStorePath le chemin vers le keystore
     * @param keyStoreType le type du keystore
     * @param keyStorePassword le mot de passe du keystore
     * @param keyAlias l'alias de clef privée
     *
     * @return le message SOAP signé
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

            // 2.) créer et ajouter les références à signer
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

            // 3.) créer l'élément SignedInfo
            SignedInfo signedInfo = sigFactory.newSignedInfo(sigFactory.newCanonicalizationMethod(
                    CanonicalizationMethod.EXCLUSIVE, (ExcC14NParameterSpec) null), sigFactory
                    .newSignatureMethod(SignatureMethod.RSA_SHA1, null), _references);

            // 4.) charger le keystore et créer les informations de clefs
            KeyStore ks = KeyStore.getInstance(keyStoreType);
            FileInputStream fis = new FileInputStream(keyStorePath);
            ks.load(fis, keyStorePassword.toCharArray());
            PrivateKey privateKey = (PrivateKey) ks.getKey(keyAlias, keyStorePassword.toCharArray());
            X509Certificate certificate = (X509Certificate) ks.getCertificate(keyAlias);
            KeyInfoFactory kif = sigFactory.getKeyInfoFactory();
            KeyInfo keyInfo = kif.newKeyInfo(Collections.singletonList(kif.newX509Data(Collections
                    .singletonList(certificate))));

            // 5.) créer l'objet de signature
            XMLSignature sig = sigFactory.newXMLSignature(signedInfo, keyInfo);

            // 6.) créer le contexte de signature
            DOMSignContext signatureContext = new DOMSignContext(privateKey, wsseHeader);
            signatureContext.putNamespacePrefix(XMLSignature.XMLNS, "ds");

            // 7.) générer la signature
            sig.sign(signatureContext);

            return _soapMessage;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Génération d'une signature d'un message SOAP
     * args[0]: chemin vers le keystore de la clef privée
     * args[1]: type du keystore
     * args[2]: le mot de passe du keystore
     * args[3]: l'alias de la clef privée dans le keystore
     * args[4]: l'alias du chemin vers le message SOAP à signer
     *
     * @param args les arguments à fournir
     */
    public static void main(String args[]) {
        // chargement du message SOAP depuis un fichier
        Document xmlDocument = XmlTools.loadFromFile(args[4]);
        SOAPMessage soapMessage = XmlTools.convertToSoapMessage(xmlDocument);
        soapMessage = XmlDSig_Java.signBody(soapMessage, args[0], args[1], args[2], args[3]);
        System.out.println(XmlTools.toPrettyString(soapMessage.getSOAPPart().getDocumentElement()));
    }
}