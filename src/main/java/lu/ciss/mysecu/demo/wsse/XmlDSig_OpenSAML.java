/*
 * XmlDSig.java
 * Date de création: 15 juin 2015
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Header;
import org.opensaml.ws.wssecurity.Security;
import org.opensaml.ws.wssecurity.util.WSSecurityHelper;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.Criteria;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.URIContentReference;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import lu.ciss.mysecu.demo.XmlTools;

/**
 * Outils pour la génération d'une signature XML
 * d'un message SOAP à travers les API d'OpenSAML.
 *
 * ATTENTION:
 * IL S'AGIT D'UN PROJET DE DEMONSTRATION. IL EST DECONSEILE DE L'UTILISER EN PRODUCTION.
 *
 * @author u156gm
 * @version $Id: XmlDSig_OpenSAML.java 16672 2015-06-30 14:26:21Z u156gm $
 * @since REL_1-1-0
 */
public class XmlDSig_OpenSAML {

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

    /**
     * Signe le body d'un message SOAP à l'aide de l'API OpenSAML et ajoute la signature dans une entête WS-Security.
     * L'entête WS-Security est automatiquement générée si elle n'existe pas encore.
     *
     * @param messageSOAP le message SOAP à signer
     * @param referencesInternes les références vers les parties du message SOAP à signer
     * @param keyStorePath le chemin vers le keystore
     * @param keyStoreType le type du keystore
     * @param keyStorePassword le mot de passe du keystore
     * @param keyAlias l'alias de la clef privée
     * @return le message SOAP signé avec la signature incluse dans l'entête WSSE
     */
    public static final Document signBody(final Document messageSOAP, final String keyStorePath,
            final String keyStoreType,
            final String keyStorePassword, final String keyAlias) {
        // 1.) conversion en objet d'OpenSAML
        XMLObject xmlObject;
        try {
            xmlObject = Configuration.getUnmarshallerFactory().getUnmarshaller(
                    messageSOAP.getDocumentElement()).unmarshall(messageSOAP.getDocumentElement());
        } catch (UnmarshallingException e) {
            throw new RuntimeException(e);
        }
        Envelope envelope = (Envelope) xmlObject;
        return XmlDSig_OpenSAML.signMessage(envelope, new XMLObject[] {envelope.getBody()}, keyStorePath, keyStoreType,
                keyStorePassword, keyAlias);
    }

    /**
     * Signe le message SOAP à l'aide de l'API OpenSAML et ajoute la signature dans une entête WS-Security.
     * L'entête WS-Security est automatiquement générée si elle n'existe pas encore.
     *
     * @param envelope l'envelope du message SOAP
     * @param references les éléments de l'envelope qui sont à signer
     * @param keyStorePath le chemin vers le keystore
     * @param keyStoreType le type du keystore
     * @param keyStorePassword le mot de passe du keystore
     * @param keyAlias l'alias de la clef privée
     * @return le message SOAP signé avec la signature incluse dans l'entête WSSE
     */
    public static final Document signMessage(Envelope envelope, XMLObject[] references, final String keyStorePath,
            final String keyStoreType,
            final String keyStorePassword, final String keyAlias) {
        try {
            // 1.) créer l'objet de signature OpenSAML
            Signature signature = (Signature) Configuration.getBuilderFactory()
                    .getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject(Signature.DEFAULT_ELEMENT_NAME);

            // 2.) ajouter la signature dans l'entête WS-Security
            // 2.a.) récupération ou création de l'entête SOAP
            Header header = envelope.getHeader();
            if (header == null) {
                header = (Header) Configuration.getBuilderFactory().getBuilder(Header.DEFAULT_ELEMENT_NAME)
                        .buildObject(Header.DEFAULT_ELEMENT_NAME);
                envelope.getUnknownXMLObjects().add(0, header);
            }
            // 2.b.) récupération ou création de l'entête WS-Security
            Security securityHeader;
            List<XMLObject> wsseHeaders = header.getUnknownXMLObjects(Security.ELEMENT_NAME);
            if (wsseHeaders == null || wsseHeaders.isEmpty()) {
                securityHeader = (Security) Configuration.getBuilderFactory().getBuilder(Security.ELEMENT_NAME)
                        .buildObject(Security.ELEMENT_NAME);
                header.getUnknownXMLObjects().add(securityHeader);
            }
            else {
                securityHeader = (Security) wsseHeaders.get(0);
            }

            // 2.c.) ajout de la signature dans l'entête
            securityHeader.getUnknownXMLObjects().add(signature);

            // 3.) définir les algorithmes de signature et de normalisation
            signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
            signature.setCanonicalizationAlgorithm(SignatureConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

            // 4.) ajouter les références internes et externes
            signature.getContentReferences().clear();
            List<XMLObject> referencedObjects = Arrays.asList(references);
            if (referencedObjects != null && !referencedObjects.isEmpty()) {
                SecureRandomIdentifierGenerator srig = new SecureRandomIdentifierGenerator();
                for (XMLObject referencedObject : referencedObjects) {
                    // 5.b.) ajouter l'identifiant WSU s'il n'existe pas encore
                    String wsuID = WSSecurityHelper.getWSUId(referencedObject);
                    if (wsuID == null) {
                        // génération d'un nombre aléatoire pour l'identifiant
                        // il s'agit de la bonne pratique d'ajouter un prefix au nombre aléatoire
                        // le prefix indique le type de l'élément identifié
                        wsuID = referencedObject.getElementQName().getLocalPart() + srig.generateIdentifier();
                        WSSecurityHelper.addWSUId(referencedObject, wsuID);
                    }
                    else {
                        WSSecurityHelper.addWSUId(referencedObject, wsuID);
                    }
                    // 5.c.) ajouter la référence vers l'identifiant WSU
                    URIContentReference uriContentReference = new URIContentReference("#" + wsuID);
                    // 5.d.) ajouter les algorithmes de transformations tels que demandé par mySecu
                    uriContentReference.getTransforms().add(SignatureConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
                    uriContentReference.setDigestAlgorithm(SignatureConstants.ALGO_ID_DIGEST_SHA1);
                    // 5.e.) ajouter la référence dans la signature
                    signature.getContentReferences().add(uriContentReference);
                }
            }

            // 5.) déterminer les credentials pour la signature directement du keystore
            KeyStore keystore;
            keystore = KeyStore.getInstance(keyStoreType);
            FileInputStream inputStream = new FileInputStream(keyStorePath);
            keystore.load(inputStream, keyStorePassword.toCharArray());
            inputStream.close();
            Map<String, String> passwordMap = new HashMap<String, String>();
            passwordMap.put(keyAlias, keyStorePassword);
            KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);
            Criteria criteria = new EntityIDCriteria(keyAlias);
            CriteriaSet criteriaSet = new CriteriaSet(criteria);
            X509Credential credential = (X509Credential) resolver.resolveSingle(criteriaSet);
            signature.setSigningCredential(credential);

            // 6.) ajouter les credentials dans KeyInfo
            org.opensaml.xml.signature.KeyInfo keyInfo = (org.opensaml.xml.signature.KeyInfo) Configuration
                    .getBuilderFactory().getBuilder(org.opensaml.xml.signature.KeyInfo.DEFAULT_ELEMENT_NAME)
                    .buildObject(org.opensaml.xml.signature.KeyInfo.DEFAULT_ELEMENT_NAME);
            KeyInfoHelper.addCertificate(keyInfo, credential.getEntityCertificate());
            signature.setKeyInfo(keyInfo);

            // 7.) serialisation (marshal) de la structure DOM avant de signer
            Configuration.getMarshallerFactory().getMarshaller(envelope).marshall(envelope);

            // 8.) générer la signature
            Signer.signObject(signature);

            // 9.) reconstruire l'objet OpenSAML en document DOM
            Element signedEnvelope = Configuration.getMarshallerFactory().getMarshaller(envelope).marshall(envelope);
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document newDocument = builder.newDocument();
            newDocument.appendChild(newDocument.importNode(signedEnvelope, true));
            return newDocument;
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
     * @param args
     * @throws UnmarshallingException
     */
    public static void main(String args[]) throws UnmarshallingException {
        // chargement du message SOAP depuis un fichier
        Document xmlDocument = XmlTools.loadFromFile(args[4]);
        xmlDocument.normalize();
        // signature du body du message SOAP via OpenSAML
        xmlDocument = XmlDSig_OpenSAML.signBody(xmlDocument, args[0],
                args[1], args[2], args[3]);
        System.out.println("Signature produite via OpenSAML:");
        System.out.println(XmlTools.toPrettyString(xmlDocument.getDocumentElement()));
    }
}