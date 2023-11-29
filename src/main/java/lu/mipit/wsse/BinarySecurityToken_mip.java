package lu.mipit.wsse;

import lu.ciss.mysecu.demo.XmlTools;
import lu.mipit.utils.FichierConfig;
import org.joda.time.DateTime;
import org.joda.time.format.ISODateTimeFormat;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.ws.soap.common.SOAPException;
import org.opensaml.ws.wssecurity.*;
import org.opensaml.ws.wssecurity.util.WSSecurityHelper;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.x509.X509Credential;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.*;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

public class BinarySecurityToken_mip {

    static {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            throw new RuntimeException(e);
        }
    }

    public static BinarySecurityToken createBinarySecurityToken(X509Certificate cert) {
        try {
            // Création de l'objet BinarySecurityToken
            BinarySecurityToken binarySecurityToken = (BinarySecurityToken) Configuration.getBuilderFactory()
                    .getBuilder(BinarySecurityToken.ELEMENT_NAME)
                    .buildObject(BinarySecurityToken.ELEMENT_NAME);

            // Configuration du BinarySecurityToken
            binarySecurityToken.setEncodingType(BinarySecurityToken.ENCODING_TYPE_BASE64_BINARY);
            binarySecurityToken.setValueType("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-tokenprofile-1.0#X509v3");
            binarySecurityToken.setValue(org.apache.xml.security.utils.Base64.encode(cert.getEncoded()));

            // Ajouter un identifiant WSU
            //String wsuId = "BST-" + UUID.randomUUID().toString();
            //WSSecurityHelper.addWSUId(binarySecurityToken, wsuId);

            return binarySecurityToken;
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("Erreur lors de l'encodage du certificat", e);
        }
    }

    public static X509Certificate loadCertificateFromKeystore(String keyStorePath, String keyStorePassword, String keyStoreType, String keyAlias) throws Exception {
        // Charger le keystore
        KeyStore keystore = KeyStore.getInstance(keyStoreType);
        FileInputStream inputStream = new FileInputStream(keyStorePath);
        keystore.load(inputStream, keyStorePassword.toCharArray());
        inputStream.close();

        // Configurer KeyStoreCredentialResolver
        Map<String, String> passwordMap = new HashMap<>();
        passwordMap.put(keyAlias, keyStorePassword);
        KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);

        // Créer CriteriaSet avec l'alias de la clé
        CriteriaSet criteriaSet = new CriteriaSet();
        criteriaSet.add(new EntityIDCriteria(keyAlias));

        // Résoudre le credential et obtenir le certificat
        Credential credential = resolver.resolveSingle(criteriaSet);
        if (credential instanceof X509Credential) {
            return ((X509Credential) credential).getEntityCertificate();
        } else {
            throw new RuntimeException("Le credential obtenu n'est pas une instance de X509Credential");
        }
    }
    public static SOAPMessage addBinarySecurityTokenToSOAP(SOAPMessage soapMessage, X509Certificate cert) throws Exception {
        // Création du BinarySecurityToken
        BinarySecurityToken binarySecurityToken = createBinarySecurityToken(cert);

        // Obtention ou création de l'en-tête WSSE
        SOAPEnvelope envelope = soapMessage.getSOAPPart().getEnvelope();
        SOAPHeader header = envelope.getHeader();
        if (header == null) {
            header = envelope.addHeader();
        }

        // Création de l'élément Security
        Security wsseHeader = (Security) Configuration.getBuilderFactory()
                .getBuilder(Security.ELEMENT_NAME)
                .buildObject(Security.ELEMENT_NAME);

        // Ajout du BinarySecurityToken à l'en-tête Security
        Element binarySecurityTokenElement = Configuration.getMarshallerFactory()
                .getMarshaller(binarySecurityToken)
                .marshall(binarySecurityToken);
        wsseHeader.getUnknownXMLObjects().add(binarySecurityToken);

        // Ajout de l'en-tête Security au message SOAP
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.newDocument();
        Element importedElement = (Element) doc.importNode(binarySecurityTokenElement, true);
        header.appendChild(soapMessage.getSOAPPart().importNode(importedElement, true));

        return soapMessage;
    }

    public static void main(String[] args) {
        // Your code here
    }
}
