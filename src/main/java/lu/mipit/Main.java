package lu.mipit;

import lu.ciss.mysecu.demo.XmlTools;
import lu.ciss.mysecu.demo.wsse.XmlDSig_OpenSAML;
import lu.mipit.http.HTTPClient;
import lu.mipit.utils.FichierConfig;
import lu.mipit.wsse.BinarySecurityToken_mip;
import lu.mipit.wsse.Body_mip;
import lu.mipit.wsse.Timestamp_mip;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Header;
import org.opensaml.ws.wssecurity.BinarySecurityToken;
import org.opensaml.ws.wssecurity.Security;
import org.opensaml.ws.wssecurity.Timestamp;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.x509.X509Credential;
import org.w3c.dom.Document;

import javax.xml.namespace.QName;
import java.io.FileInputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;


public class Main {
    static {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {

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
        String publicKey_alias = FichierConfig.getProperty("publicKeyAlias");

        // Print the values to verify
        System.out.println("url=" + serverUrl);
        System.out.println("keyStorePath=" + keyStorePath);
        System.out.println("keyStoreType=" + keyStoreType);
        System.out.println("keyStorePassword=" + keyStorePassword);
        System.out.println("trustStorePath=" + trustStorePath);
        System.out.println("trustStoreType=" + trustStoreType);
        System.out.println("trustStorePassword=" + trustStorePassword);
        System.out.println("xml=" + xml);

        // Création de l'enveloppe
        Envelope enveloppe = createEnvelope();


        // Chargement du certificat
        System.out.println("Chargement du certificat...");
        X509Certificate cert = loadCertificateFromKeystore(keyStorePath, keyStorePassword, keyStoreType, publicKey_alias);
        if (cert == null) {
            System.out.println("Échec du chargement du certificat");
        } else {
            System.out.println("Certificat chargé avec succès");
        }

        // Création du BinarySecurityToken
        System.out.println("Création du BinarySecurityToken...");
        BinarySecurityToken binarySecurityToken = BinarySecurityToken_mip.createBinarySecurityToken(cert);
        if (binarySecurityToken == null) {
            System.out.println("Échec de la création du BinarySecurityToken");
        } else {
            System.out.println("BinarySecurityToken créé avec succès");
        }

        // Ajout dans le header SOAP
        System.out.println("Ajout du token au header SOAP...");
        Header soapHeader = enveloppe.getHeader();
        if (soapHeader == null) {
            System.out.println("Échec : Header SOAP est null");
        } else {
            Security wsseHeader = (Security) soapHeader.getUnknownXMLObjects().get(0);
            if (wsseHeader == null) {
                System.out.println("Échec : wsseHeader est null");
            } else {
                wsseHeader.getUnknownXMLObjects().add(binarySecurityToken);
                System.out.println("BinarySecurityToken ajouté au wsseHeader");
            }
        }

        // Création du timestamp
        System.out.println("Création du BinarySecurityToken...");
        Timestamp ts = Timestamp_mip.createTimestamp(10);
        if (ts == null) {
            System.out.println("Échec de la création du BinarySecurityToken");
        } else {
            System.out.println("BinarySecurityToken créé avec succès");
        }
        // Ajout du timestamp dans le header SOAP
        System.out.println("Ajout du timestamp au header SOAP...");
        soapHeader = enveloppe.getHeader();
        if (soapHeader == null) {
            System.out.println("Échec : timestamp SOAP est null");
        } else {
            Security wsseHeader = (Security) soapHeader.getUnknownXMLObjects().get(0);
            if (wsseHeader == null) {
                System.out.println("Échec : wsseHeader est null");
            } else {
                wsseHeader.getUnknownXMLObjects().add(ts);
                System.out.println("timestamp ajouté au wsseHeader");
            }
        }
        //Création du body
        Body body_mip = Body_mip.createSamlSoapBody();

        // Ajout du body à l'envelope
        enveloppe.setBody(body_mip);
        // Marshalling de l'envelope
        System.out.println("Marshalling de l'enveloppe...");
        try {
            Configuration.getMarshallerFactory().getMarshaller(enveloppe).marshall(enveloppe);
            System.out.println("Marshalling effectué avec succès");
        } catch (Exception e) {
            System.out.println("Échec du marshalling : " + e.getMessage());
        }

        // Affichage du contenu
        System.out.println("Affichage du contenu de l'enveloppe...");
        try {
            String enveloppeContent = XmlTools.toPrettyString(enveloppe.getDOM());
            System.out.println("Enveloppe = " + enveloppeContent);
        } catch (Exception e) {
            System.out.println("Erreur lors de l'affichage de l'enveloppe : " + e.getMessage());
        }

        // Accéder au Header SOAP
        soapHeader = enveloppe.getHeader();
        XMLObject binarySecurityTokenXML = null;
        XMLObject timestampXML = null;

        if (soapHeader != null) {
            for (XMLObject xmlObject : soapHeader.getUnknownXMLObjects()) {
                if (xmlObject instanceof BinarySecurityToken) {
                    binarySecurityTokenXML = xmlObject;
                } else if (xmlObject instanceof Timestamp) {
                    timestampXML = xmlObject;
                }
            }
        }

        // Accéder au Body SOAP et récupérer son contenu
        Body body = enveloppe.getBody();
        XMLObject bodyContent = null;
        if (body != null && !body.getUnknownXMLObjects().isEmpty()) {
            bodyContent = body.getUnknownXMLObjects().get(0);
        }

        Document signedDocument = XmlDSig_OpenSAML.signMessage(enveloppe, new XMLObject[]{enveloppe.getBody(),ts,binarySecurityToken}, keyStorePath, keyStoreType, keyStorePassword, privateKey_alias);
        // Afficher le document signé
        System.out.println("Document signé:");
        System.out.println(XmlTools.toPrettyString(signedDocument.getDocumentElement()));

         // Création de l'URL de connexion
        URL url = new URL(serverUrl);
        System.out.println("URL spécifiée:" + url);

        HttpURLConnection connection = HTTPClient.getHTTPConnection(url, keyStorePath, keyStoreType,
                keyStorePassword, trustStorePath, trustStoreType, trustStorePassword);

        String resultat = HTTPClient.doPOST(connection, signedDocument); 
        System.out.println(resultat);


    }


    public static Envelope createEnvelope() {

        // 1.) Création de l'enveloppe SOAP 1.1
        QName envelopeQName = new QName("http://schemas.xmlsoap.org/soap/envelope/", "Envelope", "soapenv");
        Envelope envelope = (Envelope) Configuration.getBuilderFactory().getBuilder(envelopeQName)
                .buildObject(envelopeQName);

        // 2.) Création d'une entête SOAP 1.1
        QName headerQName = new QName("http://schemas.xmlsoap.org/soap/envelope/", "Header", "soapenv");
        Header header = (Header) Configuration.getBuilderFactory().getBuilder(headerQName)
                .buildObject(headerQName);
        envelope.setHeader(header);

        // 3.) Création du body SOAP 1.1
        QName bodyQName = new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body", "soapenv");
        Body body = (Body) Configuration.getBuilderFactory().getBuilder(bodyQName)
                .buildObject(bodyQName);
        envelope.setBody(body);


        // 10.) cr�ation d'une ent�te WS-Security vide
        Security wsseHeader = (Security) Configuration.getBuilderFactory().getBuilder(Security.ELEMENT_NAME)
                .buildObject(Security.ELEMENT_NAME);
        header.getUnknownXMLObjects().add(wsseHeader);

        // 11.) s�rialisation de l'envelope
        try {
            Configuration.getMarshallerFactory().getMarshaller(envelope).marshall(envelope);
        } catch (MarshallingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return envelope;
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
}

