package lu.mipit.test;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

import lu.ciss.mysecu.demo.XmlTools;
import lu.ciss.mysecu.demo.wsse.XmlDSig_OpenSAML;
import lu.mipit.utils.FichierConfig;
import org.apache.commons.codec.binary.Base64;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.namespace.NamespaceContext;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Iterator;

public class create_signature {

    public static void main(String args[]) throws Exception {
        String serverUrl = FichierConfig.getProperty("serverUrl");
        String keyStorePath = FichierConfig.getProperty("keyStorePath");
        String keyStoreType = FichierConfig.getProperty("keyStoreType");
        String keyStorePassword = FichierConfig.getProperty("keyStorePassword");
        String trustStorePath = FichierConfig.getProperty("trustStorePath");
        String trustStoreType = FichierConfig.getProperty("trustStoreType");
        String trustStorePassword = FichierConfig.getProperty("trustStorePassword");
        String xml = FichierConfig.getProperty("xml");
        String xml_check_sign = FichierConfig.getProperty("xml_check_sign");
        String xml2_create_sign = FichierConfig.getProperty("xml2_create_sign");
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
        System.out.println("xml_check_sign=" + xml_check_sign);
        System.out.println("xml2_create_sign=" + xml2_create_sign);


        KeyStore ks = KeyStore.getInstance(keyStoreType);
        FileInputStream fis = new FileInputStream(keyStorePath);
        ks.load(fis, keyStorePassword.toCharArray());
        PrivateKey privateKey = (PrivateKey) ks.getKey(privateKey_alias, keyStorePassword.toCharArray());
        X509Certificate certificate = (X509Certificate) ks.getCertificate(privateKey_alias);
        PublicKey publicKey = certificate.getPublicKey();
        System.out.println("public key = "  + publicKey.toString() );

        Document xmlDocument = XmlTools.loadFromFile(xml2_create_sign);
        xmlDocument.normalize();
        SOAPMessage message = XmlTools.convertToSoapMessage(xmlDocument);

        // Test signatare sans canonisation
        Element signedInfoElement = (Element) getSignedInfoElement(xmlDocument);
        System.out.println("element = " + elementToString(signedInfoElement)  );
        String signature = signElement(signedInfoElement, privateKey);
        System.out.println("Signature: " + signature);

        //test : on parse le XML, on prend le signedbody et canonisation du signedBody + signature
        String signature2 = canonicalizeAndSign(signedInfoElement, privateKey);
        System.out.println("Signature: " + signature2);

        //test en dur
        String bodyCanonisedByBenja = "<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"><ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"saml2 soapenv\"></ec:InclusiveNamespaces></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></ds:SignatureMethod><ds:Reference URI=\"#TS-8A64C6552EAFBF716616951123185611\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"><ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"wsse saml2 soapenv\"></ec:InclusiveNamespaces></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod><ds:DigestValue>/rdzTrClkJP333AqQZqar9jom01BUswQbphz/Vv/KVM=</ds:DigestValue></ds:Reference><ds:Reference URI=\"#X509-8A64C6552EAFBF716616951123185992\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"><ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"\"></ec:InclusiveNamespaces></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod><ds:DigestValue>bxRD+PJdkGPQxtm4s8wOAq+48K+0Lynaj/2dj5w8Cdw=</ds:DigestValue></ds:Reference><ds:Reference URI=\"#id-8A64C6552EAFBF716616951123186195\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"><ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"saml2\"></ec:InclusiveNamespaces></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod><ds:DigestValue>eibdF7buZIBfgWdCc5eoJekJGroNq8Du5Vd5BNawv+o=</ds:DigestValue></ds:Reference></ds:SignedInfo>";
        System.out.println("bodyCanonisedByBenja = " + bodyCanonisedByBenja);
        String signature3= signString(bodyCanonisedByBenja,privateKey);
        System.out.println("Signature3: " + signature3);


    }

    private static boolean verify(byte[] data, byte[] signature, PublicKey publicKey) throws GeneralSecurityException{
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(pubKey);
        sig.update(data);
        return sig.verify(signature);
    }
    public static Element getSignedInfoElement(Document document) {
        try {
            XPathFactory xPathFactory = XPathFactory.newInstance();
            XPath xpath = xPathFactory.newXPath();
            xpath.setNamespaceContext(new NamespaceContext() {
                public String getNamespaceURI(String prefix) {
                    if (prefix == null) throw new NullPointerException("Null prefix");
                    else if ("ds".equals(prefix)) return "http://www.w3.org/2000/09/xmldsig#";
                    else if ("xml".equals(prefix)) return XMLConstants.XML_NS_URI;
                    return XMLConstants.NULL_NS_URI;
                }

                public String getPrefix(String uri) { throw new UnsupportedOperationException(); }
                public Iterator getPrefixes(String uri) { throw new UnsupportedOperationException(); }
            });

            // Utiliser XPath pour trouver l'élément SignedInfo
            Element signedInfoElement = (Element) xpath.evaluate("//ds:SignedInfo", document, XPathConstants.NODE);
            return signedInfoElement;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    public static String elementToString(Element element) {
        try {
            StringWriter writer = new StringWriter();
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.transform(new DOMSource(element), new StreamResult(writer));
            return writer.toString();
        } catch (TransformerException e) {
            e.printStackTrace();
            return null;
        }
    }
    public static String signElement(Element element, PrivateKey privateKey) throws Exception {
        // Convertir l'élément en chaîne de caractères
        String elementString = elementToString(element);

        // Préparer l'objet Signature
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(elementString.getBytes());

        // Signer et encoder en Base64
        byte[] signatureBytes = signature.sign();
        return new String(Base64.encodeBase64(signatureBytes));
    }
    public static String signString(String element, PrivateKey privateKey) throws Exception {
        // Convertir l'élément en chaîne de caractères

        // Préparer l'objet Signature
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(element.getBytes());

        // Signer et encoder en Base64
        byte[] signatureBytes = signature.sign();
        return new String(Base64.encodeBase64(signatureBytes));
    }
    public static String canonicalizeAndSign(Element element, PrivateKey privateKey) throws Exception {
        if (!Init.isInitialized()) {
            Init.init();
        }
        // Canonisation de l'élément
        Canonicalizer c14n = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        byte[] canonicalizedBytes = c14n.canonicalizeSubtree(element);
        String canonicalizedString = new String(canonicalizedBytes, java.nio.charset.StandardCharsets.UTF_8);
        System.out.println("canonized Signedbody" + canonicalizedString);
        // Préparer et exécuter la signature
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(canonicalizedBytes);
        byte[] signatureBytes = signature.sign();
        return new String(Base64.encodeBase64(signatureBytes));

    }

}