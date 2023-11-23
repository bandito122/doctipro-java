package lu.mipit.wsse;

import org.apache.xml.security.Init;
import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;

public class BinarySecurityTokenCreator {
    public static void main(String[] args) {
        try {
            Init.init(); // Appel à la méthode d'initialisation

            // Créer un Document XML
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document document = dBuilder.newDocument();

            // Créer l'élément Security
            Element securityElement = document.createElement("wsse:Security");
            securityElement.setAttribute("xmlns:wsse", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
            securityElement.setAttribute("xmlns:wsu", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
            document.appendChild(securityElement);

            // Chaîne de certificat depuis l'exemple
            String certificateString = "MIIGqjCCBJKgAwIBAgIIVVH8QaoVhQYwDQYJKoZIhvcNAQELBQAwPTEWMBQGA1UEAwwNQWVTLUktQ0EtVGVzdDEWMBQGA1UECgwNQWdlbmC...";

            // Créer l'élément BinarySecurityToken
            Element binarySecurityTokenElement = document.createElement("wsse:BinarySecurityToken");
            binarySecurityTokenElement.setAttribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
            binarySecurityTokenElement.setAttribute("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-tokenprofile-1.0#X509v3");
            binarySecurityTokenElement.setAttribute("wsu:Id", "X509-" + generateRandomId());

            // Convertir la chaîne de certificat en bytes
            byte[] certBytes = Base64.decode(certificateString);

            // Créer un texte (contenu) pour BinarySecurityToken en utilisant le certificat Base64
            Text textNode = document.createTextNode(Base64.encode(certBytes));

            // Ajouter le texte comme enfant de BinarySecurityToken
            binarySecurityTokenElement.appendChild(textNode);

            // Ajouter BinarySecurityToken comme enfant de Security
            securityElement.appendChild(binarySecurityTokenElement);

            // Vous pouvez maintenant utiliser document comme votre message SOAP sécurisé avec BinarySecurityToken

            // Exemple d'impression du résultat (à des fins de débogage)
            System.out.println(elementToString((Element) document));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Générer un identifiant aléatoire pour wsu:Id
    private static String generateRandomId() {
        return Long.toHexString(Double.doubleToLongBits(Math.random()));
    }

    // Convertir un élément DOM en chaîne de caractères XML
    private static String elementToString(Element element) {
        try {
            Document document = element.getOwnerDocument();
            DOMSource source = new DOMSource(element);
            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.transform(source, result);
            return writer.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
