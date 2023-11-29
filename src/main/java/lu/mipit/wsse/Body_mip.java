package lu.mipit.wsse;

import lu.ciss.mysecu.demo.XmlTools;
import org.joda.time.DateTime;
import org.joda.time.format.ISODateTimeFormat;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.util.UUID;

import static lu.mipit.wsse.SAMLRequest_mip.*;

public class Body_mip {
    public static void main(String[] args) {
        // Your code here
    }
    static {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            throw new RuntimeException(e);
        }
    }
    public static Document createSamlRequestBody() {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.newDocument();

            // Créer l'élément racine AuthnRequest
            Element authnRequest = document.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol", "saml2p:AuthnRequest");
            authnRequest.setAttribute("AssertionConsumerServiceURL", "https://ws.mysecu.lu:7443");
            authnRequest.setAttribute("Destination", "https://www-integration.esante.lu/auth/realms/organization/ideosso/protocol/saml");
            authnRequest.setAttribute("ID", "saml-" + UUID.randomUUID().toString());
            authnRequest.setAttribute("IssueInstant", new DateTime().toString(ISODateTimeFormat.dateTime()));
            authnRequest.setAttribute("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:SOAP");
            authnRequest.setAttribute("Version", "2.0");

            // Ajouter l'élément Issuer
            Element issuer = document.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml2:Issuer");
            issuer.setTextContent("https://ws.mysecu.lu:7443");
            authnRequest.appendChild(issuer);

            // Créer l'élément Extensions et ses sous-éléments
            Element extensions = document.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol", "saml2p:Extensions");

            Element attribute = document.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml2:Attribute");
            attribute.setAttribute("Name", "psEHealthID");
            attribute.setAttribute("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");

            Element attributeValue = document.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml2:AttributeValue");
            attributeValue.setTextContent("2854201475"); // Exemple de valeur, à remplacer par la valeur appropriée

            attribute.appendChild(attributeValue);
            extensions.appendChild(attribute);
            authnRequest.appendChild(extensions);

            // Créer l'élément Subject
            Element subject = document.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml2:Subject");

            Element subjectConfirmation = document.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml2:SubjectConfirmation");
            subjectConfirmation.setAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer");

            subject.appendChild(subjectConfirmation);
            authnRequest.appendChild(subject);

            // Créer l'élément RequestedAuthnContext
            Element requestedAuthnContext = document.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol", "saml2p:RequestedAuthnContext");
            requestedAuthnContext.setAttribute("Comparison", "minimum");

            Element authnContextClassRef = document.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml2:AuthnContextClassRef");
            authnContextClassRef.setTextContent("urn:oasis:names:tc:SAML:2.0:ac:classes:X509");

            requestedAuthnContext.appendChild(authnContextClassRef);
            authnRequest.appendChild(requestedAuthnContext);

            document.appendChild(authnRequest);
            return document;
        } catch (Exception e) {
            throw new RuntimeException("Erreur lors de la création du corps de la requête SAML", e);
        }
    }
    public static Body createSamlSoapBody(Envelope envelope) throws MarshallingException, UnmarshallingException {
        // Création du contenu SAML
        Document samlDocument = createSamlRequestBody();

        // Utiliser l'usine de démarshalling d'OpenSAML pour convertir l'élément DOM en XMLObject
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        XMLObject samlXmlObject = unmarshallerFactory.getUnmarshaller(samlDocument.getDocumentElement()).unmarshall(samlDocument.getDocumentElement());

        // Récupérer le Body de l'enveloppe
        Body body = envelope.getBody();

        // Si le Body est null, créer un nouveau Body
        if (body == null) {
            body = (Body) Configuration.getBuilderFactory().getBuilder(Body.DEFAULT_ELEMENT_NAME).buildObject(Body.DEFAULT_ELEMENT_NAME);
            envelope.setBody(body);
        }

        // Ajouter le contenu SAML au Body
        body.getUnknownXMLObjects().add(samlXmlObject);

        // Retourner le Body modifié
        return body;
    }
    public static Body createSamlSoapBody() throws MarshallingException, UnmarshallingException {

        AuthnRequest authnRequest = createAuthnRequest("https://ws.mysecu.lu:7443", "https://www-integration.esante.lu/auth/realms/organization/ideosso/protocol/saml");
        Element authnRequestElement = convertToDOM(authnRequest);

        System.out.println("requete saml = " + XmlTools.toPrettyString(authnRequestElement));
        XMLObject samlXmlObject = convertToXMLObject(authnRequestElement);

        String xmlString = convertXMLObjectToString(samlXmlObject);
        System.out.println("Requête SAML en XML : " + xmlString);

        // Création du Body SAML
        QName bodyQName = new QName("http://schemas.xmlsoap.org/soap/envelope/", "Body", "soapenv");
        Body body = (Body) Configuration.getBuilderFactory().getBuilder(bodyQName)
                .buildObject(bodyQName);

        body.getUnknownXMLObjects().add(convertToXMLObject(authnRequestElement));

        // Retourner le Body modifié
        return body;
    }

}
