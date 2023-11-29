package lu.mipit.wsse;

import lu.ciss.mysecu.demo.XmlTools;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.common.impl.ExtensionsBuilder;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.xml.*;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.schema.XSAny;
import org.w3c.dom.Element;
import org.joda.time.DateTime;

import java.util.UUID;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.impl.AttributeBuilder;

public class SAMLRequest_mip {

    static {
        try {
            DefaultBootstrap.bootstrap();

        } catch (ConfigurationException e) {
            throw new RuntimeException("Erreur lors de l'initialisation d'OpenSAML", e);
        }
    }

    public static AuthnRequest createAuthnRequest(String assertionConsumerServiceURL, String destination) {


        /// Création de AuthnRequest
        AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();
        authnRequest.setAssertionConsumerServiceURL("https://ws.mysecu.lu:7443");
        authnRequest.setDestination("https://www-integration.esante.lu/auth/realms/organization/ideosso/protocol/saml");
        authnRequest.setID("saml-" + UUID.randomUUID().toString());
        authnRequest.setIssueInstant(new DateTime());
        authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:SOAP");
        authnRequest.setVersion(SAMLVersion.VERSION_20);

// Ajout de Issuer
        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue("https://ws.mysecu.lu:7443");
        authnRequest.setIssuer(issuer);

// Création et ajout des Extensions
        Extensions extensions = new ExtensionsBuilder().buildObject(SAMLConstants.SAML20P_NS, "Extensions", "saml2p");

// Création et configuration de l'Attribute
        Attribute attribute = new AttributeBuilder().buildObject();
        attribute.setName("psEHealthID");
        attribute.setNameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");

// Création et ajout de l'AttributeValue
//        XSStringBuilder stringBuilder = (XSStringBuilder) Configuration.getBuilderFactory().getBuilder(XSString.TYPE_NAME);
//        XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
//        stringValue.setValue("2854201475");
//        attribute.getAttributeValues().add(stringValue);
        // Création d'un AttributeValue en tant qu'élément XML basique
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        XMLObjectBuilder<XSAny> attributeValueBuilder = builderFactory.getBuilder(XSAny.TYPE_NAME);
        XSAny attributeValue = attributeValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);

// Ajout de la valeur textuelle directement
        attributeValue.setTextContent("2854201475");
        attribute.getAttributeValues().add(attributeValue);
// Ajout de l'Attribute aux Extensions
        extensions.getUnknownXMLObjects().add(attribute);
        authnRequest.setExtensions(extensions);

// Ajout de Subject
        Subject subject = new SubjectBuilder().buildObject();
        SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
        subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
        subject.getSubjectConfirmations().add(subjectConfirmation);
        authnRequest.setSubject(subject);

// Ajout de RequestedAuthnContext
        RequestedAuthnContext requestedAuthnContext = new RequestedAuthnContextBuilder().buildObject();
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
        AuthnContextClassRef authnContextClassRef = new AuthnContextClassRefBuilder().buildObject();
        authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:X509");
        requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
        authnRequest.setRequestedAuthnContext(requestedAuthnContext);




        return authnRequest;
    }

    public static Element convertToDOM(AuthnRequest authnRequest) throws MarshallingException {
        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(authnRequest);
        return marshaller.marshall(authnRequest);
    }

    public static XMLObject convertToXMLObject(Element element) throws UnmarshallingException {
        Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(element);
        return unmarshaller.unmarshall(element);
    }
    public static String convertXMLObjectToString(XMLObject xmlObject) throws MarshallingException {
        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(xmlObject);
        Element element = marshaller.marshall(xmlObject);
        return XmlTools.toPrettyString(element);
    }
    public static void main(String[] args) {
        try {
            AuthnRequest authnRequest = createAuthnRequest("https://ws.mysecu.lu:7443", "https://www-integration.esante.lu/auth/realms/organization/ideosso/protocol/saml");
            Element element = convertToDOM(authnRequest);

            System.out.println("requete saml = " + XmlTools.toPrettyString(element));
            XMLObject xmlObject = convertToXMLObject(element);

            String xmlString = convertXMLObjectToString(xmlObject);
            System.out.println("Requête SAML en XML : " + xmlString);
            // Ici, xmlObject contient la requête AuthnRequest SAML prête à être utilisée
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
