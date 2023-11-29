package lu.mipit.wsse;

import org.joda.time.DateTime;
import org.joda.time.format.ISODateTimeFormat;
import org.opensaml.Configuration;
import org.opensaml.ws.wssecurity.Created;
import org.opensaml.ws.wssecurity.Expires;
import org.opensaml.ws.wssecurity.Timestamp;
import org.opensaml.ws.wssecurity.util.WSSecurityHelper;
import org.w3c.dom.Element;

import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import java.util.UUID;

public class Timestamp_mip {
    public static void main(String[] args) {
        // Your code here
    }
    public static Timestamp createTimestamp(int ttlSeconds) {
        Timestamp timestamp = (Timestamp) Configuration.getBuilderFactory()
                .getBuilder(Timestamp.ELEMENT_NAME)
                .buildObject(Timestamp.ELEMENT_NAME);

        DateTime currentTime = new DateTime();
        String currentTimeString = currentTime.toString(ISODateTimeFormat.dateTime());
        String expirationTimeString = currentTime.plusSeconds(ttlSeconds).toString(ISODateTimeFormat.dateTime());

        // Créer et configurer l'élément Created
        Created created = (Created) Configuration.getBuilderFactory()
                .getBuilder(Created.ELEMENT_NAME)
                .buildObject(Created.ELEMENT_NAME);
        created.setValue(currentTimeString);

        // Créer et configurer l'élément Expires
        Expires expires = (Expires) Configuration.getBuilderFactory()
                .getBuilder(Expires.ELEMENT_NAME)
                .buildObject(Expires.ELEMENT_NAME);
        expires.setValue(expirationTimeString);

        // Ajouter les éléments Created et Expires au Timestamp
        timestamp.setCreated(created);
        timestamp.setExpires(expires);

        //String wsuId = "TS-" + UUID.randomUUID().toString();
        //WSSecurityHelper.addWSUId(timestamp, wsuId);

        return timestamp;
    }
    public static SOAPMessage addTimestampToSOAP(SOAPMessage soapMessage, int ttlSeconds) throws Exception {
        // Création du Timestamp
        Timestamp timestamp = createTimestamp(ttlSeconds);

        // Convertir le Timestamp en Element DOM
        Element timestampElement = Configuration.getMarshallerFactory().getMarshaller(timestamp)
                .marshall(timestamp);

        // Obtention ou création de l'en-tête SOAP
        SOAPEnvelope envelope = soapMessage.getSOAPPart().getEnvelope();
        SOAPHeader soapHeader = envelope.getHeader();
        if (soapHeader == null) {
            soapHeader = envelope.addHeader();
        }

        // Importer l'Element DOM en tant que SOAPElement dans le SOAPHeader
        SOAPElement soapTimestampElement = (SOAPElement) soapHeader.getOwnerDocument().importNode(timestampElement, true);
        soapHeader.appendChild(soapTimestampElement);

        return soapMessage;
    }
}
