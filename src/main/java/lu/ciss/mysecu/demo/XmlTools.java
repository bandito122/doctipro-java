/*
 * XmlTools.java
 * Date de cr�ation: 15 juin 2015
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

package lu.ciss.mysecu.demo;

import java.io.FileInputStream;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Utilitaires XML
 *
 * ATTENTION:
 * IL S'AGIT D'UN PROJET DE DEMONSTRATION. IL EST DECONSEILE DE L'UTILISER EN PRODUCTION.
 *
 * @author u156gm
 * @version $Id: XmlTools.java 16672 2015-06-30 14:26:21Z u156gm $
 * @since REL_1-0-0
 */
public final class XmlTools {

    /**
     * Retourne l'�l�ment XML sous forme textuelle
     *
     * @param element
     * @return objet String de l'�l�ment XML
     */
    public static final String toPrettyString(Element element) {
        try {
            TransformerFactory transFactory = TransformerFactory.newInstance();
            Transformer transformer = transFactory.newTransformer();
            StringWriter buffer = new StringWriter();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.transform(new DOMSource(element),
                    new StreamResult(buffer));
            String str = buffer.toString();
            return str;
        } catch (TransformerException e) {
            e.printStackTrace();
            return null;
        }
    }
    public static final String toOneLineString(Element element) {
        try {
            TransformerFactory transFactory = TransformerFactory.newInstance();
            Transformer transformer = transFactory.newTransformer();
            StringWriter buffer = new StringWriter();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "no"); // Pas d'indentation
            transformer.transform(new DOMSource(element), new StreamResult(buffer));
            String str = buffer.toString();
            return str;
        } catch (TransformerException e) {
            e.printStackTrace();
            return null;
        }
    }


    /**
     * Charge un document XML via DOM depuis un fichier.
     *
     * @param pathToFile chemin vers le fichier XML
     * @return document XML pars� via DOM
     */
    public static final Document loadFromFile(final String pathToFile) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            return builder.parse(new FileInputStream(pathToFile));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Cr�er un nouveau document et y ajouter l'�l�ment fourni.
     *
     * @param element
     * @return
     */
    public static final Document fromElement(final Element element) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.newDocument();
            document.appendChild(element);
            return document;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Convertir un document XML en message SOAP 1.1 ou 1.2
     *
     * @param xmlDocument le document XML pars� sous forme DOM
     * @return l'encapsulation Java d'un message SOAP
     */
    public static final SOAPMessage convertToSoapMessage(final Document xmlDocument) {
        try {
            MessageFactory factory = MessageFactory.newInstance();
            SOAPMessage m = factory.createMessage();
            m.getSOAPPart().setContent(new DOMSource(xmlDocument));
            return m;
        } catch (SOAPException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Convertir un message SOAP en document XML
     *
     * @param soapMessage le message SOAP
     * @return le document XML sous forme DOM
     */
    public static final Document convertToDocument(final SOAPMessage soapMessage) {
        try {
            Source src = soapMessage.getSOAPPart().getContent();
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            DOMResult result = new DOMResult();
            transformer.transform(src, result);
            return (Document) result.getNode();
        } catch (Exception e)
        {
            throw new RuntimeException(e);
        }
    }
}