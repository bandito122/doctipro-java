/*
 * AuthenticationRequest.java
 * Date de cr�ation: 30 juin 2015
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

package lu.ciss.mysecu.demo.wst;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.Header;
import org.opensaml.ws.wsaddressing.Address;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.ws.wspolicy.AppliesTo;
import org.opensaml.ws.wssecurity.Security;
import org.opensaml.ws.wstrust.CancelTarget;
import org.opensaml.ws.wstrust.RequestSecurityToken;
import org.opensaml.ws.wstrust.RequestType;
import org.opensaml.ws.wstrust.TokenType;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.MarshallingException;

import lu.ciss.mysecu.demo.XmlTools;

/**
 * G�n�ration des demandes de login et de logout conforme � WS-Trust version 1.3 moyennant les API d'OpenSAML.
 * Les demandes ne contiennent pas d'informations par rapport � l'authentification.
 * Ces donn�es sont � ajouter par une autre classe.
 *
 * ATTENTION:
 * IL S'AGIT D'UN PROJET DE DEMONSTRATION. IL EST DECONSEILE DE L'UTILISER EN PRODUCTION.
 *
 * @author u156gm
 * @version $Id: AuthenticationRequest.java 16672 2015-06-30 14:26:21Z u156gm $
 * @since REL_1-0-1
 *  */
public class AuthenticationRequest {

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
     * G�n�re une envelope SOAP 1.1 pour la demande d'authentification conforme � WS-Trust 1.3
     * L'envelope SOAP contient d�j� une ent�te WS-Security vide.
     *
     * @param tokenType le type de jeton demand�
     * @param applicationContext l'adresse de connexion mySecu
     * @return une envelope SOAP conforme
     */
    public static Envelope createIssueRequest(final String tokenType, final String applicationContext) {

        // 1.) cr�ation de l'envelope SOAP 1.1
        Envelope envelope = (Envelope) Configuration.getBuilderFactory().getBuilder(Envelope.DEFAULT_ELEMENT_NAME)
                .buildObject(Envelope.DEFAULT_ELEMENT_NAME);

        // 2.) cr�ation d'une ent�te SOAP 1.1
        Header header = (Header) Configuration.getBuilderFactory().getBuilder(Header.DEFAULT_ELEMENT_NAME)
                .buildObject(Header.DEFAULT_ELEMENT_NAME);
        envelope.setHeader(header);

        // 3.) cr�ation du body SOAP 1.1.
        Body body = (Body) Configuration.getBuilderFactory().getBuilder(Body.DEFAULT_ELEMENT_NAME)
                .buildObject(Body.DEFAULT_ELEMENT_NAME);
        envelope.setBody(body);

        // 4.) cr�ation de l'objet principal "wst:RequestSecurityToken"
        RequestSecurityToken rst = (RequestSecurityToken) Configuration.getBuilderFactory()
                .getBuilder(RequestSecurityToken.ELEMENT_NAME).buildObject(RequestSecurityToken.ELEMENT_NAME);
        body.getUnknownXMLObjects().add(rst);

        // 5.) cr�ation de l'objet "wst:RequestType"
        RequestType requestType = (RequestType) Configuration.getBuilderFactory().getBuilder(RequestType.ELEMENT_NAME)
                .buildObject(RequestType.ELEMENT_NAME);
        requestType.setValue(RequestType.ISSUE);
        rst.getUnknownXMLObjects().add(requestType);

        // 6.) cr�ation de l'objet "wst:RequestedTokenType"
        TokenType _tokenType = (TokenType) Configuration.getBuilderFactory().getBuilder(TokenType.ELEMENT_NAME)
                .buildObject(TokenType.ELEMENT_NAME);
        _tokenType.setValue(tokenType);
        rst.getUnknownXMLObjects().add(_tokenType);

        // 7.) cr�ation de l'objet "wsa:Address"
        Address address = (Address) Configuration.getBuilderFactory().getBuilder(Address.ELEMENT_NAME)
                .buildObject(Address.ELEMENT_NAME);
        address.setValue(applicationContext);

        // 8.) cr�ation de l'objet "wsa:EndpointReference"
        EndpointReference endpointReference = (EndpointReference) Configuration.getBuilderFactory()
                .getBuilder(EndpointReference.ELEMENT_NAME).buildObject(EndpointReference.ELEMENT_NAME);
        endpointReference.setAddress(address);

        // 9.) cr�ation de l'objet "wsp:AppliesTo"
        AppliesTo appliesTo = (AppliesTo) Configuration.getBuilderFactory().getBuilder(AppliesTo.ELEMENT_NAME)
                .buildObject(AppliesTo.ELEMENT_NAME);
        appliesTo.getUnknownXMLObjects().add(endpointReference);
        rst.getUnknownXMLObjects().add(appliesTo);

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

    /**
     * G�n�re une demande de logoff conforme � WS-Trust 1.3
     * L'envelope SOAP contient d�j� une ent�te WS-Security vide.
     *
     * @return envelope SOAP 1.1
     */
    public static Envelope createCancelRequest() {
        // 1.) cr�ation de l'envelope SOAP 1.1
        Envelope envelope = (Envelope) Configuration.getBuilderFactory().getBuilder(Envelope.DEFAULT_ELEMENT_NAME)
                .buildObject(Envelope.DEFAULT_ELEMENT_NAME);

        // 2.) cr�ation d'une ent�te SOAP 1.1
        Header header = (Header) Configuration.getBuilderFactory().getBuilder(Header.DEFAULT_ELEMENT_NAME)
                .buildObject(Header.DEFAULT_ELEMENT_NAME);
        envelope.setHeader(header);

        // 3.) cr�ation du body SOAP 1.1.
        Body body = (Body) Configuration.getBuilderFactory().getBuilder(Body.DEFAULT_ELEMENT_NAME)
                .buildObject(Body.DEFAULT_ELEMENT_NAME);
        envelope.setBody(body);

        // 4.) cr�ation de l'objet principal "wst:RequestSecurityToken"
        RequestSecurityToken rst = (RequestSecurityToken) Configuration.getBuilderFactory()
                .getBuilder(RequestSecurityToken.ELEMENT_NAME).buildObject(RequestSecurityToken.ELEMENT_NAME);
        body.getUnknownXMLObjects().add(rst);

        // 5.) cr�ation de l'objet "wst:RequestType"
        RequestType requestType = (RequestType) Configuration.getBuilderFactory().getBuilder(RequestType.ELEMENT_NAME)
                .buildObject(RequestType.ELEMENT_NAME);
        requestType.setValue(RequestType.CANCEL);
        rst.getUnknownXMLObjects().add(requestType);

        // 6.) cr�ation de l'objet "wst:CancelTarget" vide
        CancelTarget cancelTarget = (CancelTarget) Configuration.getBuilderFactory()
                .getBuilder(CancelTarget.ELEMENT_NAME).buildObject(CancelTarget.ELEMENT_NAME);
        rst.getUnknownXMLObjects().add(cancelTarget);

        // 7.) cr�ation d'une ent�te WS-Security vide
        Security wsseHeader = (Security) Configuration.getBuilderFactory().getBuilder(Security.ELEMENT_NAME)
                .buildObject(Security.ELEMENT_NAME);
        header.getUnknownXMLObjects().add(wsseHeader);

        // 8.) s�rialisation de l'envelope
        try {
            Configuration.getMarshallerFactory().getMarshaller(envelope).marshall(envelope);
        } catch (MarshallingException e) {
            throw new RuntimeException(e);
        }
        return envelope;
    }

    public static void main(String args[]) {
        Envelope message = AuthenticationRequest.createIssueRequest(Assertion.DEFAULT_ELEMENT_NAME.getNamespaceURI(),
                "https://ws.mysecu.lu/ws/soap/inttest/btt");
        System.out.println("*****************************************");
        System.out.println("Requ�te d'authentification: ");
        System.out.println("*****************************************");
        System.out.println(XmlTools.toPrettyString(message.getDOM()));
        System.out.println("\n\n");
        System.out.println("*****************************************");
        System.out.println("Requ�te de logout ");
        System.out.println("*****************************************");
        message = AuthenticationRequest.createCancelRequest();
        System.out.println(XmlTools.toPrettyString(message.getDOM()));
    }
}