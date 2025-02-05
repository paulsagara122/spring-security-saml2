package authgateway;

import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Base64;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.Init;
import org.xml.sax.SAXException;

public class Saml2ResponseParser {
    public static Response parseSaml2Response(String saml2Response) throws Exception {
        // Initialize OpenSAML library
        InitializationService.initialize();

        // Determine whether to decode the input
        byte[] decodedBytes;
        if (isBase64Encoded(saml2Response)) {
            decodedBytes = Base64.getDecoder().decode(saml2Response);
        } else {
            decodedBytes = saml2Response.getBytes(); // Use raw XML directly
        }

        ByteArrayInputStream is = new ByteArrayInputStream(decodedBytes);

        // Parse the SAML response XML
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(is);
        Element rootElement = document.getDocumentElement();

        // Unmarshall the SAML response
        Unmarshaller unmarshaller = XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(rootElement);
        if (unmarshaller == null) {
            throw new UnmarshallingException("No unmarshaller found for root element");
        }
        return (Response) unmarshaller.unmarshall(rootElement);
    }

    // Helper method to check if a string is Base64-encoded
    private static boolean isBase64Encoded(String input) {
        return input.matches("^[A-Za-z0-9+/=]+$");
    }
}
