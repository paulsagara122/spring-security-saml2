package authgateway;

import org.apache.commons.codec.binary.Base64;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class Saml2ResponseParser {

    /**
     * Parse the SAML response string to OpenSAML Response object.
     *
     * @param saml2Response The base64 encoded SAML response string
     * @return Parsed Response object from the SAML response
     * @throws BadCredentialsException If there's any error while parsing the response
     */
    public static Response parseSaml2Response(String saml2Response) {
        try {
            if (StringUtils.isEmpty(saml2Response)) {
                throw new BadCredentialsException("SAML response is empty");
            }

            // Step 1: Decode the base64 SAML response
            byte[] decodedResponse = Base64.decodeBase64(saml2Response);

            // Step 2: Convert decoded byte array into an InputStream (XML input stream)
            InputStream inputStream = new ByteArrayInputStream(decodedResponse);

            // Step 3: Parse the XML input stream into a DOM Element
            Element element = parseXML(inputStream);

            // Step 4: Unmarshal the XML Element into an OpenSAML Response object
            return unmarshalResponse(element);

        } catch (Exception e) {
            throw new BadCredentialsException("Error parsing SAML response", e);
        }
    }

    /**
     * Parse the XML input stream into a DOM Element.
     *
     * @param inputStream The input stream containing the XML data
     * @return The parsed DOM Element
     * @throws Exception If there's an error while parsing the XML
     */
    private static Element parseXML(InputStream inputStream) throws Exception {
        // Use an XML parser to parse the InputStream into an Element
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        org.w3c.dom.Document document = builder.parse(inputStream);
        return document.getDocumentElement();
    }

    /**
     * Unmarshal the XML Element into an OpenSAML Response object.
     *
     * @param element The DOM Element containing the SAML response XML
     * @return The unmarshalled OpenSAML Response object
     * @throws Exception If there's an error while unmarshalling the response
     */
    private static Response unmarshalResponse(Element element) throws Exception {
        // Get the unmarshaller for the Response class
        Unmarshaller unmarshaller = XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
                .getUnmarshaller(element);

        // Unmarshal the XML element into a Response object
        XMLObject xmlObject = unmarshaller.unmarshall(element);

        if (xmlObject instanceof Response) {
            return (Response) xmlObject;
        } else {
            throw new BadCredentialsException("Invalid SAML response format");
        }
    }
}
