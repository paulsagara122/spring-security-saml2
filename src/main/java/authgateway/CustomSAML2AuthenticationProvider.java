package authgateway;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class CustomSAML2AuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws BadCredentialsException {
        if (!(authentication instanceof Saml2AuthenticationToken)) {
            throw new BadCredentialsException("Authentication type not supported");
        }

        Saml2AuthenticationToken token = (Saml2AuthenticationToken) authentication;

        // Get the raw SAML response
        String saml2Response = token.getSaml2Response();
        if (saml2Response == null || saml2Response.isEmpty()) {
            throw new BadCredentialsException("SAML response is empty or invalid");
        }

        // Parse the SAML response
        Response response;
        try {
            response = Saml2ResponseParser.parseSaml2Response(saml2Response);
        } catch (Exception e) {
            throw new RuntimeException("Error parsing SAML response", e);
        }

        // Extract user details from SAML assertion
        Assertion assertion = response.getAssertions().get(0);
        String principalName = assertion.getSubject().getNameID().getValue();

        // Extract attributes from the assertion
        Map<String, List<Object>> attributes = new HashMap<>();
        for (AttributeStatement statement : assertion.getAttributeStatements()) {
            for (Attribute attribute : statement.getAttributes()) {
                List<Object> attributeValues = new ArrayList<>();
                // Log to debug the attribute name and values
                System.out.println("Attribute Name: " + attribute.getName());
                attribute.getAttributeValues().forEach(value -> {
                    String valueStr = value.getDOM().getTextContent();  // Ensure extracting the correct value as String
                    System.out.println("Attribute Value: " + valueStr);  // Log each value to check if they are correct
                    attributeValues.add(valueStr);  // Add the value as a string
                });
                attributes.put(attribute.getName(), attributeValues);
            }
        }

        // Debugging: Log attributes to check
        System.out.println("Extracted Attributes: " + attributes);

        // Assign roles/authorities based on attributes (like 'Role')
        List<GrantedAuthority> authorities = new ArrayList<>();
        if (attributes.containsKey("Role")) {
            List<Object> roles = attributes.get("Role");
            for (Object role : roles) {
                authorities.add(() -> "ROLE_" + role.toString().toUpperCase());
            }
        } else {
            authorities.add(() -> "ROLE_USER");
        }

        // Assign the Department to authorities if needed (optional)
        if (attributes.containsKey("Department")) {
            List<Object> departments = attributes.get("Department");
            for (Object department : departments) {
                System.out.println("Department: " + department);  // Log the department
            }
        }

        // Create a valid Saml2AuthenticatedPrincipal
        Saml2AuthenticatedPrincipal principal = new Saml2AuthenticatedPrincipal() {
            @Override
            public String getName() {
                return principalName;
            }

            @Override
            public Map<String, List<Object>> getAttributes() {
                return attributes;
            }
        };

        // Return a properly constructed Saml2Authentication object
        return new Saml2Authentication(principal, saml2Response, authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return Saml2AuthenticationToken.class.isAssignableFrom(authentication);
    }
}
