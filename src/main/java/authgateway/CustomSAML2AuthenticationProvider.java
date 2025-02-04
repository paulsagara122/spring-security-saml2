package authgateway;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Collections;

@Component
public class CustomSAML2AuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws BadCredentialsException {
        if (!(authentication instanceof Saml2AuthenticationToken)) {
            throw new BadCredentialsException("Authentication type not supported");
        }

        Saml2AuthenticationToken token = (Saml2AuthenticationToken) authentication;

        // Get the SAML response (the raw SAML response string)
        String saml2Response = token.getSaml2Response(); // This gets the raw SAML response

        if (saml2Response == null || saml2Response.isEmpty()) {
            throw new BadCredentialsException("SAML response is empty or invalid");
        }

        // Parse the response using the Saml2ResponseParser utility class
        Response response = Saml2ResponseParser.parseSaml2Response(saml2Response);

        // Assuming only the first assertion is needed
        Assertion assertion = response.getAssertions().get(0);

        // Validate the assertion signature and perform other checks
        validateAssertionSignature(assertion);

        // Get the principal from the assertion (usually the NameID)
        String principalName = assertion.getSubject().getNameID().getValue();

        // Create an authenticated principal (User object)
        User principal = new User(principalName, "", AuthorityUtils.createAuthorityList("ROLE_USER"));

        // Return the authentication object with the raw SAML response
        return new Saml2Authentication((AuthenticatedPrincipal) principal, saml2Response,
                AuthorityUtils.createAuthorityList("ROLE_USER"));
    }

    private void validateAssertionSignature(Assertion assertion) {
        // Signature validation logic (simplified)
        if (assertion.getSignature() == null) {
            throw new BadCredentialsException("Invalid assertion signature");
        }
        // Implement signature verification logic here using a public key, etc.
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return Saml2AuthenticationToken.class.isAssignableFrom(authentication);
    }
}
