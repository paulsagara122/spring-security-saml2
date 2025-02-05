package authgateway;

import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.security.core.annotation.AuthenticationPrincipal;

import java.util.Optional;

@Controller
public class MainController {

    @GetMapping("/")
    public String index(Model model, @AuthenticationPrincipal Saml2AuthenticatedPrincipal principal) {
        if (principal == null) {
            model.addAttribute("error", "User not authenticated.");
            return "index";
        }

        String emailAddress = principal.getName();

        // Use Optional to safely handle the attribute retrieval with a default value fallback
        String role = Optional.ofNullable(principal.getAttributes().get("Role"))
                .flatMap(attrs -> attrs.stream().findFirst())
                .map(Object::toString)
                .orElse("Unknown");

        String department = Optional.ofNullable(principal.getAttributes().get("Department"))
                .flatMap(attrs -> attrs.stream().findFirst())
                .map(Object::toString)
                .orElse("Unknown");

        model.addAttribute("emailAddress", emailAddress);
        model.addAttribute("role", role);
        model.addAttribute("department", department);
        model.addAttribute("userAttributes", principal.getAttributes());

        return "index";
    }
}
