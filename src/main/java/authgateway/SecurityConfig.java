package authgateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;
    private final CustomSAML2AuthenticationProvider customSAML2AuthenticationProvider;

    public SecurityConfig(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
                          CustomSAML2AuthenticationProvider customSAML2AuthenticationProvider) {
        this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
        this.customSAML2AuthenticationProvider = customSAML2AuthenticationProvider;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .saml2Login(withDefaults())
                .saml2Logout(withDefaults())
                .authenticationProvider(customSAML2AuthenticationProvider);  // Register custom provider

        return http.build();
    }
}


