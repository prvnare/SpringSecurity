package org.prvn.labs.security.config;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

@Configuration
public class ProjectConfig {

    // InMemory Client Registration
    @Bean
    public RegisteredClientRepository registeredClientRepository()  {
        var client = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("client")
                .clientSecret("secret")
                .redirectUri("https://springone.io/authorized")
                .authorizationGrantTypes(grantTypes -> {
                    grantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                    grantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
                    grantTypes.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
                })
//      These scopes are used for OIDC --> Usually not required if you don't use OIDC
                 //.scope(OidcScopes.OPENID)
                 //.scope(OidcScopes.PROFILE)
//      if you user user defined scope like read, consent form will be displayed and user has to consent the request
                .scope("read")
//      Authentication should be NONE , if you use the PKCE for Authorization_code , spring detects the PKCE to validate the Code_verifier
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .build();
        return new InMemoryRegisteredClientRepository(List.of(client));
    }

    // enabling oauth2 server
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();
        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, Customizer.withDefaults())
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());

//      Enables the OIDC support for Authorization server --> NOT Required if you don't want to use the OIDC

        //      http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());

//      redirects to login if any error happens
        http.exceptionHandling(exception ->
                exception.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
        return http.build();
    }


    // Security Filter chain with form login
    @Bean
    @Order(2)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .formLogin(login-> login.loginProcessingUrl("/login"))
                .authorizeHttpRequests(auth-> auth.anyRequest().authenticated())
                .build();
    }


    //InMemory user details service to authenticate the user
    @Bean
    public UserDetailsService userDetailsService() {

        UserDetails userOne = User.withUsername("userOne").password(passwordEncoder().encode("password")).roles("USER").build();
        UserDetails userTwo = User.withUsername("userTwo").password(passwordEncoder().encode("password")).roles("USER").build();
        UserDetails userThree = User.withUsername("userThree").password(passwordEncoder().encode("password")).roles("USER").build();
        return new InMemoryUserDetailsManager(userOne, userTwo, userThree);
    }

    // password encoder to encode the password
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    // To customize the Oauth2 endpoints
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().issuer("http://localhost:9090").build();
    }

    //registering the key to sign the Token
    @Bean
    public JWKSource<SecurityContext> jwkSource() {

        try {
            //Get keypair Generator for RSA
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

            //with Size of 2048
            keyPairGenerator.initialize(2048);

            //get keypair
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            //get private key
            RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();

            //get public key
            RSAPublicKey publicKey =(RSAPublicKey) keyPair.getPublic();

            //build RSA KEY
            RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();

            //GET JWS SET
            JWKSet jwkSet = new JWKSet(rsaKey);

            // create immutable JWK SET
            return  new ImmutableJWKSet<>(jwkSet);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }


    }
}
