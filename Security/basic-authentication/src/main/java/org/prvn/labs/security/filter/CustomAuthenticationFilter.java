package org.prvn.labs.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.prvn.labs.model.Otp;
import org.prvn.labs.security.authentication.UsernameOTPAuthentication;
import org.prvn.labs.security.authentication.UsernamePasswordAuthentication;
import org.prvn.labs.security.manager.SecurityOTPUserDetailManager;
import org.prvn.labs.security.manager.TokenManager;
import org.prvn.labs.security.model.OTPUserDetails;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

import java.util.List;
import java.util.Objects;
import java.util.UUID;


public class CustomAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final SecurityOTPUserDetailManager otpUserDetailManager;
    private final TokenManager tokenManager;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager, SecurityOTPUserDetailManager otpUserDetailManager, TokenManager tokenManager) {
        this.authenticationManager = authenticationManager;
        this.otpUserDetailManager = otpUserDetailManager;
        this.tokenManager = tokenManager;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)  {
        // logic to write how to call the manager and delegate the logic to provider

        String username = request.getHeader("username");
        String password = request.getHeader("password");
        String otp = request.getHeader("otp");

        if(Objects.isNull(password) && Objects.isNull(otp)){
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            return ;
        }

        if(Objects.isNull(otp)){

            //create authentication Object
            Authentication authentication = new UsernamePasswordAuthentication(username, password, List.of(()->"read"));

            // pass the authentication to the authentication manager
            authenticationManager.authenticate(authentication);

            //if  authenticated , then generate the OTP and save it to database
            UUID tempOTP = UUID.randomUUID();

            OTPUserDetails otpUserDetails = new OTPUserDetails(Otp.builder().username(username).otp(tempOTP).build());
            otpUserDetailManager.createUser(otpUserDetails);

            // set the otp to the response header
            response.setHeader("otp", tempOTP.toString());

        }else{
            Authentication authentication = new UsernameOTPAuthentication(username, otp, List.of(()->"read"));
            authenticationManager.authenticate(authentication);

            //generate random token and place it in response header
            UUID token = UUID.randomUUID();
            response.setHeader("token", token.toString());

            // add this token to token manager
            tokenManager.add(token);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {

        // logic to implement when this filter will get activated
        // use this filter if request contain login as URI
        return !request.getRequestURI().equals("/login");
    }

}
