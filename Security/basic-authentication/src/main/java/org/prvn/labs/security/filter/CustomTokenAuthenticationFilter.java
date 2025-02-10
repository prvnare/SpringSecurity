package org.prvn.labs.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.prvn.labs.security.authentication.CustomTokenAuthentication;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class CustomTokenAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;

    public CustomTokenAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }


    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getRequestURI().contains("/login");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //get token from the request header
        String token = request.getHeader("authorization");

        // create authentication object
        CustomTokenAuthentication authentication = new CustomTokenAuthentication(token);

        // validate with authentication manager
        Authentication fullyAuthentication = authenticationManager.authenticate(authentication);

        //set the authentication in security context
        SecurityContextHolder.getContext().setAuthentication(fullyAuthentication);

        // forward the request to next filters
        filterChain.doFilter(request, response);
    }

}
