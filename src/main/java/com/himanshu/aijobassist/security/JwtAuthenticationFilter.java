package com.himanshu.aijobassist.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
// OncePerRequestFilter = runs exactly once per HTTP request (not multiple times)
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // Step 1: Read the Authorization header from the incoming request
        // Every authenticated request must have: "Authorization: Bearer <token>"
        final String authHeader = request.getHeader("Authorization");

        // Step 2: If header is missing OR doesn't start with "Bearer ", skip this filter
        // This handles public endpoints like /api/auth/login — no token needed
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Step 3: Extract just the token part (remove "Bearer " prefix — 7 characters)
        // "Bearer eyJhbGci..." → "eyJhbGci..."
        final String jwt = authHeader.substring(7);

        // Step 4: Validate the token — is it real, not expired, not tampered?
        if (!jwtUtil.validateToken(jwt)) {
            // Invalid token → skip, Spring Security will return 401 via EntryPoint
            filterChain.doFilter(request, response);
            return;
        }

        // Step 5: Token is valid → extract the email stored inside it
        String email = jwtUtil.extractEmail(jwt);

        // Step 6: Only proceed if email exists AND user isn't already authenticated
        // (Prevents re-authenticating on the same request)
        if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Step 7: Load the full user details from our database using the email
            UserDetails userDetails = userDetailsService.loadUserByUsername(email);

            // Step 8: Create an authentication object Spring Security understands
            // Parameters: (who is the user, credentials=null since JWT, their roles)
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );

            // Step 9: Attach request details (IP address, session info) to the auth token
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // Step 10: Tell Spring Security "this user is authenticated for this request"
            // SecurityContextHolder = Spring's memory for the current request
            SecurityContextHolder.getContext().setAuthentication(authToken);
        }

        // Step 11: ALWAYS pass the request to the next filter in the chain
        // This must be called regardless of whether authentication succeeded or not
        filterChain.doFilter(request, response);
    }
}

