package com.starter.backend.security.doc;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class DocSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    // private static final Logger logger =
    // LoggerFactory.getLogger(DocSuccessHandler.class);

    // @Override
    // public void onAuthenticationSuccess(HttpServletRequest request,
    // HttpServletResponse response,
    // Authentication authentication) throws IOException, ServletException {
    // System.out.println("alaa eddine");
    // logger.error("asdsadasdad asd sad as d asd");
    // throw new RuntimeException("This is a test exception");
    // }

    protected Log logger = LogFactory.getLog(this.getClass());

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Value("${app.docs.roleCheck}")
        private String docs_role;
        
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
            HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        if (authentication != null && authentication.isAuthenticated()) {
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            List<String> roles = authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
            for (String string : roles) {
                logger.info(string);
            }
            if (roles.contains(docs_role)) {
                getRedirectStrategy().sendRedirect(request, response, "/doc/api-docs-ui");
                return;
            }
        }
        getRedirectStrategy().sendRedirect(request, response, "/doc/login?error");

    }
}
