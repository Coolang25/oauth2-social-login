package com.alibou.oauth2.social.security;

import com.alibou.oauth2.social.config.CustomOAuth2UserService;
import com.alibou.oauth2.social.config.OAuthLoginSuccessHandler;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf(Customizer.withDefaults())
        .cors(Customizer.withDefaults())
        .authorizeHttpRequests()
          .anyRequest()
          .authenticated()
          .and()

        .oauth2Login(
                oauth2 ->
                        oauth2
                                //.loginPage("/login")
                                .userInfoEndpoint(userEnpoint -> userEnpoint.userService(oauth2UserService))
                                .successHandler(oauthLoginSuccessHandler)
                                //.defaultSuccessUrl("/api/v1/demo", true)
        )
//        .oauth2Login()
//            //.loginPage("/login")
//            .userInfoEndpoint()
//              .userService(oauth2UserService)
//            .and()
//            .defaultSuccessUrl("/api/v1/demo", true)
//            .successHandler(oauthLoginSuccessHandler)
//
//            .and()
        .logout()
            .invalidateHttpSession(true)
            .clearAuthentication(true)
            .deleteCookies("JSESSIONID")
            .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
            //.logoutSuccessUrl("/login?logout")
            //.permitAll()
            //.logoutSuccessHandler()


    ;
    return http.build();
  }


  @Autowired
  private CustomOAuth2UserService oauth2UserService;

  @Autowired
  private OAuthLoginSuccessHandler oauthLoginSuccessHandler;

  @Bean
  CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.addAllowedOrigin("*");
    configuration.addAllowedHeader("*");
    configuration.addAllowedMethod("*");
    configuration.setAllowCredentials(true);
    UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
    urlBasedCorsConfigurationSource.registerCorsConfiguration("/**", configuration);
    return urlBasedCorsConfigurationSource;
  }
}
