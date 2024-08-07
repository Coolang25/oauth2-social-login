package com.alibou.oauth2.social.security;

import com.alibou.oauth2.social.config.CustomOAuth2UserService;
import com.alibou.oauth2.social.config.OAuthLoginSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf()
          .disable()
        .authorizeHttpRequests()
          .anyRequest()
          .authenticated()
          .and()
        .oauth2Login()
            //.loginPage("/login")
            .userInfoEndpoint()
              .userService(oauth2UserService)
            .and()
            .successHandler(oauthLoginSuccessHandler)
            .defaultSuccessUrl("/api/v1/demo", true)
            .and()
        .logout()
            .invalidateHttpSession(true)
            .clearAuthentication(true)
            .deleteCookies("JSESSIONID")
            .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
            //.logoutSuccessUrl("/login?logout")
            //.permitAll()
            .and()
              .sessionManagement(session -> session
                .maximumSessions(1))

    ;
    return http.build();
  }

  @Autowired
  private CustomOAuth2UserService oauth2UserService;

  @Autowired
  private OAuthLoginSuccessHandler oauthLoginSuccessHandler;
}
