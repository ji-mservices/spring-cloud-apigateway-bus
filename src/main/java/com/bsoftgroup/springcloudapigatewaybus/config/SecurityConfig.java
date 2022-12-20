package com.bsoftgroup.springcloudapigatewaybus.config;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAthFilter jwtAthFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

//        http
//                .cors().and()
//                .csrf().disable()   //use requests per request without session - Disable spoofing (copy url in one browser and use it in another browser)
//                .authorizeHttpRequests()
////                .requestMatchers("/auth/**")
////                .permitAll()
//                .anyRequest()
//                .authenticated()
//                .and()
//                .sessionManagement()
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)   //Don't save session data
//                .and()
//                .exceptionHandling().authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED)) // Exception Management: if an error occur, return unauthorized response
//                .and()
////                .authenticationProvider(authenticationProvider())
//                .addFilterAfter(jwtAthFilter, UsernamePasswordAuthenticationFilter.class);  //apply filter


        http
                .csrf().disable()
                // make sure we use stateless session; session won't be used to store user's state.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
                // handle an authorized attempts
//                .exceptionHandling().authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .and()
                // Add a filter to validate the tokens with every request
                .addFilterAfter(jwtAthFilter, UsernamePasswordAuthenticationFilter.class)
                // authorization requests config
                .authorizeHttpRequests()
                // allow all who are accessing "auth" service
                .requestMatchers(HttpMethod.POST, "/security/**").permitAll()
                .requestMatchers(HttpMethod.GET, "**").permitAll()
                // must be an admin if trying to access admin area (authentication is also required here)
                //.antMatchers("/gallery" + "/admin/**").hasRole("ADMIN")
                // Any other request must be authenticated
                .anyRequest().authenticated();

        return http.build();
    }

//    @Bean
//    public AuthenticationProvider authenticationProvider() {
//
//        final DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
//        authenticationProvider.setUserDetailsService(userDetailsService());
//        authenticationProvider.setPasswordEncoder(passwordEncoder());
//        return authenticationProvider;
//    }

//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
//        return config.getAuthenticationManager();
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//        return userService::getUserDetailByUsername;
//    }

    //CORS configuration
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedHeaders(List.of("X-Requested-With", "Origin", "Origin.Accept", "Content-Type", "Accept",
                "Authorization", "Access-Control-Allow-Headers", "Access-Control-Allow-Methods", "Access-Control-Expose-Headers", "Access-Control-Max-Age",
                "Access-Control-Request-Headers", "Access-Control-Request-Method", "Age", "Allow", "Alternates",
                "Content-Range", "Content-Disposition", "Content-Description"));
        configuration.setExposedHeaders(List.of("Access-Control-Allow-Credentials", "Access-Control-Allow-Origin"));
        configuration.setAllowedOriginPatterns(List.of("*"));
        configuration.setAllowedMethods(List.of("GET", "POST", "OPTIONS", "PUT", "PATCH", "DELETE"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}
