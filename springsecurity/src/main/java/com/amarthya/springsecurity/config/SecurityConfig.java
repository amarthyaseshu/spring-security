package com.amarthya.springsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
// Overriding default configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtFilter jwtFilter;

    // If we dont provide any filters like below mtd, then authentication wont be done (its like buying lock & properly not using it)
//    @Bean
//    public SecurityFilterChain seurityFilterChain(HttpSecurity http) throws Exception {
//        return http.build();
//    }

    @Bean
    public SecurityFilterChain seurityFilterChain(HttpSecurity http) throws Exception {



     return   http
                  // To disable csrf
             .csrf(customizer->customizer.disable())
                // To authenticate all requests (if this is not given wont be authenticated at all)
             .authorizeHttpRequests(request->request
                     // permit all only for register & login end pts
                     .requestMatchers("register","login")
                     .permitAll()
                     .anyRequest().authenticated())
                 // For browser to enter username & password (need to remove below one when made stateless as form login doesn't work (happens recursilvely same), automatically popup will come)
             .formLogin(Customizer.withDefaults())
                  // For postman to enter username & password
             .httpBasic(Customizer.withDefaults())
                 // To make stateless (but browser login doesnt work)
             .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
             // Authenticate jwt filter before user password authentication filter
             .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
             .build();
    }

    // This is default when we r not using DB
    // If this is implemented, default username, password doesn't work
//    @Bean
//    public UserDetailsService userDetailsService(){
//
//        UserDetails userDetails1= User.withDefaultPasswordEncoder().username("amarthya").password("am123").roles("USER")
//                .build();
//        UserDetails userDetails2= User.withDefaultPasswordEncoder().username("amarthya1").password("am1234").roles("ADMIN")
//                .build();
//
//        return new InMemoryUserDetailsManager(userDetails1,userDetails2);
//    }


    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider provider=new DaoAuthenticationProvider();
        // For normal text
       // provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
        provider.setPasswordEncoder(new BCryptPasswordEncoder(12));
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }


}
