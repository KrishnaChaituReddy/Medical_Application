package com.wecp.medicalequipmentandtrackingsystem.config;

import com.wecp.medicalequipmentandtrackingsystem.jwt.JwtRequestFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig  extends WebSecurityConfigurerAdapter{

    // implement security configuration here
    // register, login should be permitted to all
    // all other requests should be authenticated with valid JWT token


    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtRequestFilter jwtRequestFilter;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        
        auth.userDetailsService(userDetailsService).passwordEncoder(new BCryptPasswordEncoder());

    }
        protected void configure(HttpSecurity http) throws Exception {
            http
            .cors() // Enable CORS
            .and()
            .csrf().disable()
            .authorizeRequests()
            .antMatchers("/api/user/register", "/api/user/login").permitAll()
            .antMatchers(HttpMethod.POST, "/api/hospital/**").hasAnyAuthority("HOSPITAL")
            // .antMatchers("/api/hospitals/**").hasAnyAuthority("HOSPITAL")
            .antMatchers(HttpMethod.PUT, "/api/supplier/**").hasAuthority("SUPPLIER")
            .antMatchers(HttpMethod.PUT, "/api/technician/**").hasAuthority("TECHNICIAN")
            .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
            .antMatchers("/api/send-otp", "/api/reset-password","/api/verify-otp").permitAll()
            .anyRequest().authenticated()
            .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    
}