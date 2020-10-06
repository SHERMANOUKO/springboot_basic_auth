package com.sherman.securityDemo.security;

import static com.sherman.securityDemo.security.ApplicationUserRole.*;
// import static com.sherman.securityDemo.security.ApplicationUserPermission.*;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
// import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder){
        this.passwordEncoder = passwordEncoder;
    }    

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests()  
            .antMatchers("/", "index").permitAll()
            .antMatchers("/api/**").hasRole(STUDENT.name())
            // .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())
            .anyRequest()
            .authenticated()
            .and()
            .formLogin()
            .loginPage("/login").permitAll()
            .defaultSuccessUrl("/courses", true)
            .passwordParameter("password")
            .usernameParameter("username")
            .and()
            .rememberMe()
                .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                .key("mysecretkey") //defaults to two weeks
                .rememberMeParameter("remember-me")
            .and()
            .logout()
                .logoutUrl("/logout")
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "remember-me")
                .logoutSuccessUrl("/login");
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annaSmith = User.builder()
            .username("annasmith")
            .password(passwordEncoder.encode("password"))
            // .roles(STUDENT.name())
            .authorities(STUDENT.getGrantedAuthorities())
            .build();

        UserDetails lindaUser = User.builder()
            .username("linda")
            .password(passwordEncoder.encode("passwoord123"))
            // .roles(ADMIN.name())
            .authorities(ADMIN.getGrantedAuthorities())
            .build();

        UserDetails tomUser = User.builder()
            .username("tom")
            .password(passwordEncoder.encode("passwoord123"))
            // .roles(ADMINTRAINEE.name())
            .authorities(ADMINTRAINEE.getGrantedAuthorities())
            .build();

        return new InMemoryUserDetailsManager(
            annaSmith, 
            lindaUser,
            tomUser
        );
    }
    
}
