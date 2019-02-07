package fr.solutec.web.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import fr.solutec.persistence.enums.RoleEnum;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final String adminRole = RoleEnum.ADMINISTRATOR.name();

    private final UserDetailsService userDetailsService;

    @Autowired
    public WebSecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public static NoOpPasswordEncoder noOpEncoder() {
     return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    }
    
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(noOpEncoder());
    }
    /**
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) 
      throws Exception {
        auth
          .inMemoryAuthentication()
          .withUser("user").password(noOpEncoder().encode("password")).roles("USER")
          .and()
          .withUser("admin").password(noOpEncoder().encode("admin")).roles("ADMIN");
    }*/    
    /**
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // the boolean flags force the redirection even though 
        // the user requested a specific secured resource.
        http.formLogin().defaultSuccessUrl("/success.html", true);
    }*/
    
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/auth**").authenticated()
                .antMatchers("/auth/admin**").hasAuthority(adminRole)
                .anyRequest().permitAll()
            .and()
                .formLogin().loginPage("/login").defaultSuccessUrl("/auth").failureUrl("/login")
                .usernameParameter("username").passwordParameter("password")
            .and()
                .logout().invalidateHttpSession(true)
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
            .and()
                .csrf()
            .and()
                .sessionManagement().maximumSessions(1).expiredUrl("/login");
    } 
}