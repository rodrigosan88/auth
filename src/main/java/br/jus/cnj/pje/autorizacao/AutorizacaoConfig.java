package br.jus.cnj.pje.autorizacao;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import br.jus.cnj.pje.autorizacao.jwt.AutenticacaoJWTEntryPoint;
import br.jus.cnj.pje.autorizacao.jwt.AutenticacaoJWTFilter;

@Configuration
@EnableWebSecurity
@EnableOAuth2Sso
public class AutorizacaoConfig extends WebSecurityConfigurerAdapter{

	@Autowired
	private DataSource dataSource;
	
	@Autowired
	private AutenticacaoJWTEntryPoint entryPoint;
	
	@Autowired
	private ResourceServerTokenServices resourceServerTokenServices;
	
	@Autowired
	public void configurarAutenticacao(AuthenticationManagerBuilder aut) throws Exception{
		aut.jdbcAuthentication()
			.dataSource(dataSource)
			.passwordEncoder(getPasswordEncoder())
			.usersByUsernameQuery(getUsersByUsernameQuery())
			.authoritiesByUsernameQuery(getAuthoritiesByUsernameQuery());
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
        http
        .csrf().disable()
        .exceptionHandling().authenticationEntryPoint(entryPoint).and()
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
        .authorizeRequests()
        .antMatchers(
                HttpMethod.GET,
                "/",
                "/*.html",
                "/favicon.ico",
                "/**/*.html",
                "/**/*.css",
                "/**/*.js"
        ).permitAll()
        .antMatchers("/autenticar/**").permitAll()
        .antMatchers("/validar/**").permitAll()
        .antMatchers("/criarUsuario/**").permitAll()
        .antMatchers("/oauth/token/**").permitAll()
        .antMatchers("/oauth/authorize/**").permitAll()
        .anyRequest().authenticated()
        .and().formLogin().permitAll();		
		
        http.addFilterBefore(addAutenticacaoJWTFilter(), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(this.addOAuth2AuthenticationProcessingFilter(), BasicAuthenticationFilter.class);
	}
	
	private String getUsersByUsernameQuery(){
		return "SELECT ds_username, ds_password, 'true' FROM public.tb_usuario WHERE ds_username = ?";
	}
	
	private String getAuthoritiesByUsernameQuery(){
		StringBuilder sb = new StringBuilder("");

		sb.append("SELECT DISTINCT usu.ds_username, pap.ds_identificador FROM tb_usuario_papel as up ");
		sb.append("INNER JOIN tb_usuario as usu ON (up.id_usuario = usu.id_usuario) ");
		sb.append("INNER JOIN tb_papel as pap ON (up.id_papel = pap.id_papel) ");
		sb.append("WHERE usu.ds_username = ? ");
	
		return sb.toString(); 
	}
	
	@Bean
	public PasswordEncoder getPasswordEncoder(){
		PasswordEncoder encoder = new BCryptPasswordEncoder();
		return encoder;
	}
	
	@Bean
	public AutenticacaoJWTFilter addAutenticacaoJWTFilter(){
		return new AutenticacaoJWTFilter();
	}
	
	@Bean
	public OAuth2AuthenticationProcessingFilter addOAuth2AuthenticationProcessingFilter(){
		OAuth2AuthenticationProcessingFilter filter = new OAuth2AuthenticationProcessingFilter();
		
		try {
			filter.setAuthenticationManager(getOAuth2AuthenticationManager());
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return filter;
	}
	
	private OAuth2AuthenticationManager getOAuth2AuthenticationManager(){
		OAuth2AuthenticationManager manager = new OAuth2AuthenticationManager();
		manager.setTokenServices(resourceServerTokenServices);
		
		return manager;
	}
	
//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth
//			.inMemoryAuthentication()
//			.withUser("john")
//			.password("123")
//			.roles("USER");
//	}

	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}	
	
}
