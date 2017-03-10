package br.jus.cnj.pje.autorizacao.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import br.jus.cnj.pje.autorizacao.model.Usuario;
import br.jus.cnj.pje.autorizacao.service.UsuarioService;

public class AutenticacaoJWTFilter extends OncePerRequestFilter{

    @Autowired 
    UsuarioService usuarioService;

    @Autowired
    private TokenJWTUtil jwtTokenUtil;

    @Value("${jwt.header}")
    private String tokenHeader;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        
    	String jwtToken = request.getHeader(this.tokenHeader);
        String login = jwtTokenUtil.getUsernameFromToken(jwtToken);

        if (login != null && SecurityContextHolder.getContext().getAuthentication() == null) {

        	// TODO: Recuperar os dados de usuarioLogin
        	Usuario usuario = this.usuarioService.findUsuario(login);
        	User user = new User(usuario.getUsername(), usuario.getPassword(), true, true, true, true, AuthorityUtils.NO_AUTHORITIES);
        	UserDetails userDetails = user;

            if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        chain.doFilter(request, response);
    }
}
