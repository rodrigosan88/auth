package br.jus.cnj.pje.autorizacao.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import br.jus.cnj.pje.autorizacao.jwt.AutenticacaoVO;
import br.jus.cnj.pje.autorizacao.jwt.TokenJWTUtil;
import br.jus.cnj.pje.autorizacao.model.Usuario;
import br.jus.cnj.pje.autorizacao.service.UsuarioService;

@RestController
public class AutenticacaoJWTRestController{
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UsuarioService usuarioService;
	
    @Autowired
    private TokenJWTUtil tokenUtil;	
	
	@RequestMapping(value = "/autenticar", method = RequestMethod.POST)
	public ResponseEntity<?> autenticar(@RequestBody AutenticacaoVO autenticacaoVO) {
		final Authentication auth = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(autenticacaoVO.getUsername(), autenticacaoVO.getPassword()));
		
    	Usuario usuario = this.usuarioService.findUsuario(auth.getName());
    	User user = new User(usuario.getUsername(), usuario.getPassword(), true, true, true, true, auth.getAuthorities());
    	UserDetails userDetails = user;
    	String token = tokenUtil.generateToken(userDetails, usuario);
		
		SecurityContextHolder.getContext().setAuthentication(auth);
		
		return ResponseEntity.ok(token);
	}
	
	@RequestMapping(value = "/validar", method = RequestMethod.POST)
	public ResponseEntity<?> validar(@RequestBody String token){
		Boolean valido = Boolean.FALSE;
		System.out.println(token);
		valido = tokenUtil.validateToken(token);
		System.out.println("RESPOSTA DO SERVIÇO: " + valido);
		return ResponseEntity.ok(valido.toString());
	}
	
}
