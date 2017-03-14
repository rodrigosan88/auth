package br.jus.cnj.pje.autorizacao.controller;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import br.jus.cnj.pje.autorizacao.model.Usuario;
import br.jus.cnj.pje.autorizacao.service.UsuarioService;

@RestController
public class UsuarioRestController {
	
	@Autowired
	private UsuarioService usuarioService;
	
	@RequestMapping(value = "/criarUsuario", method = RequestMethod.POST)
	public ResponseEntity<?> criarUsuario(@RequestBody String str){

		JSONObject obj = new JSONObject(str);
		Usuario usuario = new Usuario();
		String username = (String) obj.get(UsuarioService.USERNAME_KEY);
		String password = (String) obj.get(UsuarioService.PASSWORD_KEY);
		
		if(!StringUtils.isEmpty(username) && !StringUtils.isEmpty(password)){
			
			usuario.setUsername(username);
			usuario.setPassword(password);
			
			usuario = usuarioService.criarUsuario(usuario);
			
		}
		return ResponseEntity.ok(usuario.toString());
	}
	
	@PreAuthorize("#oauth2.hasRole('ADMIN')")
	@RequestMapping(value = "/recuperarUsuario/{id}", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<Usuario> recuperarUsuario(@PathVariable("id") int id){
		
		Usuario usuario = usuarioService.findUsuarioById(id);
		
		return ResponseEntity.ok(usuario);
	}
	
	@RequestMapping({"/user", "/me"})
	public Map<String, String> user(Principal principal){
		Map<String, String> map = new LinkedHashMap<>();
		String roles = SecurityContextHolder.getContext().getAuthentication().getAuthorities().toString();
		
		map.put("name", principal.getName());
		map.put("roles", roles);
		
		return map;
	}
	
}
