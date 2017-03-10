package br.jus.cnj.pje.autorizacao.service;

import br.jus.cnj.pje.autorizacao.model.Usuario;

public interface UsuarioService {
	
	public static final String USERNAME_KEY = "username";
	public static final String PASSWORD_KEY = "password";
	
	public Usuario findUsuario(String username);
	public Usuario criarUsuario(Usuario usuario);
	public Usuario findUsuarioById(Integer idUsuario);
}
