package br.jus.cnj.pje.autorizacao.service;

import br.jus.cnj.pje.autorizacao.model.UsuarioLogin;

public interface UsusarioLoginService {
	UsuarioLogin findUsuarioLogin(String login);
	Iterable<UsuarioLogin> listUsuarioLogin();
}
