package br.jus.cnj.pje.autorizacao.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import br.jus.cnj.pje.autorizacao.model.UsuarioLogin;
import br.jus.cnj.pje.autorizacao.repository.UsuarioLoginRepository;

@Component("usuarioLoginService")
@Transactional
public class UsuarioLoginServiceImpl implements UsusarioLoginService{
	
	private UsuarioLoginRepository usuarioLoginRepository;
	
	@Autowired
	public UsuarioLoginServiceImpl(UsuarioLoginRepository usuarioLoginRepository) {
		this.usuarioLoginRepository = usuarioLoginRepository;
	}

	@Override
	public UsuarioLogin findUsuarioLogin(String login) {
		return this.usuarioLoginRepository.findByLogin(login);
	}

	@Override
	public Iterable<UsuarioLogin> listUsuarioLogin() {
		return this.usuarioLoginRepository.findAll();
	}
}
