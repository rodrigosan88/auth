package br.jus.cnj.pje.autorizacao.repository;

import org.springframework.data.repository.CrudRepository;

import br.jus.cnj.pje.autorizacao.model.UsuarioLogin;

public interface UsuarioLoginRepository extends CrudRepository<UsuarioLogin, Integer>{
	
	UsuarioLogin findByLogin(String login);

}
