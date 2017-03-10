package br.jus.cnj.pje.autorizacao.repository;

import org.springframework.data.repository.CrudRepository;

import br.jus.cnj.pje.autorizacao.model.Usuario;

public interface UsuarioRepository extends CrudRepository<Usuario, Integer>{

	Usuario findByUsername(String login);
	Usuario findByIdUsuario(Integer id);
	
}
