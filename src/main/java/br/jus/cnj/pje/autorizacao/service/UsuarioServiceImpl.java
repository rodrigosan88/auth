package br.jus.cnj.pje.autorizacao.service;

import java.util.Calendar;
import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import br.jus.cnj.pje.autorizacao.model.Usuario;
import br.jus.cnj.pje.autorizacao.repository.UsuarioRepository;

@Service
public class UsuarioServiceImpl implements UsuarioService {

	@Autowired
	private UsuarioRepository usuarioRepository;
	
	public UsuarioServiceImpl(UsuarioRepository usuarioRepository) {
		this.usuarioRepository = usuarioRepository;
	}
	
	@Override
	public Usuario findUsuario(String login) {
		return this.usuarioRepository.findByUsername(login);
	}
	
	public Usuario findUsuarioById(Integer idUsuario){
		return this.usuarioRepository.findByIdUsuario(idUsuario);
	}
	
	@Override
	public Usuario criarUsuario(Usuario usuario) {

		if(!StringUtils.isEmpty(usuario.getUsername()) || 
				!StringUtils.isEmpty(usuario.getPassword())){
			
			usuario.setDataValidadeSenha(getDataValidadeSenha());
			usuario.setAtivo(Boolean.TRUE);
			usuario = usuarioRepository.save(usuario);
		}
		
		return usuario;
	}

	private Date getDataValidadeSenha(){

		Calendar data = Calendar.getInstance();
		data.setTime(new Date());
		data.set(Calendar.YEAR, data.get(Calendar.YEAR) + 1);
		
		return data.getTime();
	}
	
}
