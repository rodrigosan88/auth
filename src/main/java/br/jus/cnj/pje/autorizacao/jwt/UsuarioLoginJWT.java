package br.jus.cnj.pje.autorizacao.jwt;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class UsuarioLoginJWT implements UserDetails, Serializable {

	private static final long serialVersionUID = 1L;
	private final Long id;
    private final String username;
    private final String nome;
    private final String password;
	private final String statusSenha;
	private final Date dataValidadeSenha;
    private final Date lastPasswordResetDate;
	
	
	public UsuarioLoginJWT(Long id, String username, String nome, String password, String statusSenha,
			Date dataValidadeSenha, Date lastPasswordResetDate) {
		this.id = id;
		this.username = username;
		this.nome = nome;
		this.password = password;
		this.statusSenha = statusSenha;
		this.dataValidadeSenha = dataValidadeSenha;
		this.lastPasswordResetDate = lastPasswordResetDate;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return null;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public boolean isAccountNonExpired() {
		return false;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	public Long getId() {
		return id;
	}

	public String getNome() {
		return nome;
	}

	public String getStatusSenha() {
		return statusSenha;
	}

	public Date getDataValidadeSenha() {
		return dataValidadeSenha;
	}
	
	public Date getLastPasswordResetDate() {
		return lastPasswordResetDate;
	}
}