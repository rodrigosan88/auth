package br.jus.cnj.pje.autorizacao.model;

import java.io.Serializable;
import javax.persistence.*;
import java.util.Date;
import java.util.List;


/**
 * The persistent class for the tb_usuario database table.
 * 
 */
@Entity
@Table(name="tb_usuario")
@NamedQuery(name="Usuario.findAll", query="SELECT u FROM Usuario u")
public class Usuario implements Serializable {
	private static final long serialVersionUID = 1L;

	@Id
	@SequenceGenerator(name="TB_USUARIO_IDUSUARIO_GENERATOR", sequenceName="SQ_TB_USUARIO")
	@GeneratedValue(strategy=GenerationType.SEQUENCE, generator="TB_USUARIO_IDUSUARIO_GENERATOR")
	@Column(name="id_usuario")
	private Integer idUsuario;

	@Column(name="ds_email")
	private String email;

	@Column(name="ds_password")
	private String password;

	@Column(name="ds_username")
	private String username;

	@Temporal(TemporalType.DATE)
	@Column(name="dt_validade_senha")
	private Date dataValidadeSenha;

	@Column(name="in_ativo")
	private Boolean ativo;

	//bi-directional many-to-one association to UsuarioCertificado
	@OneToMany(mappedBy="usuario")
	private List<UsuarioCertificado> usuarioCertificados;

	//bi-directional many-to-many association to Papel
	@ManyToMany
	@JoinTable(
		name="tb_usuario_papel"
		, joinColumns={
			@JoinColumn(name="id_usuario")
			}
		, inverseJoinColumns={
			@JoinColumn(name="id_papel")
			}
		)
	private List<Papel> papeis;

	public Usuario() {
	}

	public Integer getIdUsuario() {
		return this.idUsuario;
	}

	public void setIdUsuario(Integer idUsuario) {
		this.idUsuario = idUsuario;
	}

	public String getEmail() {
		return this.email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPassword() {
		return this.password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getUsername() {
		return this.username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public Date getDataValidadeSenha() {
		return this.dataValidadeSenha;
	}

	public void setDataValidadeSenha(Date dataValidadeSenha) {
		this.dataValidadeSenha = dataValidadeSenha;
	}

	public Boolean getAtivo() {
		return this.ativo;
	}

	public void setAtivo(Boolean ativo) {
		this.ativo = ativo;
	}

	public List<UsuarioCertificado> getUsuarioCertificados() {
		return this.usuarioCertificados;
	}

	public void setUsuarioCertificados(List<UsuarioCertificado> usuarioCertificados) {
		this.usuarioCertificados = usuarioCertificados;
	}

	public UsuarioCertificado addUsuarioCertificado(UsuarioCertificado usuarioCertificado) {
		getUsuarioCertificados().add(usuarioCertificado);
		usuarioCertificado.setUsuario(this);

		return usuarioCertificado;
	}

	public UsuarioCertificado removeUsuarioCertificado(UsuarioCertificado usuarioCertificado) {
		getUsuarioCertificados().remove(usuarioCertificado);
		usuarioCertificado.setUsuario(null);

		return usuarioCertificado;
	}

	public List<Papel> getPapeis() {
		return this.papeis;
	}

	public void setPapeis(List<Papel> papeis) {
		this.papeis = papeis;
	}
	
	@Override
	public String toString() {
		return getUsername();
	}

}