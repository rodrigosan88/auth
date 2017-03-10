package br.jus.cnj.pje.autorizacao.model;

import java.io.Serializable;
import javax.persistence.*;
import java.util.Date;


/**
 * The persistent class for the tb_usuario_certificado database table.
 * 
 */
@Entity
@Table(name="tb_usuario_certificado")
@NamedQuery(name="UsuarioCertificado.findAll", query="SELECT u FROM UsuarioCertificado u")
public class UsuarioCertificado implements Serializable {
	private static final long serialVersionUID = 1L;

	@Id
	@SequenceGenerator(name="TB_USUARIO_CERTIFICADO_IDUSUARIOCERTIFICADO_GENERATOR", sequenceName="SQ_TB_USUARIO_CERTIFICADO")
	@GeneratedValue(strategy=GenerationType.SEQUENCE, generator="TB_USUARIO_CERTIFICADO_IDUSUARIOCERTIFICADO_GENERATOR")
	@Column(name="id_usuario_certificado")
	private Integer idUsuarioCertificado;

	@Column(name="ds_certchain")
	private String certchain;

	@Column(name="ds_signature")
	private String signature;

	@Temporal(TemporalType.DATE)
	@Column(name="dt_validade")
	private Date dataValidade;

	//bi-directional many-to-one association to Usuario
	@ManyToOne
	@JoinColumn(name="tb_usuario_id_usuario")
	private Usuario usuario;

	public UsuarioCertificado() {
	}

	public Integer getIdUsuarioCertificado() {
		return this.idUsuarioCertificado;
	}

	public void setIdUsuarioCertificado(Integer idUsuarioCertificado) {
		this.idUsuarioCertificado = idUsuarioCertificado;
	}

	public String getCertchain() {
		return this.certchain;
	}

	public void setCertchain(String certchain) {
		this.certchain = certchain;
	}

	public String getSignature() {
		return this.signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	public Date getDataValidade() {
		return this.dataValidade;
	}

	public void setDataValidade(Date dataValidade) {
		this.dataValidade = dataValidade;
	}

	public Usuario getUsuario() {
		return this.usuario;
	}

	public void setUsuario(Usuario usuario) {
		this.usuario = usuario;
	}

}