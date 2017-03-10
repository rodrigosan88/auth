package br.jus.cnj.pje.autorizacao.model;

import java.io.Serializable;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.persistence.UniqueConstraint;

import org.hibernate.annotations.Type;

@Entity
@Table(name = "tb_usuario_login", uniqueConstraints = @UniqueConstraint(columnNames = "ds_login"))
@SequenceGenerator(allocationSize = 1, name = "gen_usuario_login", sequenceName = "sq_tb_usuario_login")
public class UsuarioLogin implements Serializable{
	
	
	private static final long serialVersionUID = 1L;
	private Integer idUsuario;
	private String senha;
	private String email;
	private String login;
	private String nome;
	private String assinatura;
	private String certChain;
	private Boolean ativo = Boolean.TRUE;
	private String hashAtivacaoSenha;
	private String statusSenha;
	private Date dataValidadeSenha;

	public UsuarioLogin() {}

	@Id
	@GeneratedValue(generator = "gen_usuario_login")
	@Column(name = "id_usuario", unique = true, nullable = false)
	public Integer getIdUsuario(){
		return this.idUsuario;
	}

	public void setIdUsuario(Integer idUsuario){
		this.idUsuario = idUsuario;
	}

	@Column(name = "ds_senha", length = 100)
	public String getSenha(){
		return this.senha;
	}

	public void setSenha(String senha){
		this.senha = senha;
	}

	@Column(name = "ds_email", length = 100)
	public String getEmail(){
		return this.email;
	}

	public void setEmail(String email){
		this.email = email;
	}

	@Column(name = "ds_login", unique = true, nullable = false, length = 100)
	public String getLogin(){
		return this.login;
	}

	public void setLogin(String login){
		this.login = login;
	}

	@Column(name = "ds_nome", nullable = false, length = 255)
	public String getNome(){
		return this.nome;
	}

	public void setNome(String nome){
		this.nome = nome;
	}

	@Lob
	@Basic(fetch=FetchType.LAZY)
	@Type(type = "org.hibernate.type.TextType")
	@Column(name = "ds_assinatura_usuario")
	public String getAssinatura(){
		return assinatura;
	}

	public void setAssinatura(String assinatura){
		this.assinatura = assinatura;
	}

	@Lob
	@Basic(fetch=FetchType.LAZY)
	@Type(type = "org.hibernate.type.TextType")
	@Column(name = "ds_cert_chain_usuario")
	public String getCertChain(){
		return certChain;
	}

	public void setCertChain(String certChain){
		this.certChain = certChain;
	}

	@Column(name = "in_ativo", nullable = false)
	public Boolean getAtivo(){
		return this.ativo;
	}

	public void setAtivo(Boolean ativo){
		this.ativo = ativo;
	}
	
	@Column(name="hash_ativacao_senha")
	public String getHashAtivacaoSenha() {
		return hashAtivacaoSenha;
	}
	
	public void setHashAtivacaoSenha(String hashAtivacaoSenha) {
		this.hashAtivacaoSenha = hashAtivacaoSenha;
	}	

	@Column(name="dt_validade_senha")
	public Date getDataValidadeSenha() {
		return dataValidadeSenha;
	}
	
	public void setDataValidadeSenha(Date dataValidadeSenha) {
		this.dataValidadeSenha = dataValidadeSenha;
	}

	@Override
	public String toString(){
		return nome;
	}

	@Transient
	public int getDiasExpirarSenha(){
		if(this.getDataValidadeSenha() != null){
			Date d1 = null;
			Date d2 = null;
			
			SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy");
			
			String sD1 = sdf.format(this.getDataValidadeSenha());
			String sD2 = sdf.format(new Date());
			try {
				 d1 = sdf.parse(sD1);
				 d2 = sdf.parse(sD2);
			} catch (ParseException e) {
				e.printStackTrace();
			}
			
			if(d1.after(d2) || d2.equals(d1)){
				return (int)((d1.getTime() - d2.getTime()) / (24*60*60*1000));
			}
		}
		
		return -1;
	}
	
	@Transient
	public String getUrlAtivacaoSenha(String urlSistema){
		if(getIdUsuario() != null && getHashAtivacaoSenha() != null && getLogin() != null && urlSistema != null){
			return urlSistema + "/Senha/ativacaoSenha.seam?hashCodigoAtivacao="+getHashAtivacaoSenha()+"&login="+getLogin();
		}
		
		return null;
	}

	@Transient
	public String[] getEmails() {
		if (this.email != null) {
			final String SEPARADOR = ",";
			return this.email.split(SEPARADOR);
		}
		return new String[0];
	}

	@Override
	public int hashCode(){
		final int prime = 31;
		int result = 1;
		result = prime * result + ((getIdUsuario() == null) ? 0 : getIdUsuario().hashCode());
		return result;
	}
	
	@Transient
	public String getNomeSobrenome(){
		String primeiroNome = "";
		String sobrenome = "";
		if(this.nome.split("\\w+").length > 1){
			primeiroNome = this.nome.substring(0, this.nome.indexOf(' ')).toLowerCase();
			sobrenome = this.nome.substring(this.nome.lastIndexOf(' ')+1).toLowerCase();
		}
		
		return primeiroNome + " " + sobrenome;
	}
	
	@Column(name = "in_status_senha", length = 1)
	public String getStatusSenha() {
		return statusSenha;
	}
	
	public void setStatusSenha(String statusSenha) {
		this.statusSenha = statusSenha;
	}	
}
