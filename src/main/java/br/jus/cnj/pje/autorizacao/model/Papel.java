package br.jus.cnj.pje.autorizacao.model;

import java.io.Serializable;
import javax.persistence.*;
import java.util.List;


/**
 * The persistent class for the tb_papel database table.
 * 
 */
@Entity
@Table(name="tb_papel")
@NamedQuery(name="Papel.findAll", query="SELECT p FROM Papel p")
public class Papel implements Serializable {
	private static final long serialVersionUID = 1L;

	@Id
	@SequenceGenerator(name="TB_PAPEL_IDPAPEL_GENERATOR", sequenceName="SQ_TB_PAPEL")
	@GeneratedValue(strategy=GenerationType.SEQUENCE, generator="TB_PAPEL_IDPAPEL_GENERATOR")
	@Column(name="id_papel")
	private Integer idPapel;

	@Column(name="ds_identificador")
	private String identificador;

	@Column(name="ds_nome")
	private String nome;

	@ManyToOne
	@JoinColumn(name="id_papel_superior")
	private Papel papelSuperior;

	public Papel() {
	}

	public Integer getIdPapel() {
		return this.idPapel;
	}

	public void setIdPapel(Integer idPapel) {
		this.idPapel = idPapel;
	}

	public String getIdentificador() {
		return this.identificador;
	}

	public void setIdentificador(String identificador) {
		this.identificador = identificador;
	}

	public String getNome() {
		return this.nome;
	}

	public void setNome(String nome) {
		this.nome = nome;
	}

	public Papel getPapelSuperior() {
		return this.papelSuperior;
	}

	public void setPapelSuperior(Papel papelSuperior) {
		this.papelSuperior = papelSuperior;
	}
	
	
}