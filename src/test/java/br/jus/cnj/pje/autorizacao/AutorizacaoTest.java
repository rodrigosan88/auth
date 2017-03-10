package br.jus.cnj.pje.autorizacao;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import ch.qos.logback.core.net.server.Client;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class AutorizacaoTest {
	
	@Autowired
	private TestRestTemplate testRest;
	
	@Test
	public void autenticar(){
		
		ResponseEntity<Client> responseEntity = testRest.postForEntity("/autenticar", "{\"login\":\"02289676195\",\"senha\":\"02289676195\"}", Client.class);
		Client client = responseEntity.getBody();
		
	}
	
}
