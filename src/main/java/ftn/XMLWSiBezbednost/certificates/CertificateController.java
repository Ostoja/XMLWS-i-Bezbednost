package ftn.XMLWSiBezbednost.certificates;

import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;

import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.Base64Utils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import ftn.XMLWSiBezbednost.utils.data.SubjectData;

@RestController
@RequestMapping("/api/certificates")
public class CertificateController {

	@Autowired
	private CertificateService certificateService;
	@Autowired
	private SubjectDataConverter converter;


	@PostMapping("/self-signed")
	public ResponseEntity<?> addSelfSignedCertificate(@RequestBody SubjectDataDTO input) {
		SubjectData subject = converter.fromDTO(input);
		certificateService.addSelfSigned(subject,
				input.getKeyStoreFile(),
				input.getSerialNumber(),
				input.getPassword());

		return new ResponseEntity<>(HttpStatus.OK);
	}

	@PostMapping("/signed")
	public ResponseEntity<?> addSignedCertificate(@RequestBody SubjectDataDTO input) {
		SubjectData subject = converter.fromDTO(input);
		certificateService.addSigned(subject,
				input.getKeyStoreFile(),
				input.getSerialNumber(),
				input.getPassword(),
				input.getIssuerKeyStoreFile(),
				input.getIssuerSerialNumber(),
				input.getIssuerPassword(),
				input.isCA());

		return new ResponseEntity<>(HttpStatus.OK);
	}

	@GetMapping("/store/{keyStoreFile}/cert/{id}")
	public ResponseEntity<?> getCertificate(@PathVariable String keyStoreFile,
			@PathVariable String id) throws CertificateEncodingException {
		Certificate cert = certificateService.get(keyStoreFile + ".jks", id);
		HashMap<String, String> response = new HashMap<>();
		response.put("certificate", Base64Utils.encodeToString(cert.getEncoded()));
		return new ResponseEntity<>(response, HttpStatus.OK);
	}

	@PutMapping("/revoke/store/{keyStoreFile}/cert/{id}")
	public ResponseEntity<?> revokeCertificate(@PathVariable String keyStoreFile,
			@PathVariable String id) throws CRLException, IOException, OperatorCreationException, ClassNotFoundException {
		certificateService.revoke(keyStoreFile + ".jks", id);
		return new ResponseEntity<>(HttpStatus.OK);
	}

	@GetMapping("/valid/store/{keyStoreFile}/cert/{id}")
	public ResponseEntity<?> isValid(@PathVariable String keyStoreFile,
			@PathVariable String id) throws ClassNotFoundException, IOException{
		boolean valid = certificateService.isValid(keyStoreFile + ".jks", id);
		HashMap<String, String> response = new HashMap<>();
		if(valid) {
			response.put("valid", "Certificate is valid" );
		}
		else {
			response.put("valid", "Certificate is invalid" );
		}
		return new ResponseEntity<>(response, HttpStatus.OK);
	}

}
