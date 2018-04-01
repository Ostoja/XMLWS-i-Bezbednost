package ftn.XMLWSiBezbednost.certificates;

import java.security.cert.Certificate;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
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
		Certificate cert = certificateService.addSelfSigned(subject, 
				input.getSerialNumber(), 
				input.getPassword());
		
		return new ResponseEntity<>(cert.toString(), HttpStatus.OK);
	}

	@PostMapping("/signed")
	public ResponseEntity<?> addSignedCertificate(@RequestBody SubjectDataDTO input) {
		SubjectData subject = converter.fromDTO(input);
		Certificate cert = certificateService.addSigned(subject, 
				input.getSerialNumber(), 
				input.getPassword(),
				input.getIssuerSerialNumber(),
				input.getIssuerPassword(),
				input.isCA());
		
		return new ResponseEntity<>(cert.toString(), HttpStatus.OK);
	}

	@GetMapping("/{id}")
	public ResponseEntity<?> getCertificate(@PathVariable String id) {
		Certificate cert = certificateService.get(id);
		return new ResponseEntity<>(cert.toString(), HttpStatus.OK);
	}

}
