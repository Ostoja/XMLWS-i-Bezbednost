package ftn.XMLWSiBezbednost.certificates;

import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;

import org.bouncycastle.operator.OperatorCreationException;
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
		certificateService.addSelfSigned(subject, 
				input.getSerialNumber(), 
				input.getPassword());
		
		return new ResponseEntity<>(HttpStatus.OK);
	}

	@PostMapping("/signed")
	public ResponseEntity<?> addSignedCertificate(@RequestBody SubjectDataDTO input) {
		SubjectData subject = converter.fromDTO(input);
		certificateService.addSigned(subject, 
				input.getSerialNumber(), 
				input.getPassword(),
				input.getIssuerSerialNumber(),
				input.getIssuerPassword(),
				input.isCA());
		
		return new ResponseEntity<>(HttpStatus.OK);
	}

	@GetMapping("/{id}")
	public ResponseEntity<?> getCertificate(@PathVariable String id) {
		Certificate cert = certificateService.get(id);
		return new ResponseEntity<>(cert.toString(), HttpStatus.OK);
	}
	
	@PostMapping("/revoke")
	public ResponseEntity<?> revokeCertificate(@RequestBody SubjectDataDTO input) throws CRLException, IOException, OperatorCreationException {
		certificateService.revoke(input.getSerialNumber(), input.getIssuerSerialNumber(), input.getIssuerPassword());
		return new ResponseEntity<>(HttpStatus.OK);
	}
	
	@GetMapping("/valid/{id}")
	public ResponseEntity<?> isValid(@PathVariable String id){
		certificateService.isValid(id);
		return new ResponseEntity<>(HttpStatus.OK);
	}

}
