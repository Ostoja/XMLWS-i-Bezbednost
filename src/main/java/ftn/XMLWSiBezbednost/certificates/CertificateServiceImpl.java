package ftn.XMLWSiBezbednost.certificates;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import ftn.XMLWSiBezbednost.utils.data.IssuerData;
import ftn.XMLWSiBezbednost.utils.data.SubjectData;
import ftn.XMLWSiBezbednost.utils.generators.CertificateGenerator;
import ftn.XMLWSiBezbednost.utils.generators.KeyGenerator;
import ftn.XMLWSiBezbednost.utils.keystore.KeyStoreReader;
import ftn.XMLWSiBezbednost.utils.keystore.KeyStoreWriter;

@Service
public class CertificateServiceImpl implements CertificateService {

	@Autowired
	private KeyGenerator keyGenerator;
	@Autowired
	private CertificateGenerator certificateGenerator;
	@Autowired
	private KeyStoreWriter keyStoreWriter;
	@Autowired
	private KeyStoreReader keyStoreReader;

	@Value("${keyStore.file}")
	private String keyStoreFile;
	@Value("${keyStore.password}")
	private String keyStorePassword;

	@Override
	public Certificate addSelfSigned(SubjectData subject,
			String alias,
			String password) {
		KeyPair keyPairSubject = keyGenerator.generateKeyPair();
		subject.setPublicKey(keyPairSubject.getPublic());
		
		IssuerData issuer = new IssuerData(keyPairSubject.getPrivate(), subject.getX500name());
		
		X509Certificate cert = certificateGenerator.generateCertificate(subject, issuer, true);
		keyStoreWriter.write(alias, keyPairSubject.getPrivate(), password.toCharArray(), cert);
		return cert;
	}

	@Override
	public Certificate addSigned(SubjectData subject,
			String alias,
			String password,
			String issuerAlias,
			String issuerPassword,
			boolean isCA) {
		KeyPair keyPairSubject = keyGenerator.generateKeyPair();
		subject.setPublicKey(keyPairSubject.getPublic());
		
		IssuerData issuer = keyStoreReader.readIssuerFromStore(keyStoreFile, 
				issuerAlias, 
				keyStorePassword.toCharArray(), 
				issuerPassword.toCharArray());
		
		X509Certificate cert = certificateGenerator.generateCertificate(subject, issuer, isCA);
		keyStoreWriter.write(alias, keyPairSubject.getPrivate(), password.toCharArray(), cert);
		return cert;
	}

	@Override
	public Certificate get(String serialNumber) {
		return keyStoreReader.readCertificate(keyStoreFile, 
				keyStorePassword, 
				serialNumber);
	}

}
