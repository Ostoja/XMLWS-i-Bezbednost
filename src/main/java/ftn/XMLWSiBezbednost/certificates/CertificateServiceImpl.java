package ftn.XMLWSiBezbednost.certificates;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import ftn.XMLWSiBezbednost.utils.crl.CRLUtils;
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
	@Value("${crl.file}")
	private String crlFile;
	
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

	@Override
	public Certificate revoke(String serialNumber, String issuerAlias, String issuerPassword) throws CRLException, IOException, OperatorCreationException {
		X509Certificate cert = (X509Certificate) keyStoreReader.readCertificate(keyStoreFile, keyStorePassword, serialNumber);
		X509CRL crl = CRLUtils.openFromFile(crlFile);
		
		IssuerData issuer = keyStoreReader.readIssuerFromStore(keyStoreFile, 
				issuerAlias, 
				keyStorePassword.toCharArray(), 
				issuerPassword.toCharArray());
		//PrivateKey pk = keyStoreReader.readPrivateKey(keyStoreFile, keyStorePassword, alias, pass)
		PrivateKey pk = issuer.getPrivateKey();
		
		X500Name CA = issuer.getX500name();
		
		Date today = Calendar.getInstance().getTime();
		X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(null, today);
		
		JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
		builder.setProvider("BC");
		ContentSigner contentSigner = builder.build(pk);
		
		crlBuilder.addCRL(new X509CRLHolder(crl.getEncoded()));
		crlBuilder.addCRLEntry(cert.getSerialNumber(), today, CRLReason.unspecified);
		X509CRLHolder holder = crlBuilder.build(contentSigner);
		JcaX509CRLConverter cnv = new JcaX509CRLConverter();
		cnv.setProvider("BC");
		X509CRL newCRL = cnv.getCRL(holder);					
		
		CRLUtils.saveCRLfile(crlFile, newCRL);
		return cert ;
	}

	@Override
	public boolean isValid(String serialNumber) {
		X509Certificate cert = (X509Certificate) keyStoreReader.readCertificate(keyStoreFile, keyStorePassword, serialNumber);
		X509CRL crl = CRLUtils.openFromFile(crlFile);
		try {
		cert.checkValidity();
		if(crl.isRevoked(cert))
			return false;
		else
			return true;
		}
		catch (CertificateExpiredException e) {
			return false;
		}
		catch (CertificateNotYetValidException e) {
			return false;
		}
	}

}
