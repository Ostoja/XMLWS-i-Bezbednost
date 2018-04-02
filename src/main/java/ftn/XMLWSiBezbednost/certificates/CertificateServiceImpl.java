package ftn.XMLWSiBezbednost.certificates;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
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
		
		if(crl==null) {
			
		}
		
		Date today = Calendar.getInstance().getTime();
		X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(CA, today);
		
		JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
		builder.setProvider("BC");
		ContentSigner contentSigner = builder.build(pk);
		
		if(crl==null) {
			 X509V2CRLGenerator crlGen = new X509V2CRLGenerator();
			 Date now = new Date();
			 BigInteger revokedSerialNumber = BigInteger.valueOf(2);
			    
			 try {
				crlGen.setIssuerDN(PrincipalUtil.getSubjectX509Principal(cert));
			} catch (CertificateEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			    
			 crlGen.setThisUpdate(now);
			 crlGen.setNextUpdate(new Date(now.getTime() + 100000));
			 crlGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
			    
			    
			 try {
				crlGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, (ASN1Encodable) new AuthorityKeyIdentifierStructure(cert));
			} catch (CertificateParsingException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			 crlGen.addExtension(X509Extensions.CRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));
			    
			 try {
				crl = crlGen.generate(pk, "BC");
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalStateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SignatureException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		}
		
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
