package ftn.XMLWSiBezbednost.certificates;

import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;

import org.bouncycastle.operator.OperatorCreationException;

import ftn.XMLWSiBezbednost.utils.data.SubjectData;

public interface CertificateService {

	Certificate addSelfSigned(SubjectData subject,
			String keyStoreFile,
			String alias,
			String password);
	Certificate addSigned(SubjectData subject,
			String keyStoreFile,
			String alias,
			String password,
			String issuerKeyStoreFile,
			String issuerAlias,
			String issuerPassword,
			boolean isCA);
	Certificate get(String keyStoreFile, String serialNumber);
	boolean isValid(String keyStoreFile, String serialNumber) throws IOException, ClassNotFoundException;
	Certificate revoke(String keyStoreFile, String serialNumber) throws CRLException, IOException, OperatorCreationException, ClassNotFoundException;
}
