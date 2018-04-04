package ftn.XMLWSiBezbednost.certificates;

import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;

import org.bouncycastle.operator.OperatorCreationException;

import ftn.XMLWSiBezbednost.utils.data.SubjectData;

public interface CertificateService {

	Certificate addSelfSigned(SubjectData subject,
			String alias,
			String password);
	Certificate addSigned(SubjectData subject,
			String alias,
			String password,
			String issuerAlias,
			String issuerPassword,
			boolean isCA);
	Certificate get(String serialNumber);
	boolean isValid(String serialNumber) throws IOException, ClassNotFoundException;
	Certificate revoke(String serialNumber) throws CRLException, IOException, OperatorCreationException, ClassNotFoundException;
}
