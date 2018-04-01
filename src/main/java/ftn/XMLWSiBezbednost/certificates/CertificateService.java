package ftn.XMLWSiBezbednost.certificates;

import java.security.cert.Certificate;

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

}
