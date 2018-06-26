package ftn.XMLWSiBezbednost.certificates;

public class SubjectDataDTO {
	private String keyStoreFile;
	private String issuerKeyStoreFile;

	private String countryName;
	private String organizationName;
	private String organizationalUnitName;
	private String commonName;
	private String surName;
	private String givenName;
	private String emailAddress;
	private String uid;

	private String serialNumber;
	private Long startTimestamp;
	private Long endTimestamp;

	private String password;
	private String issuerSerialNumber;
	private String issuerPassword;
	private boolean isCA;

	public SubjectDataDTO() {}

	public SubjectDataDTO(String keyStoreFile,
			String issuerKeyStoreFile,
			String countryName,
			String organizationName,
			String organizationalUnitName,
			String commonName,
			String surName,
			String givenName,
			String emailAddress,
			String uid,
			String serialNumber,
			Long startTimestamp,
			Long endTimestamp) {
		this.keyStoreFile = keyStoreFile;
		this.issuerKeyStoreFile = issuerKeyStoreFile;
		this.countryName = countryName;
		this.organizationName = organizationName;
		this.organizationalUnitName = organizationalUnitName;
		this.commonName = commonName;
		this.surName = surName;
		this.givenName = givenName;
		this.emailAddress = emailAddress;
		this.uid = uid;
		this.serialNumber = serialNumber;
		this.startTimestamp = startTimestamp;
		this.endTimestamp = endTimestamp;
	}

	public String getKeyStoreFile() {
		return keyStoreFile + ".jks";
	}

	public void setKeyStoreFile(String keyStoreFile) {
		this.keyStoreFile = keyStoreFile;
	}

	public String getIssuerKeyStoreFile() {
		return issuerKeyStoreFile + ".jks";
	}

	public void setIssuerKeyStoreFile(String issuerKeyStoreFile) {
		this.issuerKeyStoreFile = issuerKeyStoreFile;
	}

	public String getCountryName() {
		return countryName;
	}

	public void setCountryName(String countryName) {
		this.countryName = countryName;
	}

	public String getOrganizationName() {
		return organizationName;
	}

	public void setOrganizationName(String organizationName) {
		this.organizationName = organizationName;
	}

	public String getOrganizationalUnitName() {
		return organizationalUnitName;
	}

	public void setOrganizationalUnitName(String organizationalUnitName) {
		this.organizationalUnitName = organizationalUnitName;
	}

	public String getCommonName() {
		return commonName;
	}

	public void setCommonName(String commonName) {
		this.commonName = commonName;
	}

	public String getSurName() {
		return surName;
	}

	public void setSurName(String surName) {
		this.surName = surName;
	}

	public String getGivenName() {
		return givenName;
	}

	public void setGivenName(String givenName) {
		this.givenName = givenName;
	}

	public String getEmailAddress() {
		return emailAddress;
	}

	public void setEmailAddress(String emailAddress) {
		this.emailAddress = emailAddress;
	}

	public String getUid() {
		return uid;
	}

	public void setUid(String uid) {
		this.uid = uid;
	}

	public String getSerialNumber() {
		return serialNumber;
	}

	public void setSerialNumber(String serialNumber) {
		this.serialNumber = serialNumber;
	}

	public Long getStartTimestamp() {
		return startTimestamp;
	}

	public void setStartTimestamp(Long startTimestamp) {
		this.startTimestamp = startTimestamp;
	}

	public Long getEndTimestamp() {
		return endTimestamp;
	}

	public void setEndTimestamp(Long endTimestamp) {
		this.endTimestamp = endTimestamp;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getIssuerSerialNumber() {
		return issuerSerialNumber;
	}

	public void setIssuerSerialNumber(String issuerSerialNumber) {
		this.issuerSerialNumber = issuerSerialNumber;
	}

	public String getIssuerPassword() {
		return issuerPassword;
	}

	public void setIssuerPassword(String issuerPassword) {
		this.issuerPassword = issuerPassword;
	}

	public boolean isCA() {
		return isCA;
	}

	public void setCA(boolean isCA) {
		this.isCA = isCA;
	}

}
