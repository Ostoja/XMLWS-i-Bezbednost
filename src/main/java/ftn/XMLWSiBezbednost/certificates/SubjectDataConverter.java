package ftn.XMLWSiBezbednost.certificates;

import java.util.Date;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.stereotype.Component;

import ftn.XMLWSiBezbednost.utils.data.SubjectData;

@Component
public class SubjectDataConverter {

	public SubjectData fromDTO(SubjectDataDTO input) {		
		X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
		builder.addRDN(BCStyle.C, input.getCountryName());
		builder.addRDN(BCStyle.O, input.getOrganizationName());
		builder.addRDN(BCStyle.OU, input.getOrganizationalUnitName());
	    builder.addRDN(BCStyle.CN, input.getCommonName());
	    builder.addRDN(BCStyle.SURNAME, input.getSurName());
	    builder.addRDN(BCStyle.GIVENNAME, input.getGivenName());
	    builder.addRDN(BCStyle.E, input.getEmailAddress());
	    builder.addRDN(BCStyle.UID, input.getUid());
		
		String sn = input.getSerialNumber();
		Date startDate = new Date(input.getStartTimestamp());
		Date endDate = new Date(input.getEndTimestamp());
		
	    return new SubjectData(null, builder.build(), sn, startDate, endDate);
	}

}
