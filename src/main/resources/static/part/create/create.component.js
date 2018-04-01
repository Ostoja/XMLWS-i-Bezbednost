'use strict';

angular.module('create')
	.component('myCreateCertificate', {
		templateUrl: '/part/create/create.template.html',
		controller: function(CertificateService) {
			this.send = () => {
				this.certificate.startTimestamp = this.startDate.getTime();
				this.certificate.endTimestamp = this.endDate.getTime();
				if(this.isSelfSigned)
				{
					CertificateService.selfSign(this.certificate)
						.then( () => {
							this.status = 'Certificate created successfully';
						}, () => {
							this.status = 'Error';
						});
				}
				else
				{
					CertificateService.sign(this.certificate)
						.then( () => {
							this.status = 'Certificate created successfully';
						}, () => {
							this.status = 'Error';
						});
				}
			}
		}
	});
