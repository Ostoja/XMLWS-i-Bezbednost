'use strict';

angular.module('get')
	.component('myGetCertificate', {
		templateUrl: '/part/get/get.template.html',
		controller: function(CertificateService) {
			this.send = () => {
				CertificateService.getCertificate(this.id)
					.then( (response) => {
						this.status = 'Certificate retrieved successfully';
						this.certificate = response.data.certificate;
					}, () => {
						this.status = 'Error';
						this.certificate = null;
					});
			}
		}
	});
