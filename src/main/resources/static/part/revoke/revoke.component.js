'use strict';

angular.module('revoke')
	.component('myRevoke', {
		templateUrl: '/part/revoke/revoke.template.html',
		controller: function(CertificateService) {
			this.send = () => {
				CertificateService.revoke(this.certificate)
					.then( () => {
						this.status = 'Certificate revoked successfully';
					}, () => {
						this.status = 'Error';
					});
				}
		}
		
	});
