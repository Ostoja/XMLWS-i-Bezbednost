'use strict';

angular.module('status')
	.component('myStatus', {
		templateUrl: '/part/status/status.template.html',
		controller: function(CertificateService) {
			this.send = () => {
				CertificateService.isValid(this.id)
					.then( (response) => {
						this.status = 'Status is ';
						this.certificate = response.data.valid;
					}, () => {
						this.status = 'Error';
						this.certificate = null;
					});
			}
		}
	});
