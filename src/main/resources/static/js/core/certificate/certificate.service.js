'use strict';

angular.module('core.certificate')
	.service('CertificateService', function($http) {
		this.selfSign = (data) => {
			return $http.post('/api/certificates/self-signed', data);
		};
		this.sign = (data) => {
			return $http.post('/api/certificates/signed', data);
		};
		this.getCertificate = (id) => {
			return $http.get(`/api/certificates/${id}`);
		};
		this.revoke = (data) => {
			return $http.post('/api/certificates/revoke', data)
		}
	});
