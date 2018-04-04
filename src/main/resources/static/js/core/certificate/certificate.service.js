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
		this.revoke = (id) => {
			return $http.put('/api/certificates/revoke/${id}')
		}
		this.isValid = (id) => {
			return $http.get('/api/certificates/valid/${id}')
		}
	});
