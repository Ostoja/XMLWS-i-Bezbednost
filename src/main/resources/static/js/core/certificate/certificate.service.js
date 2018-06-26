'use strict';

angular.module('core.certificate')
	.service('CertificateService', function($http) {
		this.selfSign = (data) => {
			return $http.post('/api/certificates/self-signed', data);
		};
		this.sign = (data) => {
			return $http.post('/api/certificates/signed', data);
		};
		this.getCertificate = (store, id) => {
			return $http.get(`/api/certificates/store/${store}/cert/${id}`);
		};
		this.revoke = (store, id) => {
			return $http.put(`/api/certificates/revoke/store/${store}/cert/${id}`);
		}
		this.isValid = (store, id) => {
			return $http.get(`/api/certificates/valid/store/${store}/cert/${id}`);
		}
	});
