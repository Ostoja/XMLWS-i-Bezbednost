'use strict';

angular.module('pki')
	.config(function($stateProvider, $urlRouterProvider) {
		$stateProvider
			.state({
				name: 'create',
				url: '/create',
				component: 'myCreateCertificate'
			})
			.state({
				name: 'get',
				url: '/get',
				template: '<h1>Get Certificate</h1>'
			})
			.state({
				name: 'revoke',
				url: '/revoke',
				component: 'myRevoke'
			})
			.state({
				name: 'status',
				url: '/status',
				template: '<h1>Check Certificate Status</h1>'
			})
			.state({
				name: 'error',
				url: '/error',
				template: '<h1>Error 404</h1>'
			});

		$urlRouterProvider
			.when('', '/create')
			.when('/', '/create')
			.otherwise('/error');
	})
