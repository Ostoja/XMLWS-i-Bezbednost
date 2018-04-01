'use strict';

angular.module('pki')
	.config(function($stateProvider, $urlRouterProvider) {
		$stateProvider
			.state({
				name: 'create',
				url: '/create',
				template: '<h1>Create Certificate</h1>'
			})
			.state({
				name: 'get',
				url: '/get',
				template: '<h1>Get Certificate</h1>'
			})
			.state({
				name: 'revoke',
				url: '/revoke',
				template: '<h1>Revoke Certificate</h1>'
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
