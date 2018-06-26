'use strict';

angular.module('pki')
	.config(function($stateProvider, $urlRouterProvider, $compileProvider) {
		$stateProvider
			.state({
				name: 'create',
				url: '/create',
				component: 'myCreateCertificate'
			})
			.state({
				name: 'get',
				url: '/get',
				component: 'myGetCertificate'
			})
			.state({
				name: 'revoke',
				url: '/revoke',
				component: 'myRevoke'
			})
			.state({
				name: 'status',
				url: '/status',
				component: 'myStatus'
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

		$compileProvider.aHrefSanitizationWhitelist(/^\s*(https?|s?ftp|mailto|tel|file|data):/);
	})
