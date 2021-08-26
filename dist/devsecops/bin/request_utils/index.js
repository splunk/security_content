module.exports =
/******/ (function(modules, runtime) { // webpackBootstrap
/******/ 	"use strict";
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete installedModules[moduleId];
/******/ 		}
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	__webpack_require__.ab = __dirname + "/";
/******/
/******/ 	// the startup function
/******/ 	function startup() {
/******/ 		// Load entry module and return exports
/******/ 		return __webpack_require__(507);
/******/ 	};
/******/
/******/ 	// run startup
/******/ 	return startup();
/******/ })
/************************************************************************/
/******/ ({

/***/ 507:
/***/ (function(__unusedmodule, exports) {

"use strict";

// const { SplunkdClient } = require('splunk-rest-client');
Object.defineProperty(exports, "__esModule", { value: true });
exports.getParam = exports.getFormParam = exports.getQueryParam = exports.getFormParamValues = exports.getQueryParamValues = exports.extractParamValues = void 0;
/**
 * Retrieve a user-bound REST client from the request information.
 * @param request the request object passed by splunkd
 */
// export const getUserRestClient = request => {
//     if (!request.session) {
//         throw new Error(
//             'Cannot create user REST client as request does not contain session information. ' +
//                 'Make sure that passSession is enabled in the restmap configuration.'
//         );
//     }
//     return new SplunkdClient({
//         baseUrl: request.server.rest_uri,
//         sessionKey: request.session.authtoken,
//         verbose: true
//     });
// };
/**
 * Retrieve a system-authenticated REST client from the request information.
 * This relies on `passSystemAuth` to be enabled for the restmap stanza.
 *
 * @param request the request object passed by splunkd
 */
// export const getSystemRestClient = request => {
//     if (!request.system_authtoken) {
//         throw new Error(
//             'Cannot create system REST client as request does not contain session information. ' +
//                 'Make sure that passSystemAuth is enabled in the restmap configuration.'
//         );
//     }
//     return new SplunkdClient({
//         baseUrl: request.server.rest_uri,
//         sessionKey: request.session.authtoken
//     });
// };
// private
exports.extractParamValues = (paramArray, name) => paramArray.filter(([k]) => k === name).map(([_, v]) => v);
/**
 * Retrieve the query string parameter values with the given name.
 * Returns an empty array if not present.
 *
 * @param request the request object passed by splunkd
 * @param name
 */
exports.getQueryParamValues = (request, name) => (request.query ? exports.extractParamValues(request.query, name) : []);
/**
 * Retrieve the form parameter values with the given name. Returns an empty array if not present.
 *
 * @param request the request object passed by splunkd
 * @param name
 */
exports.getFormParamValues = (request, name) => (request.form ? exports.extractParamValues(request.form, name) : []);
/**
 * Retrieve the single (first) query string parameter with the given name. Returns `undefined` if not present or
 * if the request did not contain query string information.
 *
 * @param request the request object passed by splunkd
 * @param name
 */
exports.getQueryParam = (request, name) => exports.getQueryParamValues(request, name)[0];
/**
 * Retrieve the single (first) form parameter value with the given name. Returns `undefined` if no parameter with
 * the given name is present or if the request does not contain form parameter information.
 *
 * @param request the request object passed by splunkd
 * @param name
 */
exports.getFormParam = (request, name) => exports.getFormParamValues(request, name)[0];
/**
 * Retrieve the single (first) parameter value with the given name from either the query string (default) or
 * the form parameters if it's a POST request. Returns `undefined` if no parameter with the given name
 * is present or if the request does not contain the corresponding parameter information.
 *
 * @param request the request object passed by splunkd
 * @param name
 */
exports.getParam = (request, name) => request.method === 'POST' ? exports.getFormParam(request, name) : exports.getQueryParam(request, name);


/***/ })

/******/ });