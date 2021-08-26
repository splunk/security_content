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
/******/ 		return __webpack_require__(784);
/******/ 	};
/******/
/******/ 	// run startup
/******/ 	return startup();
/******/ })
/************************************************************************/
/******/ ({

/***/ 648:
/***/ (function(__unusedmodule, exports) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
exports.errorResponse = void 0;
exports.errorResponse = (msg, status = 500) => {
    return {
        payload: {
            messages: [{ type: 'ERROR', text: msg }],
        },
        status,
    };
};


/***/ }),

/***/ 784:
/***/ (function(module, __unusedexports, __webpack_require__) {

"use strict";

const response_utils_1 = __webpack_require__(648);
module.exports = function debugRestHandler(request) {
    console.log(`Handling report endpoint request to ${request.rest_path}`);
    if (request.path_info === 'bounce') {
        // Terminate the driver process, so we use the (possibly) updated script
        // for the next requests
        console.info('Bouncing rest driver...');
        setTimeout(() => {
            process.exit(0);
        }, 100);
        return Promise.resolve({ payload: { bounce: true } });
    }
    return Promise.resolve(response_utils_1.errorResponse(`Debug endpoint ${request.path_info} not found, do you want to try /debug/bounce endpoint?`, 404));
};


/***/ })

/******/ });