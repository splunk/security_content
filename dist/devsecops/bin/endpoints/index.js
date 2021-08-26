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
/******/ 		return __webpack_require__(315);
/******/ 	};
/******/
/******/ 	// run startup
/******/ 	return startup();
/******/ })
/************************************************************************/
/******/ ({

/***/ 315:
/***/ (function(__unusedmodule, exports, __webpack_require__) {

"use strict";

Object.defineProperty(exports, "__esModule", { value: true });
exports.Endpoint = exports.EndpointRequestHandler = exports.EndpointError = exports.normalizePathPattern = exports.Method = void 0;
const response_utils_1 = __webpack_require__(648);
var Method;
(function (Method) {
    Method["GET"] = "GET";
    Method["POST"] = "POST";
    Method["HEAD"] = "HEAD";
    Method["ALL_METHODS"] = "ALL";
})(Method = exports.Method || (exports.Method = {}));
function normalizePathPattern(pathPattern) {
    if (pathPattern[0] === '/') {
        return normalizePathPattern(pathPattern.slice(1));
    }
    return pathPattern;
}
exports.normalizePathPattern = normalizePathPattern;
class EndpointError extends Error {
    constructor(message, status = 500) {
        super(message);
        this.status = status;
    }
    toErrorResponse() {
        return response_utils_1.errorResponse(this.message, this.status);
    }
}
exports.EndpointError = EndpointError;
class EndpointRequestHandler {
    constructor(method, pathPattern, handlerFn) {
        this.method = method;
        this.pathPattern = normalizePathPattern(pathPattern);
        this.handlerFn = handlerFn;
    }
    matchesMethod(method) {
        return method === this.method || this.method === Method.ALL_METHODS;
    }
    pathMatches(path) {
        // TODO, support globbing
        return path === this.pathPattern || this.pathPattern === '*';
    }
    run(request) {
        const fn = this.handlerFn;
        return Promise.resolve(fn(request));
    }
}
exports.EndpointRequestHandler = EndpointRequestHandler;
class Endpoint {
    constructor() {
        this.handlers = [];
        this.handleRequest = this.handleRequest.bind(this);
    }
    registerHandler(method, path, handler) {
        this.handlers.push(new EndpointRequestHandler(method, path, handler));
    }
    get(path, handler) {
        this.registerHandler(Method.GET, path, handler);
    }
    post(path, handler) {
        this.registerHandler(Method.POST, path, handler);
    }
    head(path, handler) {
        this.registerHandler(Method.HEAD, path, handler);
    }
    all(path, handler) {
        this.registerHandler(Method.ALL_METHODS, path, handler);
    }
    handleRequest(request) {
        const handler = this.handlers.find((h) => h.matchesMethod(request.method) && h.pathMatches(request.path_info));
        if (!handler) {
            return Promise.resolve(response_utils_1.errorResponse('Not Found', 404));
        }
        return handler.run(request).catch((e) => {
            if (e instanceof EndpointError) {
                return e.toErrorResponse();
            }
            // Let the driver deal with unhandled error
            throw e;
        });
    }
    static create(configureFn) {
        const endpoint = new Endpoint();
        configureFn(endpoint);
        return endpoint.handleRequest;
    }
}
exports.Endpoint = Endpoint;


/***/ }),

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


/***/ })

/******/ });