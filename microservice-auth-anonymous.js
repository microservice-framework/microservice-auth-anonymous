/**
 * Profile Stats MicroService.
 */
'use strict';

const framework = '@microservice-framework';
const Cluster = require(framework + '/microservice-cluster');
const Microservice = require(framework + '/microservice');
const MicroserviceRouterRegister = require(framework + '/microservice-router-register').register;
const clientViaRouter = require(framework + '/microservice-router-register').clientViaRouter;
const debugF = require('debug');
const fs = require('fs');
const ANONYMOUS = 'anonymous';

var debug = {
  log: debugF('auth-anonymous:log'),
  debug: debugF('auth-anonymous:debug')
};

require('dotenv').config();

let permissionsPath = './permissions.json';
if (process.env.PERMISSION_PATH) {
  permissionsPath = process.env.PERMISSION_PATH;
}


var mservice = new Microservice({
  mongoUrl: '',
  mongoTable: '',
  secureKey: process.env.SECURE_KEY,
  schema: process.env.SCHEMA
});

var mControlCluster = new Cluster({
  pid: process.env.PIDFILE,
  port: process.env.PORT,
  hostname: process.env.HOSTNAME,
  count: process.env.WORKERS,
  callbacks: {
    init: microserviceAuthAnonymousINIT,
    POST: microserviceAuthAnonymousPOST,
    OPTIONS: mservice.options
  }
});

/**
 * Init Handler.
 */
function microserviceAuthAnonymousINIT(cluster, worker, address) {
  if (worker.id == 1) {
    var mserviceRegister = new MicroserviceRouterRegister({
      server: {
        url: process.env.ROUTER_URL,
        secureKey: process.env.ROUTER_SECRET,
        period: process.env.ROUTER_PERIOD,
      },
      route: {
        path: [process.env.SELF_PATH],
        url: process.env.SELF_URL,
        secureKey: process.env.SECURE_KEY,
      },
      cluster: cluster
    });
  }
}

/**
 * POST handler.
 */
function microserviceAuthAnonymousPOST(jsonData, requestDetails, callback) {
  try {
    // Validate jsonData.code for XSS
    mservice.validateJson(jsonData);
  } catch (e) {
    return callback(e, null);
  }

  getScope(function(err, anonymousJSON) {
    if (err) {
      return callback(err);
    }
    // scope it and return access token
    let scopeRequest = {
      credentials: {
        login: ANONYMOUS
      },
      scope: anonymousJSON
    }
    if (process.env.DEFAULT_TTL) {
      scopeRequest.ttl = parseInt(process.env.DEFAULT_TTL);
    }
    if(jsonData.ttl) {
      scopeRequest.ttl = jsonData.ttl;
    }
    clientViaRouter('auth', function(err, authServer) {
      if (err) {
        return callback(err);
      }
      authServer.post(scopeRequest, function(err, authAnswer) {
        if (err) {
          debug.debug('authServer.post err %O', err);
          debug.log('authServer.post failed with error.');
          return callback(err);
        }
        let handlerAnswer = {
          code: 200,
          answer: {
            accessToken: authAnswer.accessToken,
            expireAt: authAnswer.expireAt
          }
        }
        return callback(err, handlerAnswer);
      });
    });
  })
}

/**
 * Read scope from filesystem.
 */
function getScope(callback) {
  let scopeJSON;
  fs.readFile(permissionsPath, function(err, data){
    if (err) {
      return callback(err);
    }
    try {
      scopeJSON = JSON.parse(data);
      callback(null, scopeJSON);
    } catch (e) {
      return callback(new Error('Failed to load role permissions'));
    }
  })
}
