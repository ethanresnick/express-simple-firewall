'use strict';
var express = require('express')
  , Q = require('q');

/**
 * Exports a function that returns a router that can be use()d to enforce your 
 * firewall. This router should be placed in front of your real route handlers. 
 * It lets requests through (calls `next`) if they come from users that have the
 * proper role; otherwise, it responds to the request with a 401 or 403. (For 
 * public routes, it doesn't register a route handler at all, so yours is called
 * directly.)
 *
 * @param routes {Object[]} An array of route objects, each with keys: path, 
 * method (defaults to GET), and access, which is the name of the required role 
 * or an array of roles to OR match on. PUBLIC and AUTHENTICATED are reserved, 
 * predefined roles that work as you'd expect. They must be used as strings, not
 * in an array of allowed roles.
 * 
 * @param userAdapter A standard Express middleware function responsible for 
 * populating req.user with an object representing the authenticated user, if
 * any. (If no user is signed in, it should leave req.user undefined and just 
 * call `next`). A valid user object has a hasRole() method, that will be used 
 * to check whether the user is authorized see the route. hasRole can return a 
 * boolean or a Promise that resolves to a boolean, indicating whether the User 
 * has the role. 
 *
 * @param unathenticatedCb A function to call if the user hasn't authenticated, 
 * but needs to. Should send a response. Receives req, res as arguments.
 *
 * @param unathorizedCb Similar to the prior argument, but used when the user is 
 * authenticated but still doesn't have sufficient privileges.
 */
module.exports = function(routes, userAdapter, unauthenticatedCb, unauthorizedCb) {
  var router = express.Router();

  //hydrate user 
  router.use(userAdapter);

  routes.forEach(function(route) {
    if(route.access !== 'PUBLIC') {
      var method = route.method ? route.method.toLowerCase() : 'get';
      router[method](
        route.path, 
        makeNonPublicRouteHandler(route.access, unauthenticatedCb, unauthorizedCb)
      );
    }
  });

  return router;
};

/**
 * Given (an array of) required role(s), returns a function that can be used as
 * an express request handler to enforce that the user (in req.user) has the
 * required roles.
 */
function makeNonPublicRouteHandler(requiredRoleOrRoles, unauthenticatedCb, unauthorizedCb) {
  return function(req, res, next) {
    var user = req.user;

    // If we don't have a user on a non-public route, it's an automatic 401.
    if(typeof user === 'undefined') {
      res.status(401);
      unauthenticatedCb(req, res, next);
    }

    // But, if we have a user, and that's the only requirement, we continue.
    else if(requiredRoleOrRoles === "AUTHENTICATED") {
      next();
    }

    // For more complex requirements, we have to check the user's role to respond.
    else {
      return Q(user.hasRole(requiredRoleOrRoles)).then(function(hasRole) {
        if(hasRole) {
          next();
        }
        else {
          res.status(403);
          unauthorizedCb(req, res, next);                
        }
      });
    }
  };
}
