'use strict';
var express = require('express');

/**
 * Exports a function that, when called, returns a router that can be use()d to
 * enforce your firewall. This router lets requests through (calls `next`) if
 * they're for public routes or if they come from users that have been appproved
 * and have the proper role; otherwise, it responds to the request with a 401 or 403.
 *
 * @param routes {Object[]} An array of route objects, each with keys: path, method 
 * (defaults to GET), and access, which is the name of the required role. PUBLIC and
 * AUTHENTICATED are reserved, predefined roles that work as you'd expect.
 * 
 * @param userAdapter A standard Express middleware function responsible fon populating
 * req.user with an object representing the authenticated user, if any. (If no user is
 * signed in, it should leave req.user undefined and just all `next`). A valid user object
 * has an isApproved boolean property and a hasRole() method, that will be used to 
 * check whether the user is authorized see the route.
 *
 * @param _401TemplateNameOrJSON {sting|Object} The name of a template to render, or an
 * object to send as JSON, in cases where no user is logged in (and authentication is required).
 *
 * @param _403TemplateNameOrJSON {string|Object} Similar to the prior argument, but used
 * when the user is signed in but still doesn't have sufficient privileges.
 */
module.exports = function(routes, userAdapter, _401TemplateNameOrJSON, _403TemplateNameOrJSON) {
  var router = express.Router();

  //hydrate user 
  router.use(userAdapter);

  routes.forEach(function(route) {
    if(route.access !== 'PUBLIC') {
      router[route.method || 'get'](route.path, (function(requiredRole) {
        return function(req, res, next) {
          var user = req.user;

          //The user hasn't been authenticated yet; 
          //401 and back to login.
          if(typeof user === 'undefined') {
            req.session.goingTo = req.url;
            return respond(res, 401, _401TemplateNameOrJSON);
          }

          else if(route.access === "AUTHENTICATED" || (user.isApproved && user.hasRole(requiredRole))) {
            return next();
          }

          else {
            return respond(res, 403, _403TemplateNameOrJSON);
          }
        };
      }(route.access)));
    }
  });

  return router;
};

function respond(res, status, tmpOrJSON) {
    if(typeof tmpOrJSON == 'string' || tmpOrJSON instanceof String) {
        res.status(status);
        res.render(tmpOrJSON.toString());
    }
    else {
        res.json(status, tmpOrJSON);
    }
}