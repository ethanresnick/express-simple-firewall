var firewall = require('../index');
var expect = require('chai').expect;
var express = require('express');
var sinon = require('sinon');
var emitter = new (require('events').EventEmitter);
var Q = require("Q");

var routes = [
  {path:"/members", access: ["MEMBER", "ADMIN"] },
  {path:"/public", access: "PUBLIC", method: "POST"},
  {path:"/unspecifiedPolicy"},
  {path: "/profile", access: "AUTHENTICATED"},
  {path:"/admin", access: "ADMIN" }
];

// Note: two of these fake users return a promise from their hasRole,
// so that we can test that the code works whether hasRole is sync or not.
var users = {
  noRole: {
    hasRole: sinon.spy(function() { return Q(false); })
  },
  member: {
    hasRole: sinon.spy(function(roleOrRoles) { 
      return roleOrRoles === "MEMBER" || roleOrRoles.indexOf("MEMBER") > -1; 
    })
  },
  admin: {
    hasRole: sinon.spy(function(roleOrRoles) { 
      return Q(roleOrRoles === "ADMIN" || roleOrRoles.indexOf("ADMIN") > -1); 
    })
  }
};

// Set up an adapter that does nothing; we'll populate req.user in our 
// fake requests manually, so that we can unit test our adapters separately.
var firewallAdapter = sinon.spy(function(req, res, next){ next(); });

// Set up handlers for 200, 401, and 403. These emit an event when called 
// because the express router doesn't let us register a callback for when the 
// last middleware is done. So, instead, we listen for these events.
// Note: the Router will let you provide a callback that's run if next() is 
// called from the last middleware, but our unauthenticated and unauthorized 
// handlers are intentionally called without next as an argument (to make sure 
// the user doesn't accidentally let the request through the firewall), so we 
// can't take advantage of that.
var successHandler = sinon.spy(function(req, res, next) { emitter.emit('done'); });
var unauthenticatedHandler = sinon.spy(function(req, res) { emitter.emit('done'); });
var unauthorizedHandler = sinon.spy(function(req, res) { emitter.emit('done'); });

// Set up the firewall itself, and use it on a router.
var firewallRouter = firewall(routes, firewallAdapter, unauthenticatedHandler, unauthorizedHandler);
var mainRouter = express.Router();
mainRouter.use(firewallRouter);
mainRouter.use(successHandler);

// When we exercise the mainRouter below, we'll pass in fake request and 
// response objects. Our fake response object is defined below. It creates
// a spy for its status function, so we can know that the firewall called
// res.status().
var resSpy = {'status': sinon.spy(function(res, req, next) { })}

// Resolve a sequence of promises in series.
function promiseSequenceAndDone(promises, done) {
  return promises.slice(1).reduce(function(soFar, promise) {
    return soFar.then(promise, done);
  }, promises[0]).then(function() { done() }, done);
}

describe("the module's interface", function() {
  it("should export a function with arity of four", function() {
    expect(firewall).to.be.a("function").with.length(4);
  });

  it("should expose the adapters as a property", function () {
    expect(firewall.adapters).to.be.an('object');
  });
});

describe("the firewall itself", function() {
  /**
   * Asynchronously establishes expects() for the appropriate handler,
   * given the status you're expecting. And tests that res.status() was
   * called for all statuses but 200. Then returns a promise that rejects
   * if any expectations fail; resolves otherwise.
   */
  function expectStatusPromise(req, status, additionalExpectations) {
    return Q.promise(function(resolve, reject) {
      // Reset all counters before kicking off the request. 
      // We can't put this in a beforeEach b/c some tests include multiple
      // requests, in between each of which we need to do this resetting.
      // Note: this is global state, so no paralellizing tests :(.
      // That's why we use promiseSequenceAndDone.
      resSpy.status.reset();
      unauthenticatedHandler.reset();
      unauthorizedHandler.reset();
      successHandler.reset();
      firewallAdapter.reset();

      emitter.once('done', function() {
        try {
          expect(successHandler.callCount).to.equal(status === 200 ? 1 : 0);
          expect(unauthenticatedHandler.callCount).to.equal(status === 401 ? 1 : 0);
          expect(unauthorizedHandler.callCount).to.equal(status === 403 ? 1 : 0);

          if(status !== 200) {
            expect(resSpy.status.calledWith(status)).to.be.true;
          }

          if(typeof additionalExpectations == 'function') {
            additionalExpectations();
          }

          resolve();
        }
        catch(e) {
          reject(e);
        }
      });

      //dispatch the request
      mainRouter(req, resSpy);
    });
  };

  it("should call the user adapter before anything else", function(done) {
    var dummySuccessfulReq = {url: '/public', method: 'post'};

    expectStatusPromise(dummySuccessfulReq, 200, function() {
      expect(firewallAdapter.calledBefore(successHandler));
    }).then(done);
  });

  describe("public routes", function() {
    var publicRequests = [
      {url: '/public', method: 'post'},
      {url: '/public', method: 'post', user: users.noRole},
      {url: '/public', method: 'post', user: users.member}
    ];

    it("should be accessible to anyone", function(done) {
      promiseSequenceAndDone(publicRequests.map(function(publicReq) {
        return expectStatusPromise(publicReq, 200);
      }), done);
    });
  });

  describe("routes with no explicit access policy", function() {
    var unspecifiedPolicyRequests = [
      {url: '/unspecifiedPolicy', method: 'get'},
      {url: '/unspecifiedPolicy', method: 'get', user: users.noRole},
      {url: '/unspecifiedPolicy', method: 'get', user: users.admin}
    ];

    it("should be inaccessible with a 401 if no user", function(done) {
      expectStatusPromise(unspecifiedPolicyRequests[0], 401).then(function() { 
        done(); 
      }, done);
    });

    it("should be inaccessible with a 403 if a user", function(done) {
      promiseSequenceAndDone([
        expectStatusPromise(unspecifiedPolicyRequests[1], 403),
        expectStatusPromise(unspecifiedPolicyRequests[2], 403)
      ], done);
    });
  });

  describe("routes requiring specific roles", function() {
    it("should return 200, 401, or 403 as appropriate", function(done) {
      var reqs = [{
        url: '/members',
        method: "get",
        expectedStatus: 401
      }, {
        url: "/members", 
        method: "get", 
        user: users.noRole,
        expectedStatus: 403
      }, {
        url: "/members", 
        method: "get", 
        user: users.member,
        expectedStatus: 200
      }, {
        url: "/members", 
        method: "get", 
        user: users.admin,
        expectedStatus: 200
      }, {
        url: '/admin',
        method: "get",
        expectedStatus: 401
      }, {
        url: "/admin", 
        method: "get", 
        user: users.noRole,
        expectedStatus: 403
      }, {
        url: "/admin", 
        method: "get", 
        user: users.member,
        expectedStatus: 403
      }, {
        url: "/admin", 
        method: "get", 
        user: users.admin,
        expectedStatus: 200
      }];

      Q.all(reqs.map(function(req) {
        var expectedStatus = req.expectedStatus;
        delete req.expectedStatus;

        // Expect the status to match and hasRole to have beeen called.
        return expectStatusPromise(req, expectedStatus, function() {
          if(req.user) {
            expect(req.user.hasRole.callCount).to.equal(1);
          }
        });
      })).then(function() { done(); }, done);
    });
  });

  describe("routes only requiring an authenticated user", function() {
    it("should be accessible iff there's a user", function(done) {
      Q.all([
        expectStatusPromise({ url: "/profile", method: "get" }, 401),
        expectStatusPromise({ url: "/profile", method: "get", user: users.noRole }, 200),
        expectStatusPromise({ url: "/profile", method: "get", user: users.admin }, 200)
      ]).then(function() { done(); }, done);      
    })
  });
});