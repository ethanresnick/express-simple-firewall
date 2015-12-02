/** 
 * @todo explicitly test support for user.hasRole() returning a promise.
 * (Right now, it's only tested by the fact that a couple of the spies happen
 * to return one.)
 */

var firewall = require('../index')
  , expect = require('chai').expect
  , express = require('express')
  , sinon = require('sinon')
  , emitter = new (require('events').EventEmitter)
  , Q = require("Q");

var routes = [
  {path:"/members", access: "MEMBER"},
  {path:"/public", access: "PUBLIC", method: "post"},
  {path:"/unspecifiedPolicy"},
  {path: "/user", access: "AUTHENTICATED"}
];

var dummyUsers = [
  {hasRole: sinon.spy(function() { return false; })},
  {hasRole: sinon.spy(function(role) { return Q.fcall(function() { return false }); })},
  {hasRole: sinon.spy(function(role) { return Q.fcall(function() { return role === "MEMBER"; }); })},
  {hasRole: sinon.spy(function(role) { return role === "MEMBER"; })}
];

//req.user is set directly on these, rather than it being set
//through the adapter, b/c the adapters have their own unit tests.
var requests = {
  sessionUser0: {
    url: "/members", 
    method: "get", 
    user: dummyUsers[0]
  },
  unspecifiedPolicyUser1: {
    url: "/unspecifiedPolicy", 
    method: "get", 
    user: dummyUsers[1]
  },  
  unspecifiedPolicyNoUser: {
    url: "/unspecifiedPolicy", 
    method: "get"
  },
  publicNoUser: {
    url: '/public',
    method: 'post'
  },
  publicWithUser: {
    url: '/public',
    method: 'post',
    user: dummyUsers[0]
  },
  memberNoUser: {
    url: '/members',
    method: "get"
  },
  memberAuthorizedAccess: {
    url: "/members", 
    method: "get", 
    user: dummyUsers[3]
  },
  memberAccessNoRole: {
    url: "/members", 
    method: "get", 
    user: dummyUsers[1]
  },
  memberAccessUnapprovedUser: {
    url: "/members", 
    method: "get", 
    user: dummyUsers[2]
  },
  requiresUser: {
    url: "/user",
    method: "get",
    user: dummyUsers[3]
  },
  requiresUserNoUser: {
    url: "/user",
    method: "get",
    user: dummyUsers[3]
  },
  requiresUserUnapprovedUser: {
    url: "/user",
    method: "get",
    user: dummyUsers[0]
  }
};

var resSpy = {'status': sinon.spy(function(res, req, next) { })}
  , firewallAdapter = sinon.spy(function(req, res, next){ next(); })
  , routeHandler = sinon.spy(function(req, res, next) { emitter.emit('done'); })
  , unauthenticatedHandler = sinon.spy(function(req, res) { emitter.emit('done'); })
  , unauthorizedHandler = sinon.spy(function(req, res) { emitter.emit('done'); });

var firewallRouter = firewall(routes, firewallAdapter, unauthenticatedHandler, unauthorizedHandler);
var mainRouter = express.Router();
mainRouter.use(firewallRouter);
mainRouter.use(routeHandler);

describe("the module", function() {
  it("should export a function with arity of four", function() {
    expect(firewall).to.be.a("function").with.length(4);
  });

  it("should expose the adapters as a property", function () {
    expect(firewall.adapters).to.be.an('object');
  });
});

describe("the firewall itself", function() {
  //can't use beforeEach b/c some tests include multiple
  //requests, in between each of which we need to call this.
  function reset() {
    resSpy.status.reset();
    unauthenticatedHandler.reset();
    unauthorizedHandler.reset();
    routeHandler.reset();
    firewallAdapter.reset();
  }

  //The express router doesn't let us register a callback to run when the last middleware is done.
  //So, instead, we have our final handlers trigger events, which we listen to in the fns below.
  //Note: the Router will let you provide a callback that's run if next() is called from the 
  //last middleware (https://github.com/visionmedia/express/blob/master/lib/router/index.js#L115), 
  //but some of our final functions (i.e. the unauthenticated/unauthorizedHandlers) are inten-
  //tionally called without next as an argument, to make sure the user doesn't accidentally let
  //the request through the firewall. Hence our EventEmitter test pattern.
  function expectStatusPromise(req, status, additionalExpectations) {
    return Q.promise(function(resolve, reject) {
      reset();
      emitter.once('done', function() {
        try {
          expect(routeHandler.callCount).to.equal(status === 200 ? 1 : 0);
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

  function testUserAuthPromise(req, shouldWork) {
    return Q.promise(function(resolve, reject) {
      reset();
      emitter.once('done', function() {
        try {
          expect(routeHandler.callCount).to.equal(shouldWork ? 1 : 0);
          expect(req.user.hasRole.callCount).to.equal(1);
          expect(req.user.hasRole.calledWith("MEMBER")).to.be.true;
          resolve();
        }
        catch(e) {
          reject(e);
        }
      })
      mainRouter(req, resSpy);
    });
  };

  function promiseSequenceAndDone(promises, done) {
    return promises.slice(1).reduce(function(soFar, promise) {
      return soFar.then(promise);
    }, promises[0]).then(done, done);
  }

  it("should call the user adapter before anything else", function(done) {
    expectStatusPromise(requests.publicNoUser, 200, function() {
      expect(firewallAdapter.calledBefore(routeHandler));
    }).then(done);
  })

  it("should let anyone access public urls", function(done) {
    expectStatusPromise(requests.publicNoUser, 200).then(done);
  });

  it("should let any user access public urls", function(done) {
    expectStatusPromise(requests.publicWithUser, 200).then(done);
  });

  it("should make routes with no explicit access policy inaccessible with a 401 if no user", function(done) {
    expectStatusPromise(requests.unspecifiedPolicyNoUser, 401).then(done);
  });

  it("should make secure routes inaccessible with a 401 if no user", function(done) {
      expectStatusPromise(requests.memberNoUser, 401).then(done);
  });

  it("should allow any user to access routes with an AUTHENTICATED policy", function(done) {
      promiseSequenceAndDone([
        expectStatusPromise(requests.requiresUser, 200),
        expectStatusPromise(requests.requiresUserNoUser, 401),
        expectStatusPromise(requests.requiresUserUnapprovedUser, 200)
      ], done);
  });

  it("should make routes with no explicit access policy inaccessible with a 403 if a user", function(done) {
    expectStatusPromise(requests.unspecifiedPolicyUser1, 403).then(done);
  });

  describe("authenticating the user", function() {
    it("should check user.hasRole(role) is true", function(done) {
      promiseSequenceAndDone([
        testUserAuthPromise(requests.memberAuthorizedAccess, true),
        testUserAuthPromise(requests.memberAccessNoRole, false),
        testUserAuthPromise(requests.memberAccessUnapprovedUser, false)
      ], done);
    });
  });

  it("should 403 if req.user exists but doesn't have access", function(done) {
    promiseSequenceAndDone([
      expectStatusPromise(requests.sessionUser0, 403),
      expectStatusPromise(requests.memberAccessUnapprovedUser, 403)
    ], done);
  });
});