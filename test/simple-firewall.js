var firewall = require('../index')
  , expect = require('chai').expect
  , express = require('express')
  , sinonChai = require("sinon-chai")
  , sinon = require('sinon')
  , Q = require("Q")
  , emitter = new (require('events').EventEmitter)
  , app = express(); 

var routes = [
  {path:"/members", access: "MEMBER"},
  {path:"/public", access: "PUBLIC", method: "post"},
  {path:"/unspecifiedPolicy"},
  {path: "/user", access: "AUTHENTICATED"}
];

var dummyUsers = [
  {hasRole: sinon.spy(function() { return false; }), isApproved: false},
  {hasRole: sinon.spy(function(role) { return false }), isApproved: true},
  {hasRole: sinon.spy(function(role) { return role === "MEMBER"; }), isApproved: false},
  {hasRole: sinon.spy(function(role) { return role === "MEMBER"; }), isApproved: true}
];

var requests = {
  invalidSession: {
    url: "/members", 
    method: "get", 
    session: {"user_id": "invalid"}
  },
  sessionUser0: {
    url: "/members", 
    method: "get", 
    session: {"user_id": "0"}
  },
  unspecifiedPolicyUser1: {
    url: "/unspecifiedPolicy", 
    method: "get", 
    session: {"user_id": "1"}
  },  
  unspecifiedPolicyNoUser: {
    url: "/unspecifiedPolicy", 
    method: "get",
    session: {}
  },
  publicNoUser: {
    url: '/public',
    method: 'post',
    session: {}
  },
  publicWithUser: {
    url: '/public',
    method: 'post',
    session: {"user_id": "0"}
  },
  memberNoUser: {
    url: '/members',
    method: "get",
    session: {}
  },
  memberAuthorizedAccess: {
    url: "/members", 
    method: "get", 
    session: {"user_id": "3"}
  },
  memberAccessNoRole: {
    url: "/members", 
    method: "get", 
    session: {"user_id": "1"}
  },
  memberAccessUnapprovedUser: {
    url: "/members", 
    method: "get", 
    session: {"user_id": "2"}
  },
  requiresUser: {
    url: "/user",
    method: "get",
    session: {"user_id": "3"}    
  },
  requiresUserNoUser: {
    url: "/user",
    method: "get",
    session: {"user_id": "3"}    
  },
  requiresUserUnapprovedUser: {
    url: "/user",
    method: "get",
    session: {"user_id": "0"}
  }
};

var resSpy = {
  'status': sinon.spy(function(res, req, next) { }), 
  'render': sinon.spy(function(template) { 
    //we need to be able to run a callback post render in our tests to see
    //that the right thing happened, but express doesn't give us an easy way 
    //to do that, so we're having our render stub emit an event.
    emitter.emit('renderComplete'); 
    emitter.emit('sendComplete');
  }),
  'json': sinon.spy(function(status, obj) {
    emitter.emit('sendComplete');
  })
};

var routeHandler = sinon.spy(function(req, res, next) {
  next(); //so we get to the done callback
});

var userGetter = function(userId) {
  if(userId == "invalid") {
    return Q.Promise(function(resolve, reject, notify) {
      reject(new Error("Invalid user!"));
    });
  }
  else {
    return Q.Promise(function(resolve, reject, notify) {
      resolve(dummyUsers[userId]);
    });
  }
};

var adapter = firewall.adapters.sessionBased(userGetter);
var firewallRouter = firewall(routes, adapter, "loginTemp", "403Temp");
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
    resSpy.render.reset();
    routeHandler.reset();
  }

  function expectSuccessPromise(req) {
    return Q.promise(function(resolve, reject) {
      reset();
      mainRouter(req, resSpy, function(err) {
        try {
          expect(routeHandler.callCount).to.equal(1);
          expect(resSpy.render.callCount).to.equal(0);
          resolve();
        }
        catch(e) {
          reject(e);
        }
      });
    });
  };

  function expectFailurePromise(req, status, expectJSONResponse, additionalExpectations) {
    return Q.promise(function(resolve, reject) {
      reset();
      //test should end in rendering a 403/401 with login page or error, 
      //hence the emitter pattern.
      emitter.once('sendComplete', function() {
        try {
          expect(routeHandler.called).to.be.false;
          expect(resSpy[expectJSONResponse ? 'json' : 'render'].callCount).to.equal(1);
          expect(resSpy.status.calledWith(status)).to.be.true;
          
          if(status==403) {
            expect(resSpy.render.calledWith("403Temp")).to.be.true;
          }
          else if(status==401) {
            expect(resSpy.render.calledWith("loginTemp")).to.be.true;
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
      //trigger req
      firewallRouter(req, resSpy);
    });
  };

  function testUserAuthPromise(req, shouldWork) {
    return Q.promise(function(resolve, reject) {
      routeHandler.reset();
      var cb = function() {
        try {
          expect(routeHandler.callCount).to.equal(shouldWork ? 1 : 0);
          expect(req.user.hasRole.callCount).to.equal(1);
          expect(req.user.hasRole.calledWith("MEMBER")).to.be.true;
          resolve();
        }
        catch(e) {
          reject(e);
        }
      };

      //trigger req. if shouldWork, then we're getting out of the 
      //router and can use the done callback; otherwise we need events.
      if(shouldWork) {
        mainRouter(req, resSpy, cb);
      }
      else {
        emitter.once('renderComplete', cb);
        mainRouter(req, resSpy);
      }
    });
  };

  function promiseSequenceAndDone(promises, done) {
    return promises.slice(1).reduce(function(soFar, promise) {
      return soFar.then(promise);
    }, promises[0]).then(done, done);
  }

  it("should let anyone access public urls", function(done) {
    expectSuccessPromise(requests.publicNoUser).then(done);
  });

  it("should let any user access public urls", function(done) {
    expectSuccessPromise(requests.publicWithUser).then(done);
  });

  it("should make routes with no explicit access policy inaccessible with a 403 if a user", function(done) {
    expectFailurePromise(requests.unspecifiedPolicyUser1, 403).then(done);
  });

  it("should make routes with no explicit access policy inaccessible with a 401 if no user", function(done) {
    expectFailurePromise(requests.unspecifiedPolicyNoUser, 401).then(done);
  });

  describe("authenticating the user", function() {
    it("should check both that user.isApproved and user.hasRole(role) are true", function(done) {
      promiseSequenceAndDone([
        testUserAuthPromise(requests.memberAuthorizedAccess, true),
        testUserAuthPromise(requests.memberAccessNoRole, false),
        testUserAuthPromise(requests.memberAccessUnapprovedUser, false)
      ], done);
    });
  });

  it("should allow any user to access routes with an AUTHENTICATED policy", function(done) {
      promiseSequenceAndDone([
        expectSuccessPromise(requests.requiresUser),
        expectFailurePromise(requests.requiresUserNoUser, 401),
        expectSuccessPromise(requests.requiresUserUnapprovedUser)
      ], done);
  });

  it("should 403 if req.user exists but doesn't have access", function(done) {
    promiseSequenceAndDone([
      expectFailurePromise(requests.sessionUser0, 403),
      expectFailurePromise(requests.memberAccessUnapprovedUser, 403)
    ], done);
  });

  it("should 401, render the login page, and set req.session.goingTo if req.user doesn't exist and is needed", function(done) {
      expectFailurePromise(requests.memberNoUser, 401, false, function() {
        expect(requests.memberNoUser.session.goingTo).to.equal('/members');
      }).then(done);
  });
});