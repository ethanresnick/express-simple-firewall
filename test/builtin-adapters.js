var expect = require('chai').expect
  , Q = require("Q")
  , adapters = require('../lib/adapters/builtin');

var sessionAdapter = adapters.sessionBased(function(userId) {
  //this user getter rejects with an error in the case
  //of an invalid user. Other getters might resolve with
  //noting. But it doesn't really matter.
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
});

var dummyUsers = [
  {hasRole: function(role) { }, isApproved: false},
  {hasRole: function(role) { }, isApproved: true}
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
  sessionNoUser: {
    url: '/public',
    method: 'post',
    session: {}
  }
};

describe("the session adapter", function() {
  it("should populate req.user by reading req.session.user_id", function(done) {
    sessionAdapter(requests.sessionUser0, {}, function(err) {
      expect(err).to.not.exist;
      expect(requests.sessionUser0.user).to.equal(dummyUsers[0]);
      delete requests.sessionUser0.user;
      done();
    });
  });

  it("should pass along the error if req.session.user_id is set but a corresponding user can't be retrieved", function(done) {
    sessionAdapter(requests.invalidSession, {}, function(err) {
      expect(err).to.be.an.instanceof(Error).with.property('message', 'Invalid user!');
      done();
    });
  });

  it("should just call next if no req.session.user_id is present", function(done) {
    sessionAdapter(requests.sessionNoUser, {}, function(err) {
      expect(requests.sessionNoUser.user).to.be.undefined;
      expect(err).to.not.exist;
      done(); //next was called.
    });
  });
});