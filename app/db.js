var MongoClient = require("mongodb").MongoClient;

var db = null;

module.exports = {
    connect: function (url, done) {
        if (db) {
            return done(null, db);
        }
        
        MongoClient.connect(url, function (err, result) {
            if (err) {
                return done(err);
            }
            
            db = result;
            done(null, db);
        })
    },
    
    get: function () {
        return db;
    },
    
    close: function (done) {
        if (!db) {
            return done(null);
        }
        
        db.close(function (err, result) {
            if (err) {
                return done(err);
            }
            
            db = null;
            done(null);
        })
    }
}