const jwt = require("jsonwebtoken");

// const verifyToken = async(req,res,next) => {
//     const authHeader = req.headers.token
//     if(authHeader) {
//         const token =  authHeader.split(" ")[1]
//         jwt.verify(token,secretKey,(err,data)=> {
//             if (err) res.status(403).json({msg : 'invalid token'})
//                 req.user = data
//                 next();
//          });
//          } else {
//                 res.status(401).json({msg : 'authentication failed'})
//             }
//         }

const verifyToken = (req, res, next) => {
  const authHeader = req.headers.token;
  if (!authHeader) {
    return res.status(401).send("Authentication Failed");
  }
  try {
    const token = authHeader.split(" ")[1];
    const data = jwt.verify(token, process.env.SECRET_KEY);
    req.user = data;
    next();
  } catch (err) {
    console.log(err.message);
    res.status(401).send("Invalid token");
  }
};

const authorization = (req, res, next) => {
  verifyToken(req, res, () => {
    if (req.user.id === req.params.id || req.user.isAdmin) {
      next();
    } else {
      res.status(403).send("You are not allowed to perform these actions");
    }
  });
};

const admin = (req, res, next) => {
  verifyToken(req, res, () => {
    if (req.user.isAdmin) {
      next();
    } else {
      res.status(403).send("You are not allowed to perform these actions");
    }
  });
};

module.exports = { verifyToken, authorization, admin };
