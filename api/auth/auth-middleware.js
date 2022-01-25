const bcrypt = require("bcryptjs");
const Users = require("../users/users-model");
/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    next({ status: 401, message: "You shall not pass" });
  }
}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/

async function checkUsernameFree(req, res, next) {
  try {
    const hashedPassword = bcrypt.hashSync(req.body.password, 10);
    const newUser = { username: req.body.username, password: hashedPassword };

    await Users.add(newUser)
      .then((resp) => {
        req.body.newUser = resp;
        next();
      })
      .catch(async (err) => {
        await Users.findBy({ username: req.body.username }).then((resp) => {
          res.status(422).json({ message: "Username taken" });
        });
      });
  } catch (err) {
    next(err);
  }
}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/

async function checkUsernameExists(req, res, next) {
  try {
    const { username, password } = req.body;
    const [user] = await Users.findBy({ username });

    if (user && bcrypt.compareSync(password, user.password)) {
      req.session.user = user;
      console.log(req.session);
      next();
    } else {
      next({ status: 401, message: "Invalid credentials" });
    }
  } catch (err) {
    next(err);
  }
}

/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/

async function checkPasswordLength(req, res, next) {
  try {
    const { username, password } = req.body;
    if (password === undefined) {
      res.status(422).json({ message: "Password must be longer than 3 chars" });
    } else if (password.length <= 3) {
      res.status(422).json({ message: "Password must be longer than 3 chars" });
    } else {
      next();
    }
  } catch (err) {
    console.log(err);
  }
}

// Don't forget to add these to the `exports` object so they can be required in other modules
module.exports = {
  restricted,
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength,
};
