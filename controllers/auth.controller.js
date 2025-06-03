import bcryptjs from "bcryptjs";
import User from "../models/user.model.js";
import { errorHandler } from "../utils/error.js";
import jwt from "jsonwebtoken";

export const signup = async (req, res, next) => {
  const { username, email, password } = req.body;

  // 1. Basic input validation for presence and non-emptiness
  if (
    !username ||
    !email ||
    !password ||
    username === "" ||
    email === "" ||
    password === ""
  ) {
    return next(errorHandler(400, "All fields are required"));
  }

  // 2. Check if a user with the same email already exists
  const existingUserByEmail = await User.findOne({ email });

  if (existingUserByEmail) {
    return next(errorHandler(409, "User already exist with this email!"));
  }

  // 3. IMPORTANT: Check if a user with the same username already exists
  const existingUserByUsername = await User.findOne({ username });
  if (existingUserByUsername) {
    return next(
      errorHandler(
        409,
        "Username is already taken! Please choose a different one."
      )
    );
  }

  // 4. Hash the password
  const hashedPassword = bcryptjs.hashSync(password, 10);

  // 5. Create a new user instance
  const newUser = new User({
    username,
    email,
    password: hashedPassword,
  });

  try {
    // 6. Save the new user to the database
    await newUser.save();

    res.json("Signup successful");
  } catch (error) {
    next(error);
  }
};

// ... your signin function remains the same
export const signin = async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password || email === "" || password === "") {
    return next(errorHandler(400, "All fields are required"));
  }

  try {
    const validUser = await User.findOne({ email });

    if (!validUser) {
      return next(errorHandler(404, "User not found"));
    }

    const validPassword = bcryptjs.compareSync(password, validUser.password);

    if (!validPassword) {
      return next(errorHandler(400, "Wrong Credentials"));
    }

    const token = jwt.sign({ id: validUser._id }, process.env.JWT_SECRET);

    const { password: pass, ...rest } = validUser._doc;

    res
      .status(200)
      .cookie("access_token", token, {
        httpOnly: true,
      })
      .json(rest);
  } catch (error) {
    next(error);
  }
};
