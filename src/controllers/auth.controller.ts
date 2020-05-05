import { Request, Response } from "express";
import User, { IUser } from "../models/User";

import jwt from "jsonwebtoken";

export const signup = async (req: Request, res: Response) => {
  //saving a new user
  const user: IUser = new User({
    username: req.body.username,
    email: req.body.email,
    password: req.body.password
  });
  user.password = await user.encryptPassword(user.password);
  const savedUser = await user.save();

  //token
  const token: string = jwt.sign(
    { _id: savedUser.id },
    process.env.TOKEN_SECRET || "tokentest"
  );

  res.header("auth-token", token).json(savedUser);
};

export const signin = async (req: Request, res: Response) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.send(400).json("Email or password is wrong");
  const correctPassword: boolean = await user.validatePassword(
    req.body.password
  );
  if (!correctPassword) return res.status(400).json("Invalid Password");

  const token: string = jwt.sign(
    { _id: user._id },
    process.env.TOKEN_SECRET || "whatever",
    {
      expiresIn: 60 * 60
    }
  );

  res.header("auth-token", token).json(user);
};

export const profile = (req: Request, res: Response) => {
  res.send("Hello profile!");
};
