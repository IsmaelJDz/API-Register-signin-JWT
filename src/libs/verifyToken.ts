import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

interface Ipayload {
  _id: string;
  iat: number;
  exp: number;
}

export const TokenValidation = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const token = req.header("auth-token");
  if (!token) return res.status(401).json("Access denied");

  try {
    const payload = jwt.verify(
      token,
      process.env.TOKEN_SECRET || "whatever"
    ) as Ipayload;

    req.userId = payload._id;
  } catch (error) {
    return res.status(401).json("Token expired");
  }

  next();
};
