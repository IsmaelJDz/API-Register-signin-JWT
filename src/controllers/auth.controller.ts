import { Request, Response } from "express";

export const signup = (req: Request, res: Response) => {
  res.send("Hello signup!");
};

export const signin = (req: Request, res: Response) => {
  res.send("Hello sigin!");
};

export const profile = (req: Request, res: Response) => {
  res.send("Hello profile!");
};
