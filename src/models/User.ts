import { Schema, model, Document } from "mongoose";
import bcrypt from "bcryptjs";

export interface IUser extends Document {
  username: string;
  email: string;
  password: string;
  encryptPassword(pass: string): Promise<string>;
  validatePassword(pass: string): Promise<boolean>;
}

const userSchema = new Schema({
  username: {
    type: String,
    required: true,
    min: 4,
    lowercase: true
  },
  email: {
    type: String,
    unique: true,
    required: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true
  }
});

userSchema.methods.encryptPassword = async (pass: string): Promise<string> => {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(pass, salt);
};

// expresion function para acceder al contexto del this en userSchema
userSchema.methods.validatePassword = async function(
  pass: string
): Promise<boolean> {
  return await bcrypt.compare(pass, this.password);
};

export default model<IUser>("User", userSchema);
