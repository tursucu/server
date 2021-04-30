import {
  Arg,
  Ctx,
  Mutation,
  Query,
  Resolver,
  Field,
  InputType,
  ObjectType,
} from "type-graphql";
import { UserClass } from "../models/User";
import { ContextType } from "../types";
import bcrypt from "bcryptjs";

@InputType()
class UserInput {
  @Field()
  firstName: string;

  @Field()
  lastName: string;

  @Field()
  email: string;

  @Field()
  password: string;
}

@InputType()
class UserLoginInput {

  @Field()
  email: string;

  @Field()
  password: string;
}


@ObjectType()
class FieldError {
  @Field()
  code: string;

  @Field()
  message: string;
}

@ObjectType()
class UserResponse {
  @Field(() => [FieldError], { nullable: true })
  errors?: FieldError[];

  @Field(() => UserClass, { nullable: true })
  user?: UserClass;
}

@Resolver(UserClass)
export class UserResolver {
  @Query(() => UserClass,{nullable:true})
  async me(
      @Ctx() { User,req }: ContextType
  ) {
    console.log(req.session)
    if (!req.session.userEmail) {
      return null;
    }

    return User.findOne({email:req.session.userEmail});
  }

  @Mutation(() => UserResponse)
  async register(
    @Arg("data") { firstName, lastName, email, password }: UserInput,
    @Ctx() { User }: ContextType
  ): Promise<UserResponse> {

    if (!/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/.test(email)) {
      return {
        errors: [
          {
            code: "AUTH_FAIL_EMAIL",
            message: "Invalid e-mail address.",
          },
        ],
      };
    }

    const emailControl = await User.findOne({ email });

    if (emailControl) {
      return {
        errors: [
          {
            code: "AUTH_FAIL_EMAIL",
            message: "This e-mail address has already been registered.",
          },
        ],
      };
    }

    const user = await new User({
      firstName,
      lastName,
      email,
      password,
    }).save()

    return {user};
  }

  @Mutation(() => UserResponse)
  async login(
    @Arg("data") { email, password }: UserLoginInput,
    @Ctx() { User,req }: ContextType
  ): Promise<UserResponse> {

    const user = await User.findOne({ email });
    if (!user) {
      return {
        errors: [
          {
            code: "AUTH_FAIL_EMAIL",
            message: "E-mail address not found.",
          },
        ],
      };
    }

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return {
        errors: [
          {
            code: "AUTH_FAIL_PASSWORD",
            message: "Password could not be verified.",
          },
        ],
      };
    }

    req.session.userEmail = user.email;

    return { user };
  }
}
