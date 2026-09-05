import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { twoFactor } from "better-auth/plugins/two-factor";
import { passkey } from "@better-auth/passkey";
import { drizzle } from "drizzle-orm/d1";
import * as schema from "./schema";
import type { Env } from "./env";

export function createAuth(env: Env) {
  const origin = new URL(env.APP_URL).origin;
  const canEmail = Boolean(env.EMAIL_FROM && env.EMAIL);
  return betterAuth({
    appName: "Palisade",
    baseURL: origin,
    secret: env.BETTER_AUTH_SECRET,
    database: drizzleAdapter(drizzle(env.DB, { schema }), {
      provider: "sqlite",
      schema,
    }),
    trustedOrigins: [
      origin,
      ...(origin.startsWith("http://localhost")
        ? ["http://localhost:5173", "http://localhost:3000"]
        : []),
    ],
    emailAndPassword: {
      enabled: true,
      minPasswordLength: 12,
      maxPasswordLength: 128,
      requireEmailVerification: false,
      ...(canEmail
        ? {
            sendResetPassword: async ({
              user,
              url,
            }: {
              user: { email: string };
              url: string;
            }) => {
              await env.EMAIL!.send({
                from: env.EMAIL_FROM!,
                to: user.email,
                subject: "Reset your Palisade password",
                text: `Use this link to reset your Palisade password: ${url}\nIf you did not request this, ignore this email.`,
              });
            },
          }
        : {}),
    },
    ...(canEmail
      ? {
          emailVerification: {
            sendOnSignUp: true,
            autoSignInAfterVerification: false,
            sendVerificationEmail: async ({
              user,
              url,
            }: {
              user: { email: string };
              url: string;
            }) => {
              await env.EMAIL!.send({
                from: env.EMAIL_FROM!,
                to: user.email,
                subject: "Verify your email for Palisade",
                text: `Verify your email to enable private breach checks: ${url}\nIf you did not create this account, ignore this email.`,
              });
            },
          },
        }
      : {}),
    session: {
      expiresIn: 60 * 60 * 24 * 7,
      updateAge: 60 * 60 * 24,
      freshAge: 60 * 60,
    },
    user: { deleteUser: { enabled: true } },
    rateLimit: { enabled: true, storage: "database", window: 60, max: 40 },
    advanced: {
      useSecureCookies: origin.startsWith("https:"),
      database: { generateId: "uuid" },
    },
    plugins: [
      passkey({ rpID: new URL(origin).hostname, rpName: "Palisade", origin }),
      twoFactor({ issuer: "Palisade" }),
    ],
  });
}
