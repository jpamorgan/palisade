export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  BETTER_AUTH_SECRET: string;
  DATA_ENCRYPTION_KEY: string;
  APP_URL: string;
  EMAIL_FROM?: string;
  EMAIL?: {
    send(message: {
      from: string;
      to: string;
      subject: string;
      text: string;
      html?: string;
    }): Promise<unknown>;
  };
  MONITOR_QUEUE?: Queue<{ userId: string }>;
  AI?: Ai;
}
export interface Principal {
  id: string;
  email: string;
  name: string;
  emailVerified: boolean;
  scopes: string[];
  source: "session" | "token";
  sessionCreatedAt?: Date;
}
export class AppError extends Error {
  constructor(
    public code: string,
    message: string,
    public status = 400,
  ) {
    super(message);
  }
}
