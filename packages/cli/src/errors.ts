export class PalisadeError extends Error {
  constructor(
    public code: string,
    message: string,
    public exitCode = 1,
  ) {
    super(message);
    this.name = "PalisadeError";
  }
}
export function errorInfo(error: unknown): { code: string; message: string } {
  if (error instanceof PalisadeError)
    return { code: error.code, message: error.message };
  if (error instanceof Error && error.name === "ZodError")
    return {
      code: "VALIDATION_ERROR",
      message: "Invalid input: " + error.message,
    };
  return {
    code: "OPERATION_FAILED",
    message: error instanceof Error ? error.message : "Operation failed.",
  };
}
