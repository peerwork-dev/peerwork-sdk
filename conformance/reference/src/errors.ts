export class ApiError extends Error {
  constructor(public code: string, public status: number, message = code) { super(message); }
}
export function requireThat(condition: unknown, code: string, status = 400): asserts condition {
  if (!condition) throw new ApiError(code, status);
}
