const API = "/api/v1";

function csrfToken(): string {
  return (
    document.cookie
      .split("; ")
      .find((row) => row.startsWith("tailview_csrf="))
      ?.split("=")[1] ?? ""
  );
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

export type CurrentUser = {
  id: string;
  username: string;
  display_name: string;
  role: "administrator" | "viewer";
  must_change_password: boolean;
  mfa_enabled: boolean;
  mfa_required: boolean;
  auth_status: "authenticated" | "password_change_required" | "mfa_enrollment_required";
};

export type AuthResult = {
  status: "authenticated" | "password_change_required" | "mfa_enrollment_required" | "mfa_required";
  user: CurrentUser | null;
  challenge: string | null;
};

export async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    credentials: "include",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.method && options.method !== "GET"
        ? { "X-CSRF-Token": decodeURIComponent(csrfToken()) }
        : {}),
      ...options.headers,
    },
  });
  if (!response.ok) {
    const body = (await response
      .json()
      .catch(() => ({ message: response.statusText }))) as {
      message?: string;
      detail?: string;
    };
    throw new ApiError(
      response.status,
      body.message ?? body.detail ?? "Request failed",
    );
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export const api = {
  setupStatus: () => request<{ required: boolean }>("/setup/status"),
  setup: (body: unknown) =>
    request("/setup", { method: "POST", body: JSON.stringify(body) }),
  login: (body: unknown) =>
    request<AuthResult>("/auth/login", { method: "POST", body: JSON.stringify(body) }),
  verifyMfa: (body: unknown) =>
    request<AuthResult>("/auth/mfa/verify", { method: "POST", body: JSON.stringify(body) }),
  me: () => request<CurrentUser>("/auth/me"),
  logout: () => request("/auth/logout", { method: "POST" }),
  dashboard: () => request<Record<string, unknown>>("/dashboard"),
};
