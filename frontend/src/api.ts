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
    request("/auth/login", { method: "POST", body: JSON.stringify(body) }),
  me: () =>
    request<{ id: string; username: string; role: "administrator" | "viewer" }>(
      "/auth/me",
    ),
  logout: () => request("/auth/logout", { method: "POST" }),
  dashboard: () => request<Record<string, unknown>>("/dashboard"),
};
