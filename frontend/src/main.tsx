import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { TimeRangeProvider } from "./timeRange";
import "./styles.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: (count, error) =>
        !(
          error instanceof Error &&
          "status" in error &&
          (error as { status: number }).status === 401
        ) && count < 2,
    },
  },
});
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <TimeRangeProvider>
          <App />
        </TimeRangeProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
