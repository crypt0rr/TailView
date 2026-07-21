import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

export type TimeRange = "1h" | "24h" | "7d" | "30d";

const RANGE_HOURS: Record<TimeRange, number> = {
  "1h": 1,
  "24h": 24,
  "7d": 168,
  "30d": 720,
};

function validRange(value: string | null): value is TimeRange {
  return value !== null && value in RANGE_HOURS;
}

type TimeRangeState = {
  range: TimeRange;
  hours: number;
  setRange: (range: TimeRange) => void;
};

const TimeRangeContext = createContext<TimeRangeState>({
  range: "24h",
  hours: 24,
  setRange: () => undefined,
});

export function TimeRangeProvider({ children }: { children: React.ReactNode }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlRange = searchParams.get("range");
  const [range, setRangeState] = useState<TimeRange>(() => {
    if (validRange(urlRange)) return urlRange;
    const stored = localStorage.getItem("tailview.timeRange");
    return validRange(stored) ? stored : "24h";
  });

  useEffect(() => {
    if (validRange(urlRange) && urlRange !== range) setRangeState(urlRange);
  }, [range, urlRange]);

  const value = useMemo<TimeRangeState>(
    () => ({
      range,
      hours: RANGE_HOURS[range],
      setRange: (next) => {
        setRangeState(next);
        localStorage.setItem("tailview.timeRange", next);
        setSearchParams((current) => {
          const updated = new URLSearchParams(current);
          updated.set("range", next);
          return updated;
        });
      },
    }),
    [range, setSearchParams],
  );
  return <TimeRangeContext.Provider value={value}>{children}</TimeRangeContext.Provider>;
}

export function useTimeRange(): TimeRangeState {
  return useContext(TimeRangeContext);
}
