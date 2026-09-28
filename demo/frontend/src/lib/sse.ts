import { useEffect, useState } from "react";

export function useSSE<T>(path: string, onEvent?: (evt: T) => void) {
  const [events, setEvents] = useState<T[]>([]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const src = new EventSource(`${typeof window !== "undefined" ? `http://${window.location.hostname}:8100/api/demo` : process.env.NEXT_PUBLIC_DEMO_API_URL || "http://localhost:8100/api/demo"}/${path}`);
    src.onmessage = (e) => {
      try {
        const parsed = JSON.parse(e.data) as T;
        setEvents((prev) => [parsed, ...prev].slice(0, 200));
        onEvent?.(parsed);
      } catch {
        /* ignore malformed frame */
      }
    };
    src.addEventListener("event", (e) => {
      try {
        const parsed = JSON.parse((e as MessageEvent).data) as T;
        setEvents((prev) => [parsed, ...prev].slice(0, 200));
        onEvent?.(parsed);
      } catch {
        /* ignore */
      }
    });
    return () => src.close();
  }, [path]);

  return events;
}