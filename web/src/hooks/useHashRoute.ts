import { useState, useEffect, useCallback } from "react";

/* 輕量 hash router 處理 #/ 與 #/scans/{id} */
export function useHashRoute(): [string, (path: string) => void] {
  const [route, setRoute] = useState(window.location.hash.slice(1) || "/");
  useEffect(() => {
    const onChange = () => setRoute(window.location.hash.slice(1) || "/");
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  const navigate = useCallback((path: string) => {
    window.location.hash = path;
  }, []);
  return [route, navigate];
}
