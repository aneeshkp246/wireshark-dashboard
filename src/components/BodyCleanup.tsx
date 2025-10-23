"use client";

import { useEffect } from "react";

export default function BodyCleanup() {
  useEffect(() => {
    try {
      const body = document && document.body;
      if (!body) return;

      // Remove attributes injected by browser extensions or 3rd-party scripts
      for (const attr of Array.from(body.attributes)) {
        const name = attr.name;
        if (name.startsWith("__processed_") || name === "bis_register") {
          body.removeAttribute(name);
        }
      }
    } catch (e) {
      // ignore
    }
  }, []);

  return null;
}
