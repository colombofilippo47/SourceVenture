import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { MotionConfig } from "motion/react";
import App from "./App.jsx";
import "./index.css";

createRoot(document.getElementById("root")).render(
  <StrictMode>
    {/* reducedMotion="user" makes every motion.* element in the tree skip
        its animation and jump straight to the "animate" state when the OS
        (or a headless browser's ui.prefersReducedMotion pref) requests
        reduced motion — one place instead of guarding each entrance
        animation individually. */}
    <MotionConfig reducedMotion="user">
      <App />
    </MotionConfig>
  </StrictMode>
);
