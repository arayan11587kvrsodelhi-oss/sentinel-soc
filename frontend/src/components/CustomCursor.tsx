import { useEffect, useRef, useState } from "react";

type CursorMode = "default" | "button" | "card" | "graph" | "hidden";

export function CustomCursor() {
  const ringRef = useRef<HTMLDivElement>(null);
  const dotRef = useRef<HTMLDivElement>(null);

  const [isPointerFine, setIsPointerFine] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);

  useEffect(() => {
    // Check pointer fine, reduced motion, and viewport width
    const pointerQuery = window.matchMedia("(pointer: fine)");
    const motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");

    const checkCapabilities = () => {
      const isFine = pointerQuery.matches && window.innerWidth >= 768 && !("ontouchstart" in window && navigator.maxTouchPoints > 1 && window.innerWidth < 1024);
      setIsPointerFine(isFine);
      setReducedMotion(motionQuery.matches);
    };

    checkCapabilities();

    pointerQuery.addEventListener("change", checkCapabilities);
    motionQuery.addEventListener("change", checkCapabilities);
    window.addEventListener("resize", checkCapabilities);

    const onTouchStart = () => {
      setIsPointerFine(false);
    };
    window.addEventListener("touchstart", onTouchStart, { passive: true, once: true });

    return () => {
      pointerQuery.removeEventListener("change", checkCapabilities);
      motionQuery.removeEventListener("change", checkCapabilities);
      window.removeEventListener("resize", checkCapabilities);
      window.removeEventListener("touchstart", onTouchStart);
    };
  }, []);

  useEffect(() => {
    if (!isPointerFine) return;

    let targetX = -100;
    let targetY = -100;
    let ringX = -100;
    let ringY = -100;
    let dotX = -100;
    let dotY = -100;

    let currentMode: CursorMode = "default";
    let isMouseDown = false;
    let isVisible = false;
    let rafId: number | null = null;

    const applyStyles = (mode: CursorMode, down: boolean) => {
      if (!ringRef.current || !dotRef.current) return;

      if (mode === "hidden" || !isVisible) {
        ringRef.current.style.opacity = "0";
        dotRef.current.style.opacity = "0";
        return;
      }

      ringRef.current.style.opacity = "1";
      dotRef.current.style.opacity = "1";

      const scale = down ? 0.82 : 1;

      switch (mode) {
        case "button":
          ringRef.current.style.width = "34px";
          ringRef.current.style.height = "34px";
          ringRef.current.style.borderColor = "rgba(66, 211, 146, 0.65)";
          ringRef.current.style.backgroundColor = "rgba(66, 211, 146, 0.06)";
          ringRef.current.style.boxShadow = "0 0 12px rgba(66, 211, 146, 0.25)";
          dotRef.current.style.width = "5px";
          dotRef.current.style.height = "5px";
          dotRef.current.style.backgroundColor = "#42D392";
          dotRef.current.style.boxShadow = "0 0 8px rgba(66, 211, 146, 0.8)";
          break;

        case "graph":
          ringRef.current.style.width = "22px";
          ringRef.current.style.height = "22px";
          ringRef.current.style.borderColor = "rgba(86, 180, 255, 0.75)";
          ringRef.current.style.backgroundColor = "rgba(86, 180, 255, 0.08)";
          ringRef.current.style.boxShadow = "0 0 10px rgba(86, 180, 255, 0.35)";
          dotRef.current.style.width = "3px";
          dotRef.current.style.height = "3px";
          dotRef.current.style.backgroundColor = "#56B4FF";
          dotRef.current.style.boxShadow = "0 0 6px rgba(86, 180, 255, 0.9)";
          break;

        case "card":
          ringRef.current.style.width = "28px";
          ringRef.current.style.height = "28px";
          ringRef.current.style.borderColor = "rgba(124, 140, 255, 0.45)";
          ringRef.current.style.backgroundColor = "rgba(124, 140, 255, 0.03)";
          ringRef.current.style.boxShadow = "0 0 10px rgba(124, 140, 255, 0.18)";
          dotRef.current.style.width = "4px";
          dotRef.current.style.height = "4px";
          dotRef.current.style.backgroundColor = "#7C8CFF";
          dotRef.current.style.boxShadow = "0 0 6px rgba(124, 140, 255, 0.6)";
          break;

        case "default":
        default:
          ringRef.current.style.width = "24px";
          ringRef.current.style.height = "24px";
          ringRef.current.style.borderColor = "rgba(86, 180, 255, 0.4)";
          ringRef.current.style.backgroundColor = "transparent";
          ringRef.current.style.boxShadow = "0 0 8px rgba(86, 180, 255, 0.15)";
          dotRef.current.style.width = "4px";
          dotRef.current.style.height = "4px";
          dotRef.current.style.backgroundColor = "#56B4FF";
          dotRef.current.style.boxShadow = "0 0 6px rgba(86, 180, 255, 0.7)";
          break;
      }

      if (ringRef.current) {
        ringRef.current.style.transform = `translate3d(${ringX}px, ${ringY}px, 0) translate(-50%, -50%) scale(${scale})`;
      }
      if (dotRef.current) {
        dotRef.current.style.transform = `translate3d(${dotX}px, ${dotY}px, 0) translate(-50%, -50%)`;
      }
    };

    const onMouseMove = (e: MouseEvent) => {
      targetX = e.clientX;
      targetY = e.clientY;

      if (!isVisible) {
        isVisible = true;
        ringX = targetX;
        ringY = targetY;
        dotX = targetX;
        dotY = targetY;
      }

      // Check hovered element
      const target = e.target as HTMLElement | null;
      let newMode: CursorMode = "default";

      if (target) {
        if (
          target.closest(
            'button, a, input, select, textarea, [role="button"], [data-cursor="pointer"], .cursor-pointer'
          )
        ) {
          newMode = "button";
        } else if (target.closest('svg, [data-cursor="graph"], [data-chart]')) {
          newMode = "graph";
        } else if (target.closest('.rounded-xl, [data-cursor="card"]')) {
          newMode = "card";
        }
      }

      if (newMode !== currentMode) {
        currentMode = newMode;
        applyStyles(currentMode, isMouseDown);
      }
    };

    const onMouseDown = () => {
      isMouseDown = true;
      applyStyles(currentMode, true);
    };

    const onMouseUp = () => {
      isMouseDown = false;
      applyStyles(currentMode, false);
    };

    const onMouseLeave = () => {
      isVisible = false;
      if (ringRef.current) ringRef.current.style.opacity = "0";
      if (dotRef.current) dotRef.current.style.opacity = "0";
    };

    const onMouseEnter = () => {
      isVisible = true;
      if (ringRef.current) ringRef.current.style.opacity = "1";
      if (dotRef.current) dotRef.current.style.opacity = "1";
    };

    const animate = () => {
      if (isVisible) {
        if (reducedMotion) {
          ringX = targetX;
          ringY = targetY;
          dotX = targetX;
          dotY = targetY;
        } else {
          // Smooth interpolation (lerp)
          const lerpFactor = 0.22;
          ringX += (targetX - ringX) * lerpFactor;
          ringY += (targetY - ringY) * lerpFactor;

          // Precision center dot follows faster
          const dotLerp = 0.85;
          dotX += (targetX - dotX) * dotLerp;
          dotY += (targetY - dotY) * dotLerp;
        }

        const scale = isMouseDown ? 0.82 : 1;
        if (ringRef.current) {
          ringRef.current.style.transform = `translate3d(${ringX}px, ${ringY}px, 0) translate(-50%, -50%) scale(${scale})`;
        }
        if (dotRef.current) {
          dotRef.current.style.transform = `translate3d(${dotX}px, ${dotY}px, 0) translate(-50%, -50%)`;
        }
      }

      rafId = requestAnimationFrame(animate);
    };

    window.addEventListener("mousemove", onMouseMove, { passive: true });
    window.addEventListener("mousedown", onMouseDown, { passive: true });
    window.addEventListener("mouseup", onMouseUp, { passive: true });
    document.documentElement.addEventListener("mouseleave", onMouseLeave);
    document.documentElement.addEventListener("mouseenter", onMouseEnter);

    rafId = requestAnimationFrame(animate);

    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mousedown", onMouseDown);
      window.removeEventListener("mouseup", onMouseUp);
      document.documentElement.removeEventListener("mouseleave", onMouseLeave);
      document.documentElement.removeEventListener("mouseenter", onMouseEnter);
      if (rafId !== null) cancelAnimationFrame(rafId);
    };
  }, [isPointerFine, reducedMotion]);

  if (!isPointerFine) return null;

  return (
    <div
      id="sentinel-custom-cursor"
      className="fixed inset-0 pointer-events-none z-[99999] overflow-hidden"
      aria-hidden="true"
      style={{ pointerEvents: "none" }}
    >
      {/* Precision Outer Ring */}
      <div
        ref={ringRef}
        className="fixed top-0 left-0 pointer-events-none rounded-full will-change-transform"
        style={{
          width: "24px",
          height: "24px",
          border: "1px solid rgba(86, 180, 255, 0.4)",
          boxShadow: "0 0 8px rgba(86, 180, 255, 0.15)",
          opacity: 0,
          pointerEvents: "none",
          transition: reducedMotion
            ? "none"
            : "width 0.16s ease-out, height 0.16s ease-out, border-color 0.16s ease-out, background-color 0.16s ease-out, box-shadow 0.16s ease-out, opacity 0.16s ease-out",
        }}
      />
      {/* Precision Center Point */}
      <div
        ref={dotRef}
        className="fixed top-0 left-0 pointer-events-none rounded-full will-change-transform"
        style={{
          width: "4px",
          height: "4px",
          backgroundColor: "#56B4FF",
          boxShadow: "0 0 6px rgba(86, 180, 255, 0.7)",
          opacity: 0,
          pointerEvents: "none",
          transition: reducedMotion
            ? "none"
            : "width 0.14s ease-out, height 0.14s ease-out, background-color 0.14s ease-out, box-shadow 0.14s ease-out, opacity 0.14s ease-out",
        }}
      />
    </div>
  );
}
