import React, { useEffect } from 'react';

/**
 * Ambient Cursor Spotlight component that updates CSS variables (--cursor-x, --cursor-y)
 * on mouse movements to create a subtle, futuristic lighting effect across cards and surfaces.
 */
export default function CursorSpotlight() {
  useEffect(() => {
    // Check if user prefers reduced motion or is on a touch-only device
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const isTouchDevice = 'ontouchstart' in window || navigator.maxTouchPoints > 0;

    if (prefersReducedMotion || isTouchDevice) {
      return;
    }

    let ticking = false;

    const handleMouseMove = (e) => {
      if (!ticking) {
        requestAnimationFrame(() => {
          document.documentElement.style.setProperty('--cursor-x', `${e.clientX}px`);
          document.documentElement.style.setProperty('--cursor-y', `${e.clientY}px`);
          ticking = false;
        });
        ticking = true;
      }
    };

    window.addEventListener('mousemove', handleMouseMove, { passive: true });
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
    };
  }, []);

  return <div className="cursor-spotlight" aria-hidden="true" />;
}
