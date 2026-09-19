/**
 * IMMUNE-NET Motion System
 * Purposeful, restrained motion for an enterprise defence command center.
 */

export const TRANSITION_TIMINGS = {
  MICRO: 0.16,
  STANDARD: 0.28,
  EMPHASIS: 0.5,
  CINEMATIC: 0.9,
};

export const EASINGS = {
  smooth: [0.25, 0.1, 0.25, 1.0],
  easeOutQuart: [0.165, 0.84, 0.44, 1],
  anticipate: [0.36, 0, 0.66, -0.56],
};

export const SPRINGS = {
  gentle: { type: 'spring', stiffness: 280, damping: 26 },
  snappy: { type: 'spring', stiffness: 420, damping: 30 },
  subtle: { type: 'spring', stiffness: 320, damping: 32 },
};

// Staggered Container Variant
export const staggerContainer = (staggerChildren = 0.08, delayChildren = 0.05) => ({
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: {
      staggerChildren,
      delayChildren,
    },
  },
});

// Fade in upwards variant (standard card & table row reveal)
export const fadeInUp = {
  hidden: { opacity: 0, y: 12 },
  show: {
    opacity: 1,
    y: 0,
    transition: {
      duration: TRANSITION_TIMINGS.STANDARD,
      ease: EASINGS.easeOutQuart,
    },
  },
};

// Fade in downwards variant (top command bar, banners)
export const fadeInDown = {
  hidden: { opacity: 0, y: -10 },
  show: {
    opacity: 1,
    y: 0,
    transition: {
      duration: TRANSITION_TIMINGS.STANDARD,
      ease: EASINGS.easeOutQuart,
    },
  },
};

// Scale in variant (badges, icons, alerts)
export const scaleIn = {
  hidden: { opacity: 0, scale: 0.94 },
  show: {
    opacity: 1,
    scale: 1,
    transition: {
      duration: TRANSITION_TIMINGS.STANDARD,
      ease: EASINGS.easeOutQuart,
    },
  },
};

// Slide in from right (drawers, inspection sidebars)
export const slideInRight = {
  hidden: { opacity: 0, x: 28 },
  show: {
    opacity: 1,
    x: 0,
    transition: {
      duration: TRANSITION_TIMINGS.STANDARD,
      ease: EASINGS.easeOutQuart,
    },
  },
  exit: {
    opacity: 0,
    x: 28,
    transition: {
      duration: TRANSITION_TIMINGS.MICRO,
      ease: 'easeIn',
    },
  },
};

// Page transition container
export const pageTransition = {
  hidden: { opacity: 0, y: 8 },
  show: {
    opacity: 1,
    y: 0,
    transition: {
      duration: TRANSITION_TIMINGS.STANDARD,
      ease: EASINGS.smooth,
      when: 'beforeChildren',
      staggerChildren: 0.06,
    },
  },
  exit: {
    opacity: 0,
    y: -6,
    transition: { duration: TRANSITION_TIMINGS.MICRO },
  },
};
