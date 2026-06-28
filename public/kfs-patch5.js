/**
 * kfs-patch5.js  — Social Strand Patch v5
 * =========================================
 * Loaded by membersaccess.html (add alongside kfs-patch4.js).
 *
 * This patch has NO Social Strand UI changes.
 * It exists as the correct place for any future member-side
 * additions without touching membersaccess.html.
 *
 * Mobile nav architecture note (answers your question):
 * ──────────────────────────────────────────────────────
 * The "Network bar" (bottom pill nav) and the "site bar" (desktop sidebar)
 * serve DIFFERENT contexts and are BOTH needed:
 *
 *   • Desktop sidebar  — always visible on ≥769 px; provides full text labels,
 *     nested settings, and the member chip. Cannot exist on mobile because
 *     it eats the full left column.
 *
 *   • Bottom pill nav (btb)  — shown ONLY on mobile/touch (≤768 px + pointer:coarse).
 *     It floats over content, is gesture-friendly, and follows iOS/Android
 *     tap-target guidelines (44 px minimum). The desktop sidebar is hidden on
 *     these viewports.
 *
 * So they're NOT duplicates — they're the same navigation adapted for two
 * different form factors via a responsive media query.  Removing either one
 * would break usability on that viewport class.
 *
 * The only items that could be trimmed from the bottom nav are the ones that
 * are already accessible from the Settings bottom-sheet (Profile, Security,
 * My Movies, etc.) — and they already are excluded; the nav only exposes the
 * 4 primary destinations + post + settings-sheet trigger, which is the
 * recommended pattern for Instagram-style apps.
 */

(function () {
  'use strict';
  // Reserved for future Social Strand member-side additions.
  // All current changes are server-side (API) or in kfs-admin-patch.js.
})();
