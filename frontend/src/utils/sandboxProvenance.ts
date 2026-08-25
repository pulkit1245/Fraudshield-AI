// Sandbox provenance vocabulary — one source of truth for how the UI talks about
// *how* a dynamic finding was produced.
//
// Phase 1 of the sandbox hardening plan. The pipeline used to describe every
// dynamic finding as "observed during dynamic analysis" regardless of whether an
// APK had actually been executed on a device, so a simulation derived from
// static signals was indistinguishable from a real sandbox run. The backend now
// persists `dynamic_findings.mode`; this module turns that column into wording
// that never overclaims.
//
// Rules that must not be relaxed:
//   - Absent provenance (`null`/`undefined`) is UNKNOWN. It is never rendered as,
//     or defaulted to, a successful live run.
//   - Only `mode === "live"` means the sample was executed on a real device.
//   - `containment_verified !== true` is reported as NOT VERIFIED, never as
//     contained. Merely issuing `svc data disable` is not verification, and as of
//     the G4 investigation no run has ever verified it.
//
// Owner: Member D (display), Member C (data).
import type { DynamicFindingOut, SandboxMode } from "../types";

export type SandboxProvenanceLevel = "live" | "simulate" | "mobsf" | "unknown";

export interface SandboxProvenance {
  level: SandboxProvenanceLevel;
  mode: SandboxMode | null;
  /** Short pill text. */
  label: string;
  /** One-sentence explanation suitable for a banner. */
  summary: string;
  /**
   * Substituted into behaviour descriptions in place of the old unconditional
   * "during dynamic analysis". Reads as a continuation of "<Capability> was …".
   */
  observedPhrase: string;
  /** Heading for the per-capability evidence line ("Observed:" used to lie). */
  evidenceLabel: string;
  /** True when the sample actually ran on a device. Only `live` qualifies. */
  runtimeObserved: boolean;
  /** True when findings were derived rather than observed — do not read as evidence. */
  syntheticFindings: boolean;
  /** True whenever provenance is anything other than a live run. */
  degraded: boolean;
  /** Display colour for pills/banners. */
  tone: "green" | "yellow" | "gray";
  /** Human-readable containment state. Never claims containment on `null`. */
  containmentLabel: string;
  containmentTone: "green" | "yellow" | "red" | "gray";
}

/**
 * Derive display provenance from a dynamic finding.
 *
 * Pass `null`/`undefined` when there is no finding (or it has not loaded); the
 * result is the UNKNOWN level, which is safe to render but should generally be
 * suppressed by callers that know the dynamic stage never ran.
 */
export function deriveSandboxProvenance(
  dyn?: DynamicFindingOut | null
): SandboxProvenance {
  const mode = (dyn?.mode ?? null) as SandboxMode | null;
  const contained = dyn?.containment_verified ?? null;

  const containmentLabel =
    contained === true
      ? "Network containment verified"
      : contained === false
        ? "Network containment FAILED"
        : "Network containment not verified";
  const containmentTone: SandboxProvenance["containmentTone"] =
    contained === true ? "green" : contained === false ? "red" : "gray";

  const base = { mode, containmentLabel, containmentTone };

  switch (mode) {
    case "live":
      return {
        ...base,
        level: "live",
        label: "Live sandbox execution",
        summary:
          "The sample was installed and executed on a real Android device in the sandbox. The behaviour below was recorded from that run.",
        observedPhrase: "during live sandbox execution",
        evidenceLabel: "Observed",
        runtimeObserved: true,
        syntheticFindings: false,
        degraded: false,
        tone: "green",
      };
    case "simulate":
      return {
        ...base,
        label: "Simulated — not executed",
        level: "simulate",
        summary:
          "The sample was NOT executed. The behaviour below was inferred from static signals by the sandbox simulator, and is not runtime evidence. Treat it as a hypothesis, not an observation.",
        observedPhrase:
          "as inferred by the simulator from static signals — the sample was not executed",
        evidenceLabel: "Inferred",
        runtimeObserved: false,
        syntheticFindings: true,
        degraded: true,
        tone: "yellow",
      };
    case "mobsf":
      return {
        ...base,
        level: "mobsf",
        label: "External MobSF sandbox",
        summary:
          "Behaviour was reported by an external MobSF instance rather than by this project's own sandbox. Some entries are synthesised by the MobSF adapter rather than captured.",
        observedPhrase: "as reported by the external MobSF sandbox",
        evidenceLabel: "Reported",
        runtimeObserved: false,
        syntheticFindings: true,
        degraded: true,
        tone: "yellow",
      };
    default:
      return {
        ...base,
        level: "unknown",
        label: "Provenance unrecorded",
        summary:
          "How this finding was produced was not recorded, so it is not known whether the sample was actually executed. This is expected for analyses that predate provenance tracking. Do not read the behaviour below as confirmed runtime evidence.",
        observedPhrase:
          "during dynamic analysis — execution provenance was not recorded, so it is unknown whether the sample actually ran",
        evidenceLabel: "Reported",
        runtimeObserved: false,
        syntheticFindings: false,
        degraded: true,
        tone: "gray",
      };
  }
}

/**
 * Per-row provenance for a network-connection entry.
 *
 * Kept separate from threat classification on purpose: the report used to render
 * the `sink` flag (a *threat* marker) in a column headed "Classification" whose
 * only other value was "Observed" (a *provenance* word), which conflated the two.
 */
export function networkCallOrigin(prov: SandboxProvenance): {
  label: string;
  tone: "green" | "yellow" | "gray";
} {
  switch (prov.level) {
    case "live":
      return { label: "Captured", tone: "green" };
    case "simulate":
      return { label: "Synthesised", tone: "yellow" };
    case "mobsf":
      return { label: "MobSF-reported", tone: "yellow" };
    default:
      return { label: "Unrecorded", tone: "gray" };
  }
}
