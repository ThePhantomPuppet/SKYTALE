// Inline image decoders can expand compressed data by orders of magnitude. Large
// files remain available as explicit downloads instead of entering a browser codec.
export const MAX_INLINE_IMAGE_BYTES = 25 * 1024 * 1024;

// WebAudio's decodeAudioData requires a full ArrayBuffer plus decoded PCM. Keep
// native <audio> playback for larger files, but skip automatic waveform analysis.
export const MAX_AUDIO_ANALYSIS_BYTES = 8 * 1024 * 1024;

function bounded(size: number, max: number): boolean {
  return Number.isSafeInteger(size) && size >= 0 && size <= max;
}

export function mayRenderInlineImage(mime: string, size: number): boolean {
  // Raster only. An <img> renders SVG inertly, but keeping image/svg+xml (and any xml
  // image type) out of the inline sink limits it to safely-decoded bitmap formats
  // (audit LBB-10 defense-in-depth).
  const m = mime.toLowerCase();
  return (
    m.startsWith('image/') &&
    !m.includes('svg') &&
    !m.includes('xml') &&
    bounded(size, MAX_INLINE_IMAGE_BYTES)
  );
}

export function mayAnalyzeAudio(size: number): boolean {
  return bounded(size, MAX_AUDIO_ANALYSIS_BYTES);
}
