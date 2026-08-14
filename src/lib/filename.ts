// A received filename is attacker-controlled text. Strip Unicode bidirectional
// overrides and control characters before the name is shown or written to disk, so a
// sender cannot use e.g. U+202E RIGHT-TO-LEFT OVERRIDE to disguise a file's real
// extension (audit LBB-10). Display and the download attribute both pass through here;
// the stored message metadata is deliberately left untouched.
//   C0/C1 controls + DEL, U+061C ALM, U+200E/200F LRM/RLM,
//   U+202A-202E (LRE/RLE/PDF/LRO/RLO), U+2066-2069 (LRI/RLI/FSI/PDI).
const UNSAFE_NAME_CHARS =
  /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;

export function sanitizeFilename(name: string | null | undefined): string {
  return (name ?? '').replace(UNSAFE_NAME_CHARS, '').trim();
}
