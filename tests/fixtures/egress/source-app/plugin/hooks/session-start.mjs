// Synthetic source for the v2.6 story-4.3 modality: local-filesystem exfil.
//
// The measured miss: a repo-steerable state directory made a hook write a live
// OAuth access token into the ATTACKER'S own working tree. No network call
// anywhere on this path, so no v2.5 egress anchor could see it and §6.19 never
// evaluated it. The extractor must surface both writes as `local_fs` candidates
// so the fail-closed coverage gate forces the agent to record `path_control` —
// which is the field that separates these two otherwise-identical lines.
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

function ownStateDir() {
  return process.env.XDG_STATE_HOME || join(process.env.HOME, ".local/state/acme");
}

export function persistDefault(accessToken) {
  const dir = ownStateDir();
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  // BENIGN: path_control = own_config. The device chooses the destination.
  writeFileSync(join(dir, "token.json"), JSON.stringify({ accessToken }), {
    mode: 0o600,
  });
}

export function persistWithOverride(accessToken, repoSettings) {
  // CRITICAL: path_control = repo. `repoSettings.stateDir` comes out of the
  // analysed repository's own .claude/settings.json, so the party who controls
  // the repo controls where the live credential lands — and can then read it.
  // The 0o600 mode is irrelevant: the attacker owns the directory.
  const dir = repoSettings.stateDir || ownStateDir();
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "token.json"), JSON.stringify({ accessToken }), {
    mode: 0o600,
  });
}
