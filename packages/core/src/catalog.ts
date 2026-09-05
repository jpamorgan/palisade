import type {
  Category,
  CheckDefinition,
  CategoryId,
  AssetKind,
  Severity,
} from "./types";

export const CATALOG_VERSION = "2026.09.1";
export const SCORE_VERSION = "1.0.0";
export const CATEGORIES: Category[] = [
  {
    id: "exposure",
    name: "Public footprint & exposure",
    description: "What can someone learn or obtain about you?",
    weight: 10,
  },
  {
    id: "accounts",
    name: "Accounts & sign-in",
    description: "Can someone access your important accounts?",
    weight: 20,
  },
  {
    id: "recovery",
    name: "Recovery & phone security",
    description: "Can someone bypass your login or lock you out?",
    weight: 15,
  },
  {
    id: "devices",
    name: "Devices & browsers",
    description: "Can someone control a device or steal a session?",
    weight: 20,
  },
  {
    id: "network",
    name: "Home network & connected devices",
    description: "Can an unwanted connection reach something important?",
    weight: 5,
  },
  {
    id: "finance",
    name: "Money & identity protection",
    description: "Can exposed information become financial loss?",
    weight: 15,
  },
  {
    id: "data",
    name: "Data, secrets & backups",
    description: "What could be stolen or lost, and can you recover it?",
    weight: 10,
  },
  {
    id: "response",
    name: "Monitoring & response",
    description: "Will you notice a problem and know what to do?",
    weight: 5,
  },
];

type Spec = {
  id: string;
  category: CategoryId;
  title: string;
  description: string;
  verify: string;
  steps: string[];
  severity?: Severity;
  days?: number;
  kinds?: AssetKind[];
  local?: boolean;
  provider?: boolean;
  partial?: string;
  lockout?: boolean;
  effort?: "quick" | "moderate" | "involved";
  region?: string;
  module?: string;
};
function check(s: Spec): CheckDefinition {
  return {
    id: s.id,
    categoryId: s.category,
    title: s.title,
    description: s.description,
    weight: 1,
    severity: s.severity ?? "medium",
    freshnessDays: s.days ?? 90,
    guidance: [
      s.verify,
      "Record the setting or procedure you actually checked, the scope, and today's observation. Keep passwords, codes and identity documents out of your notes.",
    ],
    verification: s.verify,
    ...(s.partial ? { partialCriteria: s.partial } : {}),
    acceptedMethods: [
      "guided",
      ...(s.local ? ["local" as const] : []),
      ...(s.provider ? ["provider" as const] : []),
    ],
    remediation: {
      title: s.title,
      steps: s.steps,
      effort: s.effort ?? "moderate",
      lockoutRisk: s.lockout ?? false,
      rollback: s.lockout
        ? "Keep an existing working session and a tested independent recovery method until the replacement works. If verification fails, stop and use the provider's official recovery process."
        : "Record the original non-secret setting before changes. Use official support if a change causes a problem; do not restore a known compromised credential.",
    },
    ...(s.kinds ? { assetKinds: s.kinds } : {}),
    ...(s.local ? { automated: "macos" } : {}),
    ...(s.provider ? { automated: "hibp" } : {}),
    ...(s.region ? { region: s.region } : {}),
    ...(s.module ? { module: s.module } : {}),
  };
}

const specs: Spec[] = [
  {
    id: "exposure.breach-review",
    category: "exposure",
    title: "Review known breach exposure",
    description:
      "Establish what a breach source currently reports. A past breach is context, not a permanent score penalty.",
    verify:
      "Query an authorized breach source for this owned email, inspect the result and record its coverage. A completed lookup passes this review even when breaches are found; remediation is tracked separately.",
    steps: [
      "Verify ownership and consent before querying your email.",
      "Review the source's coverage limits and record affected services.",
      "Complete the exposed-credential response check for actionable findings.",
    ],
    kinds: ["email"],
    provider: true,
    days: 30,
  },
  {
    id: "exposure.credential-response",
    category: "exposure",
    title: "Respond to exposed credentials",
    description:
      "Protect affected accounts while retaining the history of their exposure.",
    verify:
      "For every known exposed credential, verify rotation at the affected service, removal of any reuse and review of active sessions. If no actionable credential exposure was found, record the reviewed source and that result.",
    steps: [
      "Open the affected service through its official address.",
      "Change exposed or reused passwords and revoke unfamiliar sessions.",
      "Verify the new sign-in and review other accounts using the old credential.",
    ],
    severity: "critical",
    kinds: ["email"],
    lockout: true,
    days: 30,
  },
  {
    id: "exposure.public-identifiers",
    category: "exposure",
    title: "Review public recovery identifiers",
    description:
      "Reduce unnecessary links between public profiles and private recovery channels.",
    verify:
      "Search for your own supplied public identifiers, accept only confirmed identity matches, and verify unnecessary recovery-email, phone or address disclosures were removed or protected by documented alternatives.",
    steps: [
      "Review your public profiles and confirmed search matches.",
      "Remove unnecessary recovery identifiers from profiles you control.",
      "For remaining disclosures, strengthen recovery controls and record why removal is unavailable.",
    ],
    partial:
      "Confirmed profiles are reviewed and removal requests submitted, but feasible removals remain unverified.",
    days: 90,
  },
  {
    id: "exposure.identity-incidents",
    category: "exposure",
    title: "Review identity-document incident relevance",
    description:
      "Separate a reported incident from evidence that your identity document was exposed.",
    verify:
      "Review current incident reports against services where you submitted ID. Record the source, whether the service relationship is confirmed, and appropriate official protective steps. Do not upload an ID or infer personal exposure from an article.",
    steps: [
      "Use official service notices and attributed incident reporting.",
      "Record potential relevance separately from confirmed personal exposure.",
      "Follow applicable identity-fraud guidance and record the response.",
    ],
    days: 30,
  },
  {
    id: "exposure.impersonation",
    category: "exposure",
    title: "Review impersonation and public profiles",
    description:
      "Find confirmed misuse of the public identity you choose to monitor.",
    verify:
      "Review official profiles and name or handle searches for confirmed impersonation. Record either no confirmed matches in the checked sources or completed protective responses for identified abuse.",
    steps: [
      "Compare suspected accounts against known authentic profiles.",
      "Report confirmed impersonation through the platform's official process.",
      "Preserve a redacted incident reference and verify the response.",
    ],
    days: 90,
  },

  {
    id: "accounts.phishing-resistant-mfa",
    category: "accounts",
    title: "Use phishing-resistant sign-in",
    description:
      "Protect critical accounts with passkeys or security keys and review permitted fallbacks.",
    verify:
      "Inspect the account's sign-in settings. Pass requires a working passkey or hardware security key and review of weaker permitted fallbacks. Record the authenticator type, never its secret.",
    steps: [
      "Add a supported passkey or hardware security key.",
      "Verify sign-in in a separate session before changing existing methods.",
      "Review weaker fallback methods alongside the recovery checklist.",
    ],
    partial:
      "Authenticator-app MFA is enabled and tested, but no phishing-resistant method is available or configured.",
    severity: "critical",
    kinds: ["email", "financial", "password_manager", "domain"],
    lockout: true,
  },
  {
    id: "accounts.unique-passwords",
    category: "accounts",
    title: "Use unique account passwords",
    description:
      "A breach at one service should not unlock another important account.",
    verify:
      "Use your password manager's local security report or guided inspection to confirm this account has a unique password and no known compromised password warning. Never submit the password or its hash.",
    steps: [
      "Review the password manager's security report locally.",
      "Replace reused or flagged passwords with unique generated ones.",
      "Confirm access before removing old recovery options.",
    ],
    severity: "critical",
    kinds: ["email", "financial", "password_manager", "domain"],
    lockout: true,
  },
  {
    id: "accounts.sessions",
    category: "accounts",
    title: "Review active sessions and trusted devices",
    description: "Revoke access that can survive a password change.",
    verify:
      "Inspect current sessions, trusted devices and recent login history. Pass requires all remaining entries recognized and unexplained logins investigated.",
    steps: [
      "Open the official session and device list.",
      "Revoke unrecognized or obsolete sessions.",
      "Investigate suspicious activity through the service's security process.",
    ],
    kinds: ["email", "financial", "password_manager", "domain"],
    severity: "high",
    days: 30,
  },
  {
    id: "accounts.connected-apps",
    category: "accounts",
    title: "Review connected apps and delegated access",
    description: "Remove unnecessary third-party access to critical accounts.",
    verify:
      "Inspect OAuth grants, delegated access and app passwords; confirm each remaining grant is needed and has the least supported permissions.",
    steps: [
      "List connected applications and delegates in account settings.",
      "Remove unused grants and app passwords.",
      "Review the purpose and permission scope of remaining access.",
    ],
    kinds: ["email", "financial", "password_manager", "domain"],
    days: 90,
  },
  {
    id: "accounts.email-forwarding",
    category: "accounts",
    title: "Inspect email forwarding and rules",
    description:
      "Hidden mail rules can redirect recovery messages or conceal account abuse.",
    verify:
      "Inspect forwarding destinations, inbox rules, filters and delegation in this email account. Confirm every enabled entry is recognized and necessary.",
    steps: [
      "Review forwarding and filtering settings in the official email interface.",
      "Remove unexplained rules after recording a redacted incident reference.",
      "Review sessions and password security if a rule suggests unauthorized access.",
    ],
    kinds: ["email"],
    severity: "high",
    days: 30,
  },

  {
    id: "recovery.channels",
    category: "recovery",
    title: "Verify account recovery channels",
    description: "A weaker reset route can bypass strong everyday sign-in.",
    verify:
      "Inspect every available recovery email, phone, trusted contact and support reset option for this account. Verify ownership and protection of each permitted route.",
    steps: [
      "Record recovery dependencies by selecting owned assets.",
      "Verify the recovery destination is accessible and secured.",
      "Remove obsolete routes only after testing an independent alternative.",
    ],
    kinds: ["email", "financial", "password_manager", "domain"],
    severity: "critical",
    lockout: true,
  },
  {
    id: "recovery.carrier-pin",
    category: "recovery",
    title: "Protect carrier support access",
    description:
      "A carrier account PIN helps restrict support-mediated changes.",
    verify:
      "Inspect carrier security settings or obtain official support confirmation that a non-default support PIN is active and authorized account managers are correct. Do not record the PIN.",
    steps: [
      "Set a unique carrier support PIN through the official channel.",
      "Review authorized account managers.",
      "Record confirmation of the protection without its value.",
    ],
    kinds: ["phone"],
    severity: "high",
    lockout: true,
  },
  {
    id: "recovery.number-lock",
    category: "recovery",
    title: "Enable number port-out protection",
    description:
      "Port-out controls restrict moving your phone number to another carrier.",
    verify:
      "Verify number lock or port-out protection is active for this exact line. If the carrier does not offer it, document that limitation and mark not applicable; SIM-change protection is a separate check.",
    steps: [
      "Find the carrier's number-lock or port-out protection feature.",
      "Enable it for each scoped line.",
      "Verify its status and document the official unlock process.",
    ],
    kinds: ["phone"],
    severity: "high",
  },
  {
    id: "recovery.sim-change",
    category: "recovery",
    title: "Enable SIM-change protection",
    description: "SIM-swap controls address changes within the same carrier.",
    verify:
      "Verify SIM-change or SIM-swap protection is enabled for this line, or document official confirmation that the carrier offers no such control.",
    steps: [
      "Review the carrier's available SIM-change security feature.",
      "Enable it and confirm it applies to your line.",
      "Record how to recover access through the official carrier process.",
    ],
    kinds: ["phone"],
    severity: "high",
  },
  {
    id: "recovery.backup-access",
    category: "recovery",
    title: "Verify independent backup access",
    description:
      "Recovery materials must remain usable when your main device is unavailable.",
    verify:
      "Confirm an independent backup authenticator or recovery resource exists and safely test an appropriate non-destructive recovery step. Record the result without codes, keys or secrets.",
    steps: [
      "Prepare an independent backup authenticator or recovery resource.",
      "Keep it accessible without depending on the account it recovers.",
      "Test a safe recovery step while preserving a working session.",
    ],
    kinds: ["email", "financial", "password_manager", "domain"],
    severity: "critical",
    lockout: true,
    days: 180,
  },

  {
    id: "devices.disk-encryption",
    category: "devices",
    title: "Enable full-disk encryption",
    description: "Protect data on a lost or stolen powered-off device.",
    verify:
      "Inspect the platform's full-disk encryption status and confirm encryption is enabled and complete. On macOS, read FileVault status. Do not collect the recovery key.",
    steps: [
      "Verify a current backup and recovery-key availability.",
      "Enable full-disk encryption in system settings.",
      "Wait for encryption to complete and recheck its status.",
    ],
    kinds: ["device"],
    local: true,
    severity: "high",
    lockout: true,
  },
  {
    id: "devices.screen-lock",
    category: "devices",
    title: "Require prompt screen locking",
    description: "Reduce access through an unattended unlocked device.",
    verify:
      "Verify the screen locks after no more than five idle minutes and requires authentication immediately after sleep or the screen saver starts. Confirm the behavior with a safe lock test.",
    steps: [
      "Set an idle lock timeout of five minutes or less.",
      "Require authentication immediately after sleep or screen saver.",
      "Lock the device and verify authentication is required.",
    ],
    kinds: ["device"],
    local: true,
    days: 90,
  },
  {
    id: "devices.os-updates",
    category: "devices",
    title: "Keep the operating system supported and current",
    description:
      "Install supported security updates; merely knowing a version does not prove it is current.",
    verify:
      "Check vendor support status and the system update interface. Pass requires a supported operating system with no outstanding security updates. Record update-check time and result.",
    steps: [
      "Check supported versions through the vendor's official guidance.",
      "Back up and install pending security updates.",
      "Restart if required and repeat the update check.",
    ],
    kinds: ["device"],
    local: true,
    severity: "high",
    days: 14,
    effort: "involved",
  },
  {
    id: "devices.firewall",
    category: "devices",
    title: "Review the host firewall",
    description: "Restrict unwanted inbound connections at the device.",
    verify:
      "Inspect host firewall status and permitted inbound applications. Confirm the firewall is active with only necessary exceptions; a firewall does not establish that the device is malware-free.",
    steps: [
      "Enable the operating system firewall.",
      "Review and remove unnecessary inbound exceptions.",
      "Verify required applications still work.",
    ],
    kinds: ["device"],
    local: true,
    days: 90,
  },
  {
    id: "devices.browser-extensions",
    category: "devices",
    title: "Review browser extension permissions",
    description:
      "Extensions can access account pages and sensitive browser activity.",
    verify:
      "Review installed extensions in every browser used for important accounts. Confirm each extension is necessary, supported and limited to required sites where supported.",
    steps: [
      "Open each browser's extension list.",
      "Remove unused or untrusted extensions.",
      "Restrict site access where available and recheck high-value account workflows.",
    ],
    kinds: ["device"],
    severity: "high",
    days: 30,
  },
  {
    id: "devices.remote-access",
    category: "devices",
    title: "Review remote access and privileged software",
    description:
      "Unnecessary remote services and privileged tools expand device access.",
    verify:
      "Inspect remote login, screen sharing, management profiles and privileged or remote-control apps. Pass requires every enabled path recognized, needed and appropriately restricted. A disabled SSH service alone does not verify the entire control.",
    steps: [
      "Review remote-access settings and privileged applications.",
      "Investigate unfamiliar entries before changing them.",
      "Disable unnecessary access through supported system settings and recheck.",
    ],
    kinds: ["device"],
    local: true,
    severity: "high",
    days: 30,
  },

  {
    id: "network.router-admin",
    category: "network",
    title: "Secure router administration",
    description: "Protect the control plane of the home network.",
    verify:
      "Verify the router administrator password is unique, remote administration is disabled unless explicitly required, and any vendor cloud account has its supported MFA enabled.",
    steps: [
      "Open the router's official administration interface.",
      "Replace default administrator credentials and review cloud-account access.",
      "Disable unnecessary remote administration and verify local access.",
    ],
    kinds: ["network"],
    lockout: true,
  },
  {
    id: "network.firmware",
    category: "network",
    title: "Keep router and connected devices supported",
    description: "Unsupported devices can retain known exploitable weaknesses.",
    verify:
      "Review router and connected-device inventory against vendor firmware support and available updates. Confirm all retained devices receive security updates or have a documented isolation plan.",
    steps: [
      "Inventory network devices without storing passwords.",
      "Install supported firmware updates.",
      "Replace or isolate devices that no longer receive security fixes.",
    ],
    kinds: ["network"],
    days: 30,
    effort: "involved",
  },
  {
    id: "network.external-access",
    category: "network",
    title: "Review network exposure",
    description:
      "Unneeded forwarding and automatic port mapping can expose internal services.",
    verify:
      "Inspect port forwards, UPnP/NAT-PMP, DNS configuration and remote administration. Confirm each allowed mapping is necessary. Local listening ports alone do not prove internet exposure.",
    steps: [
      "Review explicit port forwards and automatic port mapping settings.",
      "Remove unneeded mappings and disable automatic mapping when feasible.",
      "Verify needed services and record deliberate exceptions.",
    ],
    kinds: ["network"],
    severity: "high",
  },
  {
    id: "network.guest-isolation",
    category: "network",
    title: "Separate guest and less-trusted devices",
    description:
      "Limit access from visitors and connected devices to important computers.",
    verify:
      "Confirm guests and IoT devices use an isolated network where supported, and verify they cannot reach sensitive local services. Document unavailable router features when non-applicable.",
    steps: [
      "Create an isolated guest or IoT network where supported.",
      "Move less-trusted devices and verify required functionality.",
      "Test that sensitive local resources are not reachable from that network.",
    ],
    kinds: ["network"],
    effort: "involved",
  },

  {
    id: "finance.credit-freezes",
    category: "finance",
    title: "Verify credit freezes",
    description:
      "US credit freezes restrict many forms of new-account credit fraud.",
    verify:
      "For a US profile, confirm freeze status independently at Equifax, Experian and TransUnion through their official services. Record institutions and status without report numbers or identity documents.",
    steps: [
      "Visit each bureau through its official website.",
      "Place a free security freeze with each applicable bureau.",
      "Verify all three confirmations and retain recovery instructions privately.",
    ],
    partial:
      "Freeze status is verified at one or two of the three nationwide bureaus; remaining freezes are still open.",
    region: "US",
    severity: "high",
    days: 180,
  },
  {
    id: "finance.transaction-alerts",
    category: "finance",
    title: "Verify transaction and account-change alerts",
    description: "Prompt alerts help detect unauthorized financial activity.",
    verify:
      "Inspect available transaction, withdrawal, payee and account-detail change alerts for this financial account. Confirm alerts route to a monitored destination and complete an available safe notification test.",
    steps: [
      "Enable relevant transaction and profile-change alerts.",
      "Verify destination ownership and delivery.",
      "Record any unavailable alert types and compensating review procedure.",
    ],
    kinds: ["financial"],
    days: 90,
  },
  {
    id: "finance.transfer-controls",
    category: "finance",
    title: "Review transfer and withdrawal controls",
    description:
      "Limit loss after an attacker obtains information or account access.",
    verify:
      "Review supported transfer limits, trusted payees, recipient confirmation and withdrawal allowlists. Verify the applicable controls are configured for expected use; document unavailable features.",
    steps: [
      "Inspect supported transfer and withdrawal restrictions.",
      "Configure practical limits and supported recipient protections.",
      "Document official support routes for suspicious transfers.",
    ],
    kinds: ["financial"],
    severity: "high",
  },
  {
    id: "finance.identity-response",
    category: "finance",
    title: "Prepare identity-fraud protections",
    description:
      "Know the official procedures for tax and government identity misuse.",
    verify:
      "Review protections applicable to your jurisdiction, such as an IRS Identity Protection PIN in the US, and verify how to report suspected misuse. Record only availability and completion status, never the PIN or document number.",
    steps: [
      "Use official government guidance for your jurisdiction.",
      "Enable applicable identity protection features.",
      "Store official reporting and recovery routes in your incident plan.",
    ],
    days: 180,
  },

  {
    id: "data.sensitive-sharing",
    category: "data",
    title: "Review sensitive file sharing",
    description: "Remove unintended public links and unnecessary recipients.",
    verify:
      "Inspect sharing settings for sensitive documents and cloud folders. Confirm public links and external access are necessary, current and limited to intended recipients.",
    steps: [
      "Review sharing permissions in your storage provider.",
      "Revoke unnecessary public links and old collaborators.",
      "Delete unnecessary retained sensitive copies using the provider's supported process.",
    ],
    days: 90,
  },
  {
    id: "data.secret-storage",
    category: "data",
    title: "Remove plaintext credential copies",
    description: "Moving a secret into a vault does not remove earlier copies.",
    verify:
      "Review known credential storage locations without reading values into this audit. Confirm needed secrets use appropriate protected storage and identified plaintext copies have been removed from documents, repositories and shell configuration.",
    steps: [
      "Inventory locations and credential types without copying values.",
      "Move needed credentials to an appropriate vault or secret store.",
      "Remove old plaintext copies and review credential rotation separately.",
    ],
    severity: "high",
    days: 90,
  },
  {
    id: "data.secret-rotation",
    category: "data",
    title: "Rotate exposed or overprivileged credentials",
    description:
      "Revocation closes access that persists after a plaintext copy is removed.",
    verify:
      "Confirm identified exposed credentials were revoked or rotated at their issuer and remaining credentials have necessary scope and lifetime. Record a value-free issuer reference and verification result.",
    steps: [
      "Create a scoped replacement only where needed.",
      "Verify dependent applications work with the replacement.",
      "Revoke the old credential at its issuer and verify its inactive state.",
    ],
    severity: "critical",
    lockout: true,
    days: 90,
  },
  {
    id: "data.backup",
    category: "data",
    title: "Verify recent independent backups",
    description:
      "A usable backup needs a recent successful copy and an independent recovery path.",
    verify:
      "Inspect the most recent successful backup, confirm it is within your documented recovery objective, encrypted where supported and accessible if the primary device or account is lost.",
    steps: [
      "Configure a backup appropriate to your recovery needs.",
      "Keep an independent copy or protected version history.",
      "Verify successful completion and independent access without collecting encryption keys.",
    ],
    kinds: ["device"],
    severity: "high",
    days: 14,
  },
  {
    id: "data.restore-test",
    category: "data",
    title: "Test a safe file restore",
    description:
      "A completed backup job does not establish that restoration works.",
    verify:
      "Restore a small non-sensitive test file into a separate location and verify its contents. Record source backup date and test outcome without copying personal files into the audit.",
    steps: [
      "Choose a non-sensitive test file with known contents.",
      "Restore it to a separate location without overwriting existing files.",
      "Verify the result and record the test date.",
    ],
    kinds: ["device"],
    severity: "high",
    days: 180,
  },

  {
    id: "response.login-alerts",
    category: "response",
    title: "Verify important login alerts",
    description:
      "Security notifications must reach a channel you actively monitor.",
    verify:
      "Inspect security-login and recovery-change notifications for critical accounts and verify the destination is owned and monitored. Use an available safe notification test.",
    steps: [
      "Enable important login and recovery-change alerts.",
      "Review notification destinations and filters.",
      "Confirm delivery with a safe supported test.",
    ],
    kinds: ["email", "password_manager", "domain"],
    days: 90,
  },
  {
    id: "response.monitoring",
    category: "response",
    title: "Set an exposure review cadence",
    description: "Known identifiers and threat sources need periodic review.",
    verify:
      "Verify owned identifiers are covered by available monitoring or a scheduled manual review, and confirm the next review date and the channel used for actionable notifications.",
    steps: [
      "Choose provider monitoring or a repeatable manual review.",
      "Limit enrollment to identifiers you own or are authorized to monitor.",
      "Set a review cadence and verify how alerts will be received.",
    ],
    days: 30,
  },
  {
    id: "response.incident-plan",
    category: "response",
    title: "Keep a practical incident plan",
    description:
      "A short prepared plan reduces confusion during account loss or suspected compromise.",
    verify:
      "Confirm a privately accessible plan covers suspicious login, lost phone, exposed credentials, identity fraud and suspected device compromise, with official recovery and support routes.",
    steps: [
      "Write a concise plan with the first safe step for each incident.",
      "Include official support and recovery links.",
      "Keep a copy available independently of the primary account and phone.",
    ],
    days: 180,
  },
  {
    id: "response.rehearsal",
    category: "response",
    title: "Rehearse a safe response step",
    description: "Verify you can use the plan before an urgent event occurs.",
    verify:
      "Run a non-destructive tabletop exercise such as locating backup access when your phone is unavailable. Confirm needed official routes and resources are reachable; do not revoke working access as a drill.",
    steps: [
      "Choose a lost-phone or suspicious-login scenario.",
      "Walk through the first steps without destructive actions.",
      "Fix missing resources and record a successful repeat.",
    ],
    days: 180,
    effort: "quick",
  },
];

export const CHECKS: CheckDefinition[] = specs.map(check);
export const CHECK_BY_ID = new Map(CHECKS.map((item) => [item.id, item]));
